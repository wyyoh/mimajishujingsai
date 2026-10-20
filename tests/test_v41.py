"""V4.1 security semantics: real primitives, governed roles and bound evidence."""
import copy
import json
import subprocess
import time
import uuid
import threading

import pytest
from fastapi.testclient import TestClient

from services.agility import PROVIDERS, sm2_sign, sm2_verify, sm3, sm4_gcm
from services.encoding import Rejected, canonical, digest
from services.governance import decide, check_policy, classify
from services.initialization import RUNTIME
from services.orchestrator import execute, initialize, RUNS
from services.orchestrator import free_port
from services.storage import read
from services.signatures import sign_object, verify_object, check_authorization
from services.merkle import snapshot, verify_snapshot, verify_proof
from services.evidence import export_public, verify_export
from services.v41_attacks import attack, KINDS
from tests.provenance import record_run, observe


def request(suite="V41_HYBRID_SM", **updates):
    return {"asset_id": "household-load-demo", "region": "A", "resources": ["residential", "charging"],
            "function": "SUM", "algorithm_suite": suite, "request_nonce": uuid.uuid4().hex, **updates}


def test_real_sm_primitives_and_cli_interop(tmp_path):
    initialize()
    assert sm3(b"abc") == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    # RFC8998 Appendix A.1, original hex values; not a TLS conformity claim.
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    nonce = bytes.fromhex("00001234567800000000ABCD")
    message = bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
    aad = bytes.fromhex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
    expected = bytes.fromhex("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D")
    ciphertext, tag = sm4_gcm(key, nonce, message, aad)
    assert ciphertext == expected and tag.hex() == "83de3541e4c2b58177e065a9bf7b62ec"
    assert sm4_gcm(key, nonce, ciphertext, aad, tag) == message
    for candidate_key, candidate_nonce, candidate_data, candidate_aad, candidate_tag in (
        (b"0" * 16, nonce, ciphertext, aad, tag), (key, b"0" * 12, ciphertext, aad, tag),
        (key, nonce, b"0" + ciphertext[1:], aad, tag), (key, nonce, ciphertext, b"different", tag),
        (key, nonce, ciphertext, aad, b"0" * 16)):
        with pytest.raises(Rejected, match="SM4_AUTHENTICATION_FAILED"):
            sm4_gcm(candidate_key, candidate_nonce, candidate_data, candidate_aad, candidate_tag)
    payload, domain = b"real governed task", "GRID-TASK-AUTH-V2"
    signature = sm2_sign(RUNTIME / "utility/sm2.key", payload, domain)
    assert sm2_verify(RUNTIME / "public/utility-sm2-1.pem", payload, domain, signature)
    assert not sm2_verify(RUNTIME / "public/gateway-sm2-1.pem", payload, domain, signature)
    assert not sm2_verify(RUNTIME / "public/utility-sm2-1.pem", payload, "GRID-AGG-RECEIPT-V2", signature)
    data, signed = tmp_path / "message", tmp_path / "signature"
    data.write_bytes(payload)
    signed.write_bytes(signature)
    command = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(RUNTIME / "public/utility-sm2-1.pem"),
               "-rawin", "-digest", "sm3", "-pkeyopt", "distid:" + domain, "-in", str(data), "-sigfile", str(signed)]
    assert subprocess.run(command, capture_output=True).returncode == 0
    command = ["openssl", "pkeyutl", "-sign", "-inkey", str(RUNTIME / "utility/sm2.key"), "-rawin", "-digest", "sm3", "-pkeyopt", "distid:" + domain, "-in", str(data)]
    from services.custody import openssl_with_key
    assert sm2_verify(RUNTIME / "public/utility-sm2-1.pem", payload, domain, openssl_with_key(command[1:], RUNTIME / 'utility/sm2.key'))
    observe("sm_conformance", {"SM3_known_answer": True, "SM4_RFC8998_A1": True, "SM2_CLI_both_directions": True, "independent_crypto_implementation": False})


def test_governance_denies_untrusted_scope_level_function_and_downgrade():
    assert classify("critical-load-demo")["classification_scope"] == "SIMULATED_NOT_OFFICIAL"
    for data, subject, code in (
        (request(), "unknown", "POLICY_SUBJECT_UNKNOWN"),
        (request(region="B"), "grid_operator_A", "POLICY_REGION_DENIED"),
        (request(), "grid_analyst_A", "POLICY_DATA_LEVEL_DENIED"),
        (request(asset_id="public-load-demo", function="AVG"), "grid_analyst_A", "POLICY_FUNCTION_DENIED"),
        (request("V41_CLASSIC"), "grid_operator_A", "POLICY_CRYPTO_DOWNGRADE"),
        (request("V41_HYBRID", asset_id="critical-load-demo"), "grid_operator_A", "POLICY_CRYPTO_DOWNGRADE")):
        with pytest.raises(Rejected, match=code):
            decide(data, subject)
    policy = decide(request(asset_id="public-load-demo"), "grid_analyst_A")
    assert check_policy(policy, digest(policy), "SAB", business=True) == policy
    changed = copy.deepcopy(policy)
    changed["data_level"] = "important_simulated"
    with pytest.raises(Rejected, match="POLICY_DIGEST_MISMATCH"):
        check_policy(changed, digest(policy), "SAB")
    policy["expires_at"] = "2020-01-01T00:00:00Z"
    with pytest.raises(Rejected, match="POLICY_EXPIRED"):
        check_policy(policy, digest(policy), "SAB")


def test_merkle_odd_empty_proof_structure_and_tamper():
    records = [{"report_id": str(index), "ciphertext": str(index + 10)} for index in range(5)]
    value = snapshot(records, "fixture", "slot-0")
    assert verify_snapshot(value, value["merkle_root"], 5, "slot-0", "fixture")
    for proof in value["proofs"]:
        assert verify_proof(proof, value["merkle_root"], 5)
    changed = copy.deepcopy(value)
    changed["records"][0]["ciphertext"] = "changed"
    with pytest.raises(Rejected, match="SNAPSHOT_ROOT_MISMATCH"):
        verify_snapshot(changed, value["merkle_root"], 5, "slot-0", "fixture")
    proof = copy.deepcopy(value["proofs"][0])
    proof["index"] = True
    with pytest.raises(Rejected, match="MERKLE_PROOF_INDEX_INVALID"):
        verify_proof(proof, value["merkle_root"], 5)
    proof = copy.deepcopy(value["proofs"][0])
    proof["path"].pop()
    with pytest.raises(Rejected, match="MERKLE_PROOF_MISMATCH"):
        verify_proof(proof, value["merkle_root"], 5)
    empty = snapshot([], "fixture", "slot-0")
    assert verify_snapshot(empty, empty["merkle_root"], 0, "slot-0", "fixture")


@pytest.mark.parametrize("suite", list(PROVIDERS))
def test_real_provider_business_paths_and_signed_v2_evidence(suite):
    policy = decide(request(suite), "grid_operator_A", experimental=True, nodes=12, slots=1)
    selected = PROVIDERS[suite]
    result = execute(nodes=12, slots=1, profile=selected.profile, governance=policy)
    record_run(result["run_id"])
    assert result["status"] == "COMPLETED" and result["oracle_match"] is True
    receipts = read(RUNS / result["run_id"] / "receipts.json")
    assert {item["algorithm"] for item in receipts[0]["signatures"]} == set(selected.algorithms)
    verified = verify_export(export_public(result["run_id"]), expected_context={"run_id": result["run_id"], "algorithm_suite": suite})
    assert verified["v41_checks"][0]["snapshot_verified"] and verified["v41_checks"][0]["audit_checkpoint_verified"]
    connections = read(RUNS / result["run_id"] / "connection_evidence.json")
    assert {item["link_id"] for item in connections} == {"L1", "L2"}
    for item in connections:
        assert item["actual_group"] == selected.group and item["tls_record_bytes_sent"] > 0 and item["tls_record_bytes_received"] > 0
        if selected.sm4_channel:
            assert item["sm4_frames_sent"] > 0 and item["sm4_frames_received"] > 0
    if suite == "V41_HYBRID_SM":
        changed_type = copy.deepcopy(receipts[0])
        changed_type["payload"]["key_epoch"] = True
        with pytest.raises(Rejected, match="Protocol validation must preserve canonical input exactly"):
            verify_object(changed_type, "GRID_AGG_RECEIPT_V2", selected.profile, RUNTIME)
        for kind in KINDS:
            tested = attack(result["run_id"], kind)
            assert tested["attack_rejected"] and tested["restored_verified"] and tested["original_unchanged"]
        # ALL_REQUIRED applies to the added SM2 and retained ECDSA/ML-DSA.
        for index in range(3):
            modified = copy.deepcopy(receipts[0])
            modified["signatures"].pop(index)
            with pytest.raises(Rejected, match="REQUIRED_SIGNATURE_MISSING"):
                verify_object(modified, "GRID_AGG_RECEIPT_V2", selected.profile, RUNTIME)


@pytest.mark.parametrize("fault,code", [("snapshot_tamper", "SOURCE_SNAPSHOT_MISMATCH"), ("policy_tamper", "OBJECT_SIGNATURE_INVALID"), ("audit_tamper", "AUDIT_HASH_MISMATCH"), ("result_digest_tamper", "OBJECT_SIGNATURE_INVALID")])
def test_real_v41_role_flow_rejects_mutation(fault, code):
    policy = decide(request(), "grid_operator_A", nodes=12, slots=1)
    result = execute(nodes=12, slots=1, governance=policy, scenario=fault)
    record_run(result["run_id"])
    assert result["status"] == "REJECTED" and result["results"] == []
    assert code in {item["code"] for item in result["errors"]}


def test_authenticated_policy_api_and_legacy_entry_cannot_bypass(monkeypatch):
    from services import api
    from services.sessions import ACCESS_PATH
    monkeypatch.setattr(api, "LAB", False)
    with TestClient(api.app) as client:
        assert client.post("/api/collaborations", json=request(), headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 401
        credentials = read(ACCESS_PATH)["accounts"]
        assert client.post("/api/session", json={"subject": "grid_analyst_A", "password": credentials["grid_analyst_A"]}).status_code == 200
        assert client.post("/api/policies/preview", json=request()).status_code == 403
        assert client.post("/api/runs", json={"region": "A"}, headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 409
        permitted = request(asset_id="public-load-demo")
        preview = client.post("/api/policies/preview", json=permitted)
        assert preview.status_code == 200 and preview.json()["execution_mode"] == "PREVIEW" and preview.json()["authorization_signed"] is False
        assert client.post("/api/collaborations", json={**permitted, "requester_id": "grid_operator_A"}, headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 409
        assert client.post('/api/expansion/preview',json={'asset_id':'public-load-demo','request_nonce':uuid.uuid4().hex,'requester_id':'grid_operator_A'}).status_code==422
        assert client.post("/api/session/logout").status_code == 200
        assert client.post("/api/policies/preview", json=permitted).status_code == 401


@pytest.mark.parametrize("function", ["AVG", "COUNT"])
def test_real_additional_functions_are_authorized_and_bound(function):
    from services.dataset import generate
    policy = decide(request(function=function), "grid_operator_A", nodes=12, slots=1)
    result = execute(nodes=12, slots=1, governance=policy)
    record_run(result["run_id"])
    assert result["status"] == "COMPLETED" and result["oracle_match"] is True
    fixture = generate(12, 1)
    expected_nodes = [node for node in fixture["nodes"] if node["region"] == "A" and node["resource_class"] in ("residential", "charging")]
    total = sum(node["values_W"][0] for node in expected_nodes)
    actual = result["results"][0]["published_value"]
    assert actual["function"] == function
    if function == "COUNT":
        assert actual["value"] == str(len(expected_nodes)) and actual["unit"] == "reports"
    else:
        assert actual["numerator"] == total and actual["denominator"] == len(expected_nodes) and actual["value"] == f"{total}/{len(expected_nodes)}"
    assert verify_export(export_public(result["run_id"]), expected_context={"function": function})["v41_checks"]


def test_sm4_application_frame_replay_is_rejected_on_real_mtls(monkeypatch):
    from services import native
    initialize()
    port = free_port()
    listener = native.Listener(port, "gateway", "source", "X25519MLKEM768", RUNTIME, "L1", True)
    seen, errors, captured = [], [], []
    actual_send = native.LIB.grid_tls_send
    def capture(pointer, data, length):
        captured.append(bytes(data[:length]))
        return actual_send(pointer, data, length)
    monkeypatch.setattr(native.LIB, "grid_tls_send", capture)
    def receive():
        try:
            with listener.accept() as connection:
                seen.append(connection.receive())
                try:
                    connection.receive()
                    errors.append("REPLAY_ACCEPTED")
                except Rejected as exc:
                    errors.append(exc.code)
        except Exception as exc:
            errors.append(str(exc))
    receiver = threading.Thread(target=receive)
    receiver.start()
    try:
        with native.TLS.connect(port, "source", "gateway", "X25519MLKEM768", RUNTIME, "L1", True) as connection:
            message = {"request_id": uuid.uuid4().hex, "plaintext_sentinel": "application frame payload"}
            connection.send(message)
            assert captured and b"application frame payload" not in captured[0]
            assert actual_send(connection.pointer, captured[0], len(captured[0])) == 1
            receiver.join(10)
            assert not receiver.is_alive() and seen == [message] and errors == ["SM4_FRAME_CONTEXT_OR_REPLAY"]
        observe("sm4_frame_replay", {"actual_group": "X25519MLKEM768", "first_message_received": True, "replayed_frame_rejected": True, "private_keys_or_exporter_material_recorded": False})
    finally:
        listener.close()
        receiver.join(10)

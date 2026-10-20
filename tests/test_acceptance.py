import copy
import json
import os
import socket
import threading
import time
import uuid
import hashlib
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from services import pfdam, native
from services.encoding import Rejected, canonical, loads, b64, digest
from services.initialization import ROOT, RUNTIME
from services.orchestrator import initialize, execute, RUNS
from services.signatures import sign_object, verify_object, check_authorization
from services.storage import read
from services.evidence import export_public, verify_export
from services.dataset import generate, windows
from tests.provenance import record_run


@pytest.fixture(scope="session")
def material():
    return (
        initialize(),
        read(RUNTIME / "utility/pfdam.json"),
        read(RUNTIME / "gateway/pfdam.json"),
    )


@pytest.fixture(scope="session")
def run_case(material):
    cache = {}

    def get(
        scenario="normal", profile="SAB", nodes=12, slots=2, resources=None, region="A"
    ):
        key = (
            scenario,
            profile,
            nodes,
            slots,
            tuple(resources or ["residential", "charging"]),
            region,
        )
        if key not in cache:
            cache[key] = execute(
                nodes=nodes,
                slots=slots,
                scenario=scenario,
                profile=profile,
                resources=resources,
                region=region,
            )
        record_run(cache[key])
        return cache[key]

    return get


@pytest.fixture
def authorization(material):
    public, secret, _ = material
    now = datetime.now(timezone.utc)
    fmt = lambda x: x.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    context = {
        "object_type": "GRID_PUBLIC_TASK_V1",
        "schema_version": 1,
        "task_id": uuid.uuid4().hex,
        "run_id": uuid.uuid4().hex,
        "task_nonce": uuid.uuid4().hex,
        "metric_id": "average_active_power_W",
        "param_id": public["param_id"],
        "slots": windows(1),
    }
    token = pfdam.authorize(
        public, secret, [pfdam.tag(context, "slot-0", "A", "residential")]
    )
    payload = {
        "object_type": "GRID_TASK_AUTH_V1",
        "schema_version": 1,
        "task_id": context["task_id"],
        "run_id": context["run_id"],
        "issuer_role": "utility",
        "target_gw": "gateway",
        "slots": context["slots"],
        "issued_at": fmt(now),
        "not_before": fmt(now - timedelta(seconds=1)),
        "expires_at": fmt(now + timedelta(minutes=15)),
        "metric_id": context["metric_id"],
        "param_id": public["param_id"],
        "policy_ref": uuid.uuid4().hex,
        "token_bundle": {"slot-0": token},
        "security_profile": "SAB",
        "key_epoch": 1,
    }
    return context, payload


def assert_ok(run):
    assert run["status"] in ("COMPLETED", "PARTIAL") and run["oracle_match"] is True
    assert run["execution_mode"] == "REAL"
    checks = read(RUNS / run["run_id"] / "oracle_summary.json")
    assert all(c["set_match"] and c["value_match"] for c in checks)


@pytest.mark.acceptance("T01", "E01", "E02")
def test_normal_full_population(run_case):
    run = run_case(nodes=120, slots=4)
    assert_ok(run)
    assert len(run["results"]) == 4
    assert [
        (r["counts"]["received"], r["counts"]["accepted"], r["expected_target_count"])
        for r in run["results"]
    ] == [(120, 40, 40)] * 4


@pytest.mark.acceptance("T02", "T03")
def test_complete_labels_and_class_change(run_case):
    one = run_case(resources=["residential"])
    both = run_case()
    other = run_case(region="B")
    for run in (one, both, other):
        assert_ok(run)
    assert all(r["counts"]["accepted"] == 2 for r in one["results"])
    assert all(r["counts"]["accepted"] == 4 for r in both["results"])
    assert one["task_id"] != both["task_id"] != other["task_id"]


@pytest.mark.acceptance("T04", "T05")
def test_empty_and_legal_zero_distinct(run_case):
    empty = run_case("no_matching_reports")
    zero = run_case("zero")
    assert_ok(empty)
    assert_ok(zero)
    assert all(
        r["value_W"] is None and r["counts"]["accepted"] == 0 for r in empty["results"]
    )
    assert all(
        r["value_W"] == 0 and r["counts"]["accepted"] == 4 for r in zero["results"]
    )


@pytest.mark.acceptance("T06", "E16")
def test_actual_report_mutation(run_case):
    run = run_case("modified_report")
    assert_ok(run)
    assert run["results"][0]["counts"]["accepted"] == 3
    assert run["results"][0]["counts"]["joint_check_failed"] == 9
    assert run["results"][1]["counts"]["accepted"] == 4


@pytest.mark.acceptance("T07")
def test_target_missing_population(run_case):
    run = run_case("missing", nodes=120, slots=4)
    assert_ok(run)
    assert all(
        r["counts"]["received"] == 112
        and r["counts"]["accepted"] == 32
        and r["coverage_basis_points"] == 8000
        for r in run["results"]
    )


@pytest.mark.acceptance("T08")
def test_exact_report_retry_not_counted(run_case):
    run = run_case("duplicate_report")
    assert_ok(run)
    assert all(
        r["counts"]["accepted"] == 4
        and r["counts"]["received"] == 13
        and r["counts"]["duplicate"] == 1
        for r in run["results"]
    )


@pytest.mark.acceptance("T09", "E18")
def test_real_cryptographic_window_binding(material, authorization):
    public, uc, gw = material
    context, _ = authorization
    right = pfdam.tag(context, "slot-0", "A", "residential")
    wrong = pfdam.tag(context, "slot-1", "A", "residential")
    token = pfdam.authorize(public, uc, [right])
    envelope = {
        "task_id": context["task_id"],
        "run_id": context["run_id"],
        "slot_id": "slot-0",
        "param_id": public["param_id"],
        "report": pfdam.report(public, 100, wrong, native.utc()),
    }
    envelope["report_id"] = digest(envelope)
    _, accepted, rejected = pfdam.match_and_aggregate(public, gw, token, [envelope])
    assert not accepted and rejected[0]["code"] == "REPORT_JOINT_CHECK_FAILED"


@pytest.mark.acceptance("T10", "E17")
def test_invalid_element_and_cipher_domain(material):
    from services.pairing import Element, G1

    valid = G1.encode()
    with pytest.raises(Rejected):
        Element.decode("G1", valid[:-4])
    public, uc, gw = material
    token = pfdam.authorize(public, uc, [b"test"])
    envelope = {
        "report": {"CT": "0", "B": "0", "C": "a", "D": ["a"] * 16, "T": native.utc()}
    }
    envelope["report_id"] = digest(envelope)
    _, accepted, rejected = pfdam.match_and_aggregate(public, gw, token, [envelope])
    assert not accepted and rejected[0]["code"] == "CIPHERTEXT_DOMAIN_INVALID"


@pytest.mark.acceptance("T10", "E17")
def test_zero_ephemeral_cannot_turn_mac_key_into_public_identity(material):
    import hmac
    from services.pairing import G1, GT, ORDER
    from services.encoding import unb64

    public, uc, gw = material
    token = pfdam.authorize(public, uc, [b"authorized"])
    n = int(public["N"])
    stamp = native.utc()
    one = GT.scale(0)
    value = {
        "CT": str(1 + 42 * n),
        "B": "0",
        "C": GT.encode(),
        "D": [G1.scale(0).encode()] * 16,
        "T": stamp,
    }
    content = canonical({"Theta": value["C"], "CT": value["CT"], "T": stamp})
    value["B"] = str(
        int.from_bytes(hmac.digest(unb64(one.encode()), content, "sha256"), "big")
        % ORDER
    )
    forged = {"report": value}
    forged["report_id"] = digest(forged)
    _, accepted, rejected = pfdam.match_and_aggregate(public, gw, token, [forged])
    assert not accepted and rejected[0]["code"] == "REPORT_EPHEMERAL_ZERO"
    good = {"report": pfdam.report(public, 42, b"authorized", stamp)}
    good["report_id"] = digest(good)
    _, accepted, rejected = pfdam.match_and_aggregate(public, gw, token, [good])
    assert accepted and not rejected


@pytest.mark.acceptance("T11", "E19")
def test_policy_limitation_is_recorded():
    probe = read(ROOT / "artifacts/probes/primitives.json")
    check = next(
        x for x in probe["checks"] if x["name"] == "singleton_policy_candidate_relation"
    )
    assert (
        check["result"] == "DEMONSTRATED_LIMITATION" and check["real_pairing"] is True
    )
    assert (
        read(ROOT / "docs/claims_registry.json")["authorization_set_hiding"]["status"]
        == "DEMONSTRATED_LIMITATION"
    )


@pytest.mark.acceptance("T12", "E13")
def test_randomness_separate_from_data_seed(material):
    public, _, _ = material
    assert generate() == generate()
    a = pfdam.report(public, 100, b"same-tag", native.utc())
    b = pfdam.report(public, 100, b"same-tag", a["T"])
    assert a["CT"] != b["CT"] and a["C"] != b["C"] and a["D"] != b["D"]


@pytest.mark.acceptance("T13", "E03")
def test_actual_conjunctive_signatures(authorization):
    context, payload = authorization
    for profile in ("SA", "SAB"):
        payload["security_profile"] = profile
        obj, _ = sign_object(payload, RUNTIME)
        recovered, evidence = verify_object(obj, "GRID_TASK_AUTH_V1", profile, RUNTIME)
        check_authorization(recovered, context, profile)
        assert evidence["ecdsa_valid"] and evidence["mldsa_valid"]


@pytest.mark.acceptance("T14")
def test_signed_auth_fields_are_bound(authorization):
    _, payload = authorization
    obj, _ = sign_object(payload, RUNTIME)
    for field, value in (
        ("target_gw", "another-gateway"),
        ("param_id", "f" * 96),
        ("policy_ref", "changed"),
    ):
        bad = copy.deepcopy(obj)
        bad["payload"][field] = value
        with pytest.raises(Rejected, match="OBJECT_SIGNATURE_INVALID"):
            verify_object(bad, "GRID_TASK_AUTH_V1", "SAB", RUNTIME)


@pytest.mark.acceptance("T14", "T16")
def test_actual_gateway_rejects_invalid_and_expired_authorizations(run_case):
    for scenario, code, valid in (
        ("invalid_authorization", "OBJECT_SIGNATURE_INVALID", False),
        ("expired_authorization", "AUTH_EXPIRED", True),
    ):
        run = run_case(scenario)
        assert run["status"] == "REJECTED" and not run["results"]
        evidence = read(RUNS / run["run_id"] / "rejection_evidence.json")["gateway"]
        assert (
            evidence["code"] == code
            and evidence["signature_evidence"]["signature_valid"] is valid
        )


@pytest.mark.acceptance("T15", "E04")
def test_trusted_registry_and_profile_local_policy(authorization):
    _, payload = authorization
    obj, _ = sign_object(payload, RUNTIME)
    obj["signatures"][0]["key_id"] = "attacker-self-signed"
    with pytest.raises(Rejected, match="UNTRUSTED_SIGNATURE_KEY"):
        verify_object(obj, "GRID_TASK_AUTH_V1", "SAB", RUNTIME)
    payload["security_profile"] = "S0"
    obj, _ = sign_object(payload, RUNTIME)
    with pytest.raises(Rejected, match="LOCAL_SECURITY_PROFILE_MISMATCH"):
        verify_object(obj, "GRID_TASK_AUTH_V1", "SAB", RUNTIME)


@pytest.mark.acceptance("T16", "T17", "E15")
def test_valid_signature_wrong_business_context(authorization):
    context, payload = authorization
    for mutation, code in (
        ({"expires_at": "2020-01-01T00:00:00Z"}, "AUTH_EXPIRED"),
        ({"target_gw": "other-gateway"}, "AUTH_WRONG_AUDIENCE"),
    ):
        bad = {**payload, **mutation}
        obj, _ = sign_object(bad, RUNTIME)
        recovered, evidence = verify_object(obj, "GRID_TASK_AUTH_V1", "SAB", RUNTIME)
        assert evidence["signature_valid"]
        with pytest.raises(Rejected, match=code):
            check_authorization(recovered, context, "SAB")


@pytest.mark.acceptance("T18")
def test_signature_domains_are_real(authorization):
    _, payload = authorization
    message = canonical(payload)
    signature = native.sign(
        RUNTIME / "utility/mldsa.key", message, "GRID-TASK-AUTH-V1", True
    )
    assert not native.verify(
        RUNTIME / "public/utility-mldsa-1.pem",
        message,
        "GRID-AGG-RECEIPT-V1",
        signature,
        True,
    )
    obj, _ = sign_object(payload, RUNTIME)
    with pytest.raises(Rejected):
        verify_object(obj, "GRID_AGG_RECEIPT_V1", "SAB", RUNTIME)


@pytest.mark.acceptance("T19")
def test_each_required_signature_cannot_be_removed_or_corrupted(authorization):
    _, payload = authorization
    obj, _ = sign_object(payload, RUNTIME)
    for index in (0, 1):
        bad = copy.deepcopy(obj)
        bad["signatures"].pop(index)
        with pytest.raises(Rejected, match="REQUIRED_SIGNATURE_MISSING"):
            verify_object(bad, "GRID_TASK_AUTH_V1", "SAB", RUNTIME)
        bad = copy.deepcopy(obj)
        bad["signatures"][index]["value"] = b64(b"bad signature")
        with pytest.raises(Rejected, match="OBJECT_SIGNATURE_INVALID"):
            verify_object(bad, "GRID_TASK_AUTH_V1", "SAB", RUNTIME)


@pytest.mark.acceptance("T20", "E14")
def test_canonicalization_rejects_ambiguous_inputs():
    for value in [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":"\\ud800"}',
        b'{"a":9007199254740992}',
    ]:
        with pytest.raises(Rejected):
            loads(value)
    assert canonical({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert (
        canonical({"unicode": "中文", "big": "9007199254740992"})
        == b'{"big":"9007199254740992","unicode":"\xe4\xb8\xad\xe6\x96\x87"}'
    )


@pytest.mark.acceptance("T21", "T22")
def test_real_receipt_validation_and_mutation(run_case):
    run = run_case()
    receipts = read(RUNS / run["run_id"] / "receipts.json")
    payload, evidence = verify_object(
        receipts[0], "GRID_AGG_RECEIPT_V1", "SAB", RUNTIME
    )
    assert evidence["signature_valid"] and payload["run_id"] == run["run_id"]
    bad = copy.deepcopy(receipts[0])
    bad["payload"]["counts"]["received"] += 1
    with pytest.raises(Rejected, match="OBJECT_SIGNATURE_INVALID"):
        verify_object(bad, "GRID_AGG_RECEIPT_V1", "SAB", RUNTIME)
    bad_run = run_case("invalid_receipt")
    assert bad_run["status"] == "REJECTED" and not bad_run["results"]


@pytest.mark.acceptance("T26")
def test_receipt_both_signatures_required(run_case):
    run = run_case()
    obj = read(RUNS / run["run_id"] / "receipts.json")[0]
    for index in (0, 1):
        bad = copy.deepcopy(obj)
        bad["signatures"][index]["value"] = b64(b"bad signature")
        with pytest.raises(Rejected, match="OBJECT_SIGNATURE_INVALID"):
            verify_object(bad, "GRID_AGG_RECEIPT_V1", "SAB", RUNTIME)


@pytest.mark.acceptance("T25", "E10")
def test_archive_receipt_validity_and_public_export(run_case, tmp_path):
    run = run_case()
    archive = export_public(run["run_id"])
    result = verify_export(archive)
    assert result["file_hashes_valid"] and all(
        x["signature_valid"] for x in result["receipt_checks"]
    )
    assert (
        result["authorization_independent_verification"]
        == "NOT_INCLUDED_IN_PUBLIC_EXPORT"
    )
    assert result["plaintext_correspondence"] == "REQUIRES_TRUSTED_UC_OR_PRIVATE_ORACLE"
    assert result["receipt_authenticity_verified"] and result["signed_result_metadata_consistent"]
    pinned = {key: run[key] for key in ("run_id", "task_id", "param_id", "security_profile", "slot_count")}
    assert verify_export(archive, expected_context=pinned)["expected_context_checked"]
    for key, wrong in (("run_id", "0" * 32), ("task_id", "0" * 32),
                       ("param_id", "0" * 96), ("security_profile", "S0"), ("slot_count", 4)):
        with pytest.raises(Rejected, match="EXPORT_EXPECTED_CONTEXT_MISMATCH"):
            verify_export(archive, expected_context={**pinned, key: wrong})
    with zipfile.ZipFile(archive) as z:
        original = {name: z.read(name) for name in z.namelist()}

    def altered(name, mutate):
        entries = copy.deepcopy(original)
        mutate(entries)
        manifest = loads(entries["export_manifest.json"])
        manifest["files"] = {n: hashlib.sha256(data).hexdigest()
                             for n, data in entries.items() if n != "export_manifest.json"}
        entries["export_manifest.json"] = canonical(manifest)
        path = tmp_path / f"{name}.zip"
        with zipfile.ZipFile(path, "w") as z:
            for n, data in entries.items():
                z.writestr(n, data)
        return path

    def edit_json(entries, filename, change):
        obj = loads(entries[filename])
        change(obj)
        entries[filename] = canonical(obj)

    mutations = {
        "counts": ("EXPORT_RESULT_RECEIPT_MISMATCH", "run_manifest.json",
                   lambda m: m["results"][0]["counts"].update(accepted=999)),
        "count_type": ("EXPORT_RESULT_RECEIPT_MISMATCH", "run_manifest.json",
                       lambda m: m["results"][0]["counts"].update(invalid=False)),
        "receipt_reference": ("EXPORT_RESULT_RECEIPT_MISMATCH", "run_manifest.json",
                              lambda m: m["results"][0].update(receipt_digest="0" * 96)),
        "omitted_receipts": ("EXPORT_RESULT_RECEIPT_SET_MISMATCH", "receipts.json", lambda m: m.clear()),
        "duplicate_receipt": ("EXPORT_RECEIPT_SLOT_INVALID", "receipts.json", lambda m: m.__setitem__(1, m[0])),
        "duplicate_result": ("EXPORT_RESULT_SLOT_INVALID", "run_manifest.json",
                             lambda m: m["results"].__setitem__(1, m["results"][0])),
        "outer_run": ("EXPORT_RUN_CONTEXT_MISMATCH", "export_manifest.json", lambda m: m.update(run_id="0" * 32)),
        "parameter_substitution": ("EXPORT_PARAMETER_MISMATCH", "parameter_manifest.json", lambda m: m.update(h="1")),
        "result_status": ("EXPORT_RESULT_STATUS_MISMATCH", "run_manifest.json",
                          lambda m: m["results"][0].update(status="NO_VALID_DATA")),
        "signed_payload": ("OBJECT_SIGNATURE_INVALID", "receipts.json",
                           lambda m: m[0]["payload"]["counts"].update(accepted=999)),
    }
    for name, (code, filename, change) in mutations.items():
        path = altered(name, lambda entries: edit_json(entries, filename, change))
        with pytest.raises(Rejected, match=code):
            verify_export(path)
    missing = altered("missing_completed_slot", lambda e: (
        edit_json(e, "run_manifest.json", lambda m: m["results"].pop()),
        edit_json(e, "receipts.json", lambda m: m.pop())))
    with pytest.raises(Rejected, match="EXPORT_COMPLETED_SLOTS_MISSING"):
        verify_export(missing)
    extra = altered("unapproved_file", lambda e: e.update({"untrusted.json": b"{}"}))
    with pytest.raises(Rejected, match="EXPORT_FILE_SET_MISMATCH"):
        verify_export(extra)
    unlisted = altered("unlisted_file", lambda e: None)
    with zipfile.ZipFile(unlisted, "a") as z:
        z.writestr("untrusted.json", b"{}")
    with pytest.raises(Rejected, match="EXPORT_FILE_SET_MISMATCH"):
        verify_export(unlisted)
    # A signed GW ciphertext receipt does not authenticate the UC's plaintext.
    changed_value = altered("unsigned_value", lambda e: edit_json(e, "run_manifest.json",
        lambda m: m["results"][0].update(value_W=999999)))
    scoped = verify_export(changed_value)
    assert scoped["plaintext_correspondence"] == "REQUIRES_TRUSTED_UC_OR_PRIVATE_ORACLE"
    assert "value_W" in scoped["unsigned_metadata"]
    failed = run_case("invalid_authorization")
    no_receipts = verify_export(export_public(failed["run_id"]))
    assert not no_receipts["receipt_authenticity_verified"] and not no_receipts["receipt_checks"]


@pytest.mark.acceptance("T27", "T33", "E05", "E06")
def test_real_business_connection_provenance(run_case):
    run = run_case(nodes=120, slots=4)
    connections = read(RUNS / run["run_id"] / "connection_evidence.json")
    assert {c["link_id"] for c in connections} == {"L1", "L2"}
    assert len(connections) == 4
    assert all(
        c["actual_group"] == "X25519MLKEM768"
        and c["tls_version"] == "TLSv1.3"
        and c["peer_verified"]
        and c["business_request_refs"]
        and not c["session_reused"]
        and not c["early_data_accepted"]
        for c in connections
    )


@pytest.mark.acceptance("T28")
def test_strict_group_refusal_on_business(run_case):
    run = run_case("incompatible_tls")
    assert run["status"] == "REJECTED" and not run["results"]
    assert any("TLS_HANDSHAKE_FAILED" in e["message"] for e in run["errors"])


@pytest.mark.acceptance("T32", "T37", "E07")
def test_real_filesystem_isolation_and_export_fields(run_case):
    import zipfile

    run = run_case()
    records = read(RUNS / run["run_id"] / "role_isolation.json")
    assert run["role_file_isolation"] is True and set(records) == {
        "source",
        "gateway",
        "utility",
    }
    assert all(c["read_denied"] for r in records.values() for c in r["checks"])
    forbidden = {
        "private_key",
        "node_id",
        "values_W",
        "token_bundle",
        "alpha",
        "p_prime",
        "q_prime",
        "xag",
        "xgw",
    }

    def scan(obj):
        if isinstance(obj, dict):
            assert not (set(obj) & forbidden)
            for v in obj.values():
                scan(v)
        elif isinstance(obj, list):
            for v in obj:
                scan(v)

    with zipfile.ZipFile(export_public(run["run_id"])) as z:
        for n in z.namelist():
            data = z.read(n)
            assert b"PRIVATE KEY" not in data
            scan(loads(data))


@pytest.mark.acceptance("T35")
def test_four_profiles_same_semantics_and_parameters(run_case):
    runs = [run_case(profile=p) for p in ("S0", "SA", "SB", "SAB")]
    for r in runs:
        assert_ok(r)
    assert len({r["param_id"] for r in runs}) == 1
    assert len({r["dataset_digest"] for r in runs}) == 1
    assert len({tuple(x["value_W"] for x in r["results"]) for r in runs}) == 1


@pytest.mark.acceptance("T36", "T38", "E08", "E09")
def test_browser_state_and_failure_labels():
    path = ROOT / "artifacts/iterations/privacy/current/browser.json"
    if not path.exists():
        pytest.skip("actual browser checks pending")
    result = read(path)
    assert (
        result["real_failure_kept"]
        and result["condition_change_clears_metrics"]
        and result["no_horizontal_overflow"]
    )
    v41 = result
    assert v41["exit_code"] == 0 and v41["business_metrics_recomputed"] and v41["withheld_has_no_numeric_view"]
    assert v41["cross_subject_access_denied"] and v41["real_401_login_recovery"]
    assert v41["open_risks_not_greenwashed"] and v41["real_failure_kept"] and v41["condition_change_clears_metrics"] and v41["replay_preserves_source"]
    from services.versioning import source_version
    assert v41["core_source_digest"] == source_version()["core_source_digest"]
    for filename, expected_hash in v41["ui_fingerprint"]["files"].items():
        import hashlib
        assert filename.startswith("apps/web/")
        assert hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() == expected_hash
    from tests.provenance import record_run
    record_run(v41["run_id"])
    record_run(v41["failed_run_id"])


@pytest.mark.acceptance("T39")
def test_actual_timings_and_units(run_case):
    run = run_case()
    rows = read(RUNS / run["run_id"] / "performance_raw.json")
    assert run["elapsed_ns"] > 0 and run["benchmark_context"]["unit"] == "ns"
    assert {
        "generate_reports",
        "match_and_aggregate",
        "native_verify_recover",
        "sign",
        "verify",
    } <= {r["operation"] for r in rows}
    assert all(isinstance(r["elapsed_ns"], int) and r["elapsed_ns"] > 0 for r in rows)


@pytest.mark.acceptance("T40", "E11")
def test_independent_offline_reproduction_record():
    path = ROOT / "artifacts/iterations/privacy/current/legacy-offline.json"
    if not path.exists():
        pytest.skip("independent clean environment not yet exercised")
    result = read(path)
    assert (
        result["fresh_runtime"]
        and result["network_disabled"]
        and result["oracle_match"]
    )
    v41 = read(ROOT / "artifacts/iterations/privacy/current/v41-offline.json")
    assert v41["exit_code"] == 0 and v41["protocol_version"] == 2 and v41["public_receipt_links_verified"]
    assert v41["fresh_runtime"] and v41["fresh_virtual_environment"] and v41["network_disabled"] and v41["oracle_match"]
    from services.versioning import source_version
    assert v41["core_source_digest"] == source_version()["core_source_digest"]


@pytest.mark.acceptance("E12", "E20")
def test_current_parameter_bounds_are_explicit(material):
    public, secret, _ = material
    assert (
        public["modulus_bits"] == 3072
        and public["core_audit_status"] == "PENDING_REFERENCE_37_REVIEW"
    )
    audit = read(RUNTIME / "ta/parameter_audit.json")
    assert (
        audit["actual_order_divides_decryption_exponent"]
        and audit["actual_h_order"] != audit["paper_claimed_h_order"]
    )
    assert (2 * int(secret["alpha"])) * 900 * 10**9 < int(public["N"])

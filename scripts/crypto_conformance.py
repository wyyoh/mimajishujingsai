"""Public NIST sigVer vectors and CLI/adapter integration checks, not certification."""
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services import native
from services.encoding import canonical, digest, unb64
from services.initialization import ROOT, RUNTIME
from services.orchestrator import execute, RUNS
from services.signatures import CONTEXTS, trusted_registry
from services.storage import read, write
from services.versioning import source_version


def command(args):
    from services.custody import pem_password
    args = list(map(str, args))
    password = pem_password(args[args.index('-inkey')+1]) if '-inkey' in args else None
    return subprocess.run(["openssl", *args, *(['-passin', 'stdin'] if password else [])], input=password+b'\n' if password else None, capture_output=True, timeout=15)


def tlv(tag, content):
    n = len(content)
    length = bytes([n]) if n < 128 else (lambda b: bytes([128 + len(b)]) + b)(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + length + content


def public_key_pem(raw):
    # RFC 9881: id-ml-dsa-65 2.16.840.1.101.3.4.3.18, absent parameters.
    assert len(raw) == 1952
    oid = tlv(6, bytes.fromhex("608648016503040312"))
    der = tlv(48, tlv(48, oid) + tlv(3, b"\x00" + raw))
    text = base64.b64encode(der)
    return b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(text[i:i+64] for i in range(0, len(text), 64)) + b"\n-----END PUBLIC KEY-----\n"


def main():
    started = native.utc()
    frozen = source_version()
    vectors = ROOT / "references/crypto-vectors"
    source = read(vectors / "source_manifest.json")
    for entry in source["files"].values():
        assert hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    prompt = read(vectors / "mldsa65-prompt.json")
    expected = read(vectors / "mldsa65-expectedResults.json")
    selected = [g for g in prompt["testGroups"] if g["parameterSet"] == "ML-DSA-65"
                and g["signatureInterface"] == "external" and g["preHash"] == "pure"]
    assert len(selected) == 1
    group = selected[0]
    expected_by_id = {t["tcId"]: t["testPassed"] for g in expected["testGroups"]
                      if g["tgId"] == group["tgId"] for t in g["tests"]}
    version = subprocess.check_output(["openssl", "version"], text=True).strip()
    library = json.loads(native.LIB.grid_library_info())
    assert version.split()[1] == library["openssl"].split()[1]
    kat_rows, integration = [], []
    # Private canonical TaskAuth data must never enter the public evidence folder.
    (RUNTIME / "audit").mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="conformance-", dir=RUNTIME / "audit") as directory:
        temp = Path(directory)
        key, message, signature = (temp / n for n in ("public.pem", "message.bin", "signature.bin"))
        for test in group["tests"]:
            key.write_bytes(public_key_pem(bytes.fromhex(test["pk"])))
            message.write_bytes(bytes.fromhex(test["message"]))
            signature.write_bytes(bytes.fromhex(test["signature"]))
            result = command(["pkeyutl", "-verify", "-pubin", "-inkey", key,
                              "-in", message, "-sigfile", signature,
                              "-pkeyopt", "hexcontext-string:" + test["context"]])
            # Both actual positive successes and actual signature-failure results
            # are required; an unsupported CLI option must not count as rejection.
            assert result.returncode in (0, 1), result.stderr.decode(errors="replace")
            assert b"signature verif" in (result.stdout + result.stderr).lower(), repr((result.returncode, result.stdout, result.stderr))
            observed = result.returncode == 0
            assert observed is expected_by_id[test["tcId"]]
            kat_rows.append({"tgId": group["tgId"], "tcId": test["tcId"],
                             "expected_valid": expected_by_id[test["tcId"]],
                             "observed_valid": observed, "exit_code": result.returncode,
                             "context_bytes": len(test["context"]) // 2,
                             "message_bytes": len(test["message"]) // 2})
        run = execute(nodes=12, slots=2, profile="SAB")
        assert run["status"] == "COMPLETED" and run["oracle_match"]
        objects = [("utility", read(RUNTIME / "runs" / run["run_id"] / "utility/authorization.json")),
                   ("gateway", read(RUNS / run["run_id"] / "receipts.json")[0])]
        for role, envelope in objects:
            payload = envelope["payload"]
            data, ctx = canonical(payload), CONTEXTS[payload["object_type"]]
            message.write_bytes(data)
            for algorithm, alg, pq in (("ECDSA-P256-SHA256", "ecdsa", False), ("ML-DSA-65", "mldsa", True)):
                _, public = trusted_registry(RUNTIME, role, alg)
                private = RUNTIME / role / (alg + ".key")
                options = ["-pkeyopt", "context-string:" + ctx] if pq else ["-rawin", "-digest", "sha256"]
                native_sig = next(s for s in envelope["signatures"] if s["algorithm"] == algorithm)
                signature.write_bytes(unb64(native_sig["value"]))
                verified = command(["pkeyutl", "-verify", "-pubin", "-inkey", public,
                                    "-in", message, "-sigfile", signature, *options])
                assert verified.returncode == 0, verified.stderr.decode(errors="replace")
                message.write_bytes(data + b" ")
                modified = command(["pkeyutl", "-verify", "-pubin", "-inkey", public,
                                    "-in", message, "-sigfile", signature, *options])
                assert modified.returncode == 1
                message.write_bytes(data)
                if pq:
                    wrong = command(["pkeyutl", "-verify", "-pubin", "-inkey", public,
                                     "-in", message, "-sigfile", signature,
                                     "-pkeyopt", "context-string:GRID-WRONG-CONTEXT"])
                    assert wrong.returncode == 1
                signed = command(["pkeyutl", "-sign", "-inkey", private, "-in", message,
                                  "-out", signature, *options])
                assert signed.returncode == 0, signed.stderr.decode(errors="replace")
                cli_sig = signature.read_bytes()
                assert native.verify(public, data, ctx, cli_sig, pq)
                assert not native.verify(public, data + b" ", ctx, cli_sig, pq)
                if pq:
                    assert not native.verify(public, data, "GRID-WRONG-CONTEXT", cli_sig, pq)
                other = "gateway" if role == "utility" else "utility"
                _, wrong_key = trusted_registry(RUNTIME, other, alg)
                assert not native.verify(wrong_key, data, ctx, cli_sig, pq)
                integration.append({"object_type": payload["object_type"], "algorithm": algorithm,
                                    "payload_digest": digest(payload), "payload_bytes": len(data),
                                    "native_signature_cli_verified": True, "cli_signature_native_verified": True,
                                    "changed_message_rejected_both_directions": True,
                                    "wrong_role_key_rejected": True, "wrong_context_rejected_both_directions": True if pq else None,
                                    "signature_bytes": len(cli_sig)})
    assert source_version() == frozen
    result = {"schema": "GRID_CRYPTO_CONFORMANCE_V1", "started_at": started, "finished_at": native.utc(),
              "command": [".venv/bin/python", "scripts/crypto_conformance.py"], **frozen,
              "probe_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "openssl_cli": version, "openssl_native": library, "vector_source": source,
              "selected_interface": "ML-DSA-65 external pure sigVer, tgId=3; all 15 cases in this group",
              "official_vector_cases": kat_rows, "official_valid": sum(r["expected_valid"] for r in kat_rows),
              "official_invalid": sum(not r["expected_valid"] for r in kat_rows),
              "other_groups": "NOT_EXECUTED: ML-DSA-44/87, preHash, internal and external-mu are outside the application profile",
              "real_run_id": run["run_id"], "application_cross_checks": integration,
              "scope": "Public official-vector consistency and independent CLI/adapter API paths using the same OpenSSL implementation. Not CAVP/CMVP/FIPS certification, an independent implementation audit, or whole-protocol security proof.",
              "exit_code": 0}
    write(ROOT / 'artifacts/iterations/standards/current/crypto-conformance.json', result)
    write(ROOT / 'artifacts/iterations/standards/crypto-history' / (result['finished_at'].replace(':','-')+'-conformance.json'), result)
    print(json.dumps({"official_vectors": len(kat_rows), "positive": result["official_valid"],
                      "negative": result["official_invalid"], "object_algorithm_cross_checks": len(integration),
                      "run_id": run["run_id"], "exit_code": 0}))


if __name__ == "__main__":
    main()

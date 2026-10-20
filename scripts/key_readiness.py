"""Inspect local key/certificate readiness without exposing private material."""
import argparse
import hashlib
import json
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.initialization import ROOT, RUNTIME
from services.native import utc
from services.storage import read, write
from services.versioning import source_version


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--minimum-days", type=int, default=7)
    parser.add_argument("--planned-at", help="UTC ISO-8601 date of the intended demonstration")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/tests/key_readiness.json")
    args = parser.parse_args()
    assert 0 <= args.minimum_days <= 366
    now = datetime.now(timezone.utc)
    planned = datetime.fromisoformat(args.planned_at.replace("Z", "+00:00")) if args.planned_at else now
    assert planned.utcoffset() == timedelta(0)
    horizon = planned + timedelta(days=args.minimum_days)
    from services.custody import enabled, openssl_with_key
    managed = enabled(RUNTIME)
    from services.trust import registry as signed_registry, lookup
    if managed:
        registered = signed_registry(RUNTIME)
        registry = {role: {entry['algorithm']: entry for entry in registered['entries'] if entry['role'] == role and entry['algorithm'] in ('ecdsa', 'mldsa', 'sm2') and entry['status'] == 'ACTIVE'} for role in ('utility', 'gateway')}
    else:
        registry = read(RUNTIME / 'public/key_registry.json')
    rows, issues = [], []
    roles = ('ta', 'source', 'gateway', 'utility', *[f'source-{i}' for i in range(1,4) if (RUNTIME / f'source-{i}/tls.pem').exists()])
    for role in roles:
        directory = RUNTIME / role
        if stat.S_IMODE(directory.stat().st_mode) & 0o077:
            issues.append(role + ":PRIVATE_DIRECTORY_PERMISSIONS")
        for path in sorted(directory.glob("*.key")):
            if stat.S_IMODE(path.stat().st_mode) & 0o077:
                issues.append(role + ":PRIVATE_KEY_PERMISSIONS")
    for role in roles:
        cert = RUNTIME / "public/ca.pem" if role == "ta" else lookup(RUNTIME, role, 'tls')[1] if managed else RUNTIME / role / "tls.pem"
        output = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-noout", "-dates"], text=True)
        dates = dict(line.split("=", 1) for line in output.splitlines())
        parse = lambda text: datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before, not_after = parse(dates["notBefore"]), parse(dates["notAfter"])
        identity_options = [] if role == "ta" else ["-verify_hostname", role + ".grid"]
        verify = subprocess.run(["openssl", "verify", "-CAfile", str(RUNTIME / "public/ca.pem"),
                                 *identity_options, str(cert)], capture_output=True)
        valid = verify.returncode == 0 and not_before <= planned and not_after > horizon
        if not valid:
            issues.append(role + ":CERTIFICATE_NOT_READY_FOR_HORIZON")
        rows.append({"role": role, "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
                     "renew_before": (not_after - timedelta(days=args.minimum_days)).isoformat(),
                     "current_chain_and_identity_valid": verify.returncode == 0,
                     "ready_for_planned_horizon": valid})
    key_rows = []
    for role, algorithms in registry.items():
        assert role in ("utility", "gateway")
        for algorithm, entry in algorithms.items():
            assert algorithm in ("ecdsa", "mldsa", "sm2") and entry["epoch"] >= 1
            filename = entry["public_key"]
            assert Path(filename).name == filename and not filename.startswith(".")
            der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(RUNTIME / "public" / filename),
                                           "-outform", "DER"])
            private = RUNTIME / role / entry.get('private_key', algorithm+'.key')
            actual = openssl_with_key(['pkey', '-in', private, '-pubout', '-outform', 'DER'], private)
            if actual != der:
                issues.append(role + ":SIGNING_KEY_REGISTRY_MISMATCH")
            key_rows.append({"role": role, "algorithm": algorithm, "key_id": entry["key_id"],
                             "epoch": entry["epoch"], "public_spki_sha256": hashlib.sha256(der).hexdigest(),
                             "private_public_match": actual == der})
    result = {"schema": "GRID_KEY_READINESS_V1", "checked_at": utc(), **source_version(),
              "command": [".venv/bin/python", "scripts/key_readiness.py", *sys.argv[1:]],
              "probe_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "planned_at": planned.isoformat(), "minimum_days": args.minimum_days,
              "certificates": rows, "trusted_public_keys": key_rows,
              "private_permissions_checked": True, "issues": issues,
              "lifecycle_scope": "Signed pinned registry, software custody and task-boundary signing/TLS updates and revocation when managed; no HSM certification or host-administrator isolation.",
              "future_demonstration": "Recheck certificate horizon. Renew leaf identities under the active CA through approved management. CA root and PFDAM parameter migration remain separate procedures; new runtime initialization is not rotation.",
              "exit_code": 0 if not issues else 1}
    write(args.output, result)
    print(json.dumps(result, ensure_ascii=False))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())

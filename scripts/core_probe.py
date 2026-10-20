import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services import pfdam
from services.initialization import initialize_keys
from services.native import utc
from services.encoding import digest

runtime = initialize_keys()
path = runtime / "public/parameters.json"
if not path.exists():
    public, uc, gw, audit = pfdam.setup()
    for name, data in (
        ("public/parameters.json", public),
        ("utility/pfdam.json", uc),
        ("gateway/pfdam.json", gw),
        ("ta/parameter_audit.json", audit),
    ):
        out = runtime / name
        from services.storage import write
        write(out, data, private=not name.startswith('public/'))
        os.chmod(out, 0o600 if not name.startswith("public/") else 0o644)
else:
    public = json.loads(path.read_text())
    from services.storage import read
    uc = read(runtime / 'utility/pfdam.json')
    gw = read(runtime / 'gateway/pfdam.json')
ctx = {"task_nonce": "fresh-core-probe", "metric_id": "average_active_power_W"}
labels = [
    pfdam.tag(ctx, "slot-0", "A", resource)
    for resource in ["residential", "commercial", "charging"]
]
token = pfdam.authorize(public, uc, [labels[0], labels[2]])
reports = []
for label, value in zip(labels, [12, 99, 34], strict=True):
    envelope = {
        "task_id": "probe",
        "run_id": "probe",
        "slot_id": "slot-0",
        "param_id": public["param_id"],
        "report": pfdam.report(public, value, label, utc()),
    }
    envelope["report_id"] = digest(envelope)
    reports.append(envelope)
started = time.perf_counter_ns()
agg, accepted, rejected = pfdam.match_and_aggregate(public, gw, token, reports)
stamp = utc()
signature = pfdam.native_sign(gw, agg, stamp)
recovered = pfdam.verify_recover(public, uc, agg, stamp, signature, len(accepted))
assert len(accepted) == 2 and len(rejected) == 1 and recovered == 46
result = {
    "kind": "REAL_PFDAM_COMPONENT_NOT_VERTICAL_SAB",
    "command": ".venv/bin/python scripts/core_probe.py",
    "exit_code": 0,
    "param_id": public["param_id"],
    "modulus_bits": public["modulus_bits"],
    "pairing": public["pairing"],
    "accepted_count": len(accepted),
    "joint_check_failed_count": len(rejected),
    "recovered_W": recovered,
    "expected_W": 46,
    "aggregate_verify_recover_ns": time.perf_counter_ns() - started,
    "policy_hiding": "DEMONSTRATED_LIMITATION",
    "parameter_security_review": "PENDING_REFERENCE_37_REVIEW",
}
import uuid
out = Path(__file__).resolve().parents[1] / 'artifacts/iterations/standards/probes' / ('pfdam-component-'+uuid.uuid4().hex+'.json')
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps(result))

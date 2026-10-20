"""Exercise V2 governance, SM protection and public verification without routes."""
import json
import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.initialization import ROOT, RUNTIME
from services.orchestrator import initialize, execute, RUNS
from services.governance import decide
from services.evidence import export_public, verify_export
from services.storage import read, write
from services.versioning import source_version

initialize()
routes = subprocess.check_output(["ip", "route"], text=True)
assert not routes.strip()
policy = decide({"asset_id": "critical-load-demo", "region": "A", "resources": ["residential", "charging"],
                 "function": "AVG", "algorithm_suite": "V41_HYBRID_SM", "request_nonce": uuid.uuid4().hex}, "grid_operator_A")
run = execute(governance=policy)
assert run["status"] == "COMPLETED" and run["oracle_match"] is True
connections = read(RUNS / run["run_id"] / "connection_evidence.json")
assert {row["link_id"] for row in connections} == {"L1", "L2"}
assert all(row["actual_group"] == "X25519MLKEM768" and row.get("sm4_frames_sent", 0) and row.get("sm4_frames_received", 0) for row in connections)
verified = verify_export(export_public(run["run_id"]), expected_context={"run_id": run["run_id"], "algorithm_suite": "V41_HYBRID_SM", "function": "AVG"})
assert len(verified["v41_checks"]) == 4 and all(row["snapshot_verified"] and row["audit_checkpoint_verified"] for row in verified["v41_checks"])
result = {"schema": "GRID_V41_FRESH_OFFLINE_RESULT", "run_id": run["run_id"], "param_id": run["param_id"],
          "protocol_version": 2, "algorithm_suite": "V41_HYBRID_SM", "function": "AVG", "oracle_match": True,
          "public_receipt_links_verified": True, "role_file_isolation": run["role_file_isolation"], "routes": routes,
          "network_disabled": True, "fresh_runtime": True, "fresh_virtual_environment": True, **source_version(),
          "scope": "Fresh source directory, virtual environment, trust root, keys and PFDAM parameters in a network namespace on the same WSL host; not a second physical host"}
write(ROOT / "v41_offline_result.json", result)
print(json.dumps(result, ensure_ascii=False))

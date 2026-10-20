import json
import os
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.orchestrator import execute

routes = subprocess.run(
    ["ip", "route", "show"], check=True, capture_output=True, text=True
).stdout
assert not routes.strip(), "offline network namespace unexpectedly has external routes"
result = execute(nodes=12, slots=2, profile="SAB")
assert result["status"] == "COMPLETED" and result["oracle_match"]
record = {
    "fresh_runtime": True,
    "fresh_virtual_environment": True,
    "network_disabled": True,
    "network_namespace": os.readlink("/proc/self/ns/net"),
    "routes": routes,
    "run_id": result["run_id"],
    "param_id": result["param_id"],
    "oracle_match": result["oracle_match"],
    "role_file_isolation": result["role_file_isolation"],
    "core_source_digest": result["core_source_digest"],
    "native_library_sha256": result["native_library_sha256"],
    "scope": "fresh source directory, virtual environment and keys on the same WSL Ubuntu host; isolated network namespace",
}
Path("offline_result.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
print(json.dumps(record))

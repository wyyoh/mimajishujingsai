import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.initialization import ROOT
from services.storage import write
from services.versioning import source_version

lock = subprocess.run(
    [sys.executable, "-m", "pip", "freeze"], check=True, capture_output=True, text=True
).stdout
(ROOT / "requirements.lock.txt").write_text(lock, encoding="utf-8")
build = {
    **source_version(),
    "mcl_commit": "a8cad811f720264e6e140f54c66463be60189789",
    "platform": "WSL Ubuntu x86_64",
    "dependency_lock": "requirements.lock.txt",
}
write(ROOT / "artifacts/probes/build_manifest.json", build)
print(
    json.dumps(
        {
            "core_source_digest": build["core_source_digest"],
            "dependencies": len(lock.splitlines()),
        }
    )
)

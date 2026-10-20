"""Run regression in a private cloned runtime so the development API stays usable."""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.initialization import ROOT, RUNTIME
from services.orchestrator import initialize
from services.native import utc
from services.storage import write
from services.versioning import source_version


def main():
    initialize()
    target = Path(tempfile.mkdtemp(prefix="grid-v42-regression-"))
    for name in ("public", "ta", "source", "gateway", "utility"):
        shutil.copytree(RUNTIME / name, target / name)
    for name in ('source-1', 'source-2', 'source-3'):
        if (RUNTIME / name).exists():
            shutil.copytree(RUNTIME / name, target / name)
    if (RUNTIME / 'datasets').exists():
        shutil.copytree(RUNTIME / 'datasets', target / 'datasets', ignore=shutil.ignore_patterns('original.zip', '*.part'))
    shutil.copyfile(RUNTIME / "credentials.json", target / "credentials.json")
    arguments = sys.argv[1:] or ["tests", "-q"]
    command = [sys.executable, "-m", "pytest", *arguments]
    started = utc()
    before = source_version()
    process = subprocess.run(command, cwd=ROOT, env={**os.environ, "GRID_RUNTIME": str(target), "GRID_LAB": "0"})
    after = source_version()
    changed = before["core_source_digest"] != after["core_source_digest"] or before["native_library_sha256"] != after["native_library_sha256"]
    result = {"schema": "GRID_V42_ISOLATED_REGRESSION", "started_at": started, "finished_at": utc(), "command": command,
              "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "source_changed": changed,
              "private_runtime": str(target), "scope": "Cloned credentials/parameters, fresh run state and API database on same WSL host; not fresh key generation or a second physical host",
              **before, "exit_code": process.returncode if not changed else 2}
    destination = ROOT / "artifacts/iterations/v42/validations" / (started.replace(":", "-") + ".json")
    write(destination, result)
    print("Regression record: " + str(destination.relative_to(ROOT)), flush=True)
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())

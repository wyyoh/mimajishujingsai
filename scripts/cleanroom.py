"""Offline install and real run in a fresh directory, venv and network namespace."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.initialization import ROOT, RUNTIME
from services.storage import write
from services.native import utc
started = utc()
output = ROOT/'artifacts/iterations/standards/offline'/started.replace(':','-')
current = ROOT/'artifacts/iterations/standards/current'
output.mkdir(parents=True, exist_ok=True)
current.mkdir(parents=True, exist_ok=True)

container = Path(tempfile.mkdtemp(prefix="grid-offline-reproduction-", dir="/tmp"))
destination = container / "source"
destination.mkdir()
for directory in ("services", "native", "scripts", "shared", "tests"):
    shutil.copytree(
        ROOT / directory,
        destination / directory,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
for filename in ("requirements.txt", "requirements.lock.txt"):
    shutil.copyfile(ROOT / filename, destination / filename)
(destination / 'references/datasets/uci321').mkdir(parents=True)
shutil.copyfile(ROOT / 'references/datasets/uci321/import.json', destination / 'references/datasets/uci321/import.json')
public_seed = container / 'private-runtime/datasets/uci321'
public_seed.mkdir(parents=True, mode=0o700)
shutil.copyfile(RUNTIME / 'datasets/uci321/week.json', public_seed / 'week.json')
os.chmod(public_seed / 'week.json', 0o600)
(destination / ".build").mkdir()
shutil.copyfile(
    ROOT / ".build/libgridcrypto.so", destination / ".build/libgridcrypto.so"
)
(destination / "third_party/mcl/lib").mkdir(parents=True)
shutil.copyfile(
    ROOT / "third_party/mcl/lib/libmcl.so",
    destination / "third_party/mcl/lib/libmcl.so",
)
shutil.copytree(ROOT / ".build/wheelhouse", destination / ".build/wheelhouse")
subprocess.run(["python3", "-m", "venv", str(destination / ".venv")], check=True)
install = [
    str(destination / ".venv/bin/python"),
    "-m",
    "pip",
    "--isolated",
    "install",
    "--no-index",
    "--find-links",
    str(destination / ".build/wheelhouse"),
    "-r",
    str(destination / "requirements.lock.txt"),
]
out = subprocess.run(install, capture_output=True, text=True)
(container / "install.log").write_text(out.stdout + out.stderr, encoding="utf-8")
assert out.returncode == 0, out.stderr
command = [
    "unshare",
    "--user",
    "--map-root-user",
    "--net",
    "bash",
    str(destination / "scripts/offline_namespace.sh"),
    str(destination),
    str(container / "private-runtime"),
]
process = subprocess.run(command, capture_output=True, text=True, timeout=240, env={**os.environ, 'GRID_CUSTODY_PASSPHRASE':secrets.token_urlsafe(32)})
(container / "run.log").write_text(process.stdout + process.stderr, encoding="utf-8")
assert process.returncode == 0, process.stderr + process.stdout
record = json.loads((destination / "offline_result.json").read_text(encoding="utf-8"))
v41_record = json.loads((destination / "v41_offline_result.json").read_text(encoding="utf-8"))
v42_record = json.loads((destination / 'v42_offline_result.json').read_text(encoding='utf-8'))
v42_record.update(command=command, install_command=install, exit_code=process.returncode, reproduction_directory=str(container))
write(current / 'v4-offline.json', v42_record)
write(output / 'v4-offline.json', v42_record)
v41_record.update(command=command, install_command=install, exit_code=process.returncode, reproduction_directory=str(container))
write(current / 'v41-offline.json', v41_record)
write(output / 'v41-offline.json', v41_record)
for name, filename in [('install.log','offline-install.log'), ('run.log','offline-run.log')]:
    shutil.copyfile(container/name, current/filename)
    shutil.copyfile(container/name, output/filename)
record.update(
    command=command,
    install_command=install,
    exit_code=process.returncode,
    reproduction_directory=str(container),
)
write(current / 'legacy-offline.json', record)
write(output / 'legacy-offline.json', record)
write(
    output / 'wheel-manifest.json',
    {
        "wheels": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (ROOT / ".build/wheelhouse").glob("*.whl")
        },
        "platform": "CPython 3.14 Linux x86_64",
        "install_command": "pip --isolated install --no-index --find-links .build/wheelhouse -r requirements.lock.txt",
    },
)
print(json.dumps(record, ensure_ascii=False))

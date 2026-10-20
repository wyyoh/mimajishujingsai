"""Verify the complete software payload before offline loading. Hashes are not signatures."""
import hashlib
import json
from pathlib import Path, PurePosixPath

root = Path(__file__).resolve().parents[1]
manifest = root / "package_manifest.json"
if not manifest.exists():
    raise SystemExit("No package manifest; run this command from the generated software package")
files = json.loads(manifest.read_text(encoding="utf-8"))["files"]
for name, expected in files.items():
    key = PurePosixPath(name)
    if key.is_absolute() or ".." in key.parts:
        raise SystemExit("Invalid manifest path")
    target = root / key
    if not target.is_file() or target.is_symlink():
        raise SystemExit(f"Missing or unsafe package file: {name}")
    if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"Package hash mismatch: {name}")
print(f"Verified {len(files)} software files")

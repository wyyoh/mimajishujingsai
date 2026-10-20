import hashlib
import json

from .initialization import ROOT


def source_version():
    paths = sorted(
        [
            *ROOT.glob("services/*.py"),
            *ROOT.glob("native/*.cpp"),
            ROOT / "requirements.txt",
            ROOT / "requirements.lock.txt",
            ROOT / 'contracts/privacy_release.json',
        ]
    )
    files = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in paths
    }
    return {
        "core_source_digest": hashlib.sha256(
            json.dumps(files, sort_keys=True).encode()
        ).hexdigest(),
        "native_library_sha256": hashlib.sha256(
            (ROOT / ".build/libgridcrypto.so").read_bytes()
        ).hexdigest(),
        "core_source_files": files,
    }

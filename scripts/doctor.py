import argparse
import ctypes.util
import hashlib
import json
import os
import platform
import ssl
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def collect():
    def run(*args):
        p = subprocess.run(args, capture_output=True, text=True)
        return {
            "command": list(args),
            "exit_code": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
        }

    mcl = ROOT / "third_party/mcl/lib/libmcl.so"
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "openssl_python": ssl.OPENSSL_VERSION,
        "openssl": run("openssl", "version", "-a"),
        "ssl_library": ctypes.util.find_library("ssl"),
        "cpu_count": os.cpu_count(),
        "cpu": run("lscpu"),
        "memory": run("free", "-b"),
        "kernel": run("uname", "-a"),
        "compiler": run("g++", "--version"),
        "mcl_commit": run(
            "git", "-C", str(ROOT / "third_party/mcl"), "rev-parse", "HEAD"
        ),
        "mcl_sha256": hashlib.sha256(mcl.read_bytes()).hexdigest()
        if mcl.exists()
        else None,
        "kem_algorithms": run("openssl", "list", "-kem-algorithms"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = collect()
    text = json.dumps(data, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text)

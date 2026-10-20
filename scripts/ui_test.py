"""Launch the local lab if necessary and run the Windows browser checks from WSL."""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
server = None
try:
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:8580/api/config", timeout=2
        ) as res:
            config = json.load(res)
    except OSError:
        server = subprocess.Popen(
            [sys.executable, "-m", "services.cli", "serve", "--lab"],
            cwd=root,
            env={**os.environ, "PYTHONPATH": str(root)},
            stdout=subprocess.DEVNULL,
        )
        for attempt in range(60):
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:8580/api/config", timeout=2
                ) as res:
                    config = json.load(res)
                break
            except OSError:
                if server.poll() is not None:
                    raise RuntimeError("Local server failed to start")
                time.sleep(1)
        else:
            raise RuntimeError("Local server readiness timed out")
    if not config["lab_enabled"]:
        raise RuntimeError(
            "Browser checks require an explicitly started lab server; stop the business server first"
        )
    node = shutil.which("node.exe")
    if not node:
        raise RuntimeError("Install Node.js on Windows and expose node.exe to WSL")
    script = subprocess.check_output(
        ["wslpath", "-w", str(root / "apps/web/scripts/ui-check.mjs")], text=True
    ).strip()
    sys.exit(subprocess.call([node, script], cwd=root / "apps/web"))
finally:
    if server is not None:
        server.terminate()
        server.wait(timeout=10)

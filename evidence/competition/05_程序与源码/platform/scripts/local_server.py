"""Local lifecycle helper; Windows keeps the foreground WSL host alive."""

import argparse
import fcntl
import json
import os
import signal
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from services.initialization import ROOT, RUNTIME


URL = "http://127.0.0.1:8580"
STATE = RUNTIME / "local-server.json"
LOG = RUNTIME / "server.log"
PYTHON = str(ROOT / ".venv/bin/python")


def start_ticks(pid):
    # /proc/stat's command field may itself contain spaces or parentheses.
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def owned_process(record):
    try:
        pid = record["pid"]
        if type(pid) is not int or pid <= 1 or type(record["lab"]) is not bool:
            return False
        if record["root"] != str(ROOT) or record["runtime"] != str(RUNTIME.resolve()):
            return False
        if record["start_ticks"] != start_ticks(pid):
            return False
        proc = Path(f"/proc/{pid}")
        if (proc / "cwd").resolve() != ROOT:
            return False
        args = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        expected = [PYTHON, "-m", "services.cli", "serve"]
        if record["lab"]:
            expected.append("--lab")
        return args == [os.fsencode(arg) for arg in expected]
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return False


def owns_listener(pid):
    try:
        sockets = {
            fd.readlink().as_posix()
            for fd in Path(f"/proc/{pid}/fd").iterdir()
        }
        for row in Path(f"/proc/{pid}/net/tcp").read_text().splitlines()[1:]:
            fields = row.split()
            if fields[1] == "0100007F:2184" and fields[3] == "0A":
                return f"socket:[{fields[9]}]" in sockets
    except OSError:
        pass
    return False


def status():
    result = {"state": "STOPPED", "url": URL + "/?v42=1", "log": str(LOG)}
    try:
        record = json.loads(STATE.read_text())
    except (OSError, ValueError):
        record = {}
    if owned_process(record):
        result.update(state="STARTING", pid=record["pid"], lab=record["lab"])
        if owns_listener(record["pid"]):
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(URL + "/api/config", timeout=2) as response:
                    config = json.load(response)
                if config.get("lab_enabled") is record["lab"]:
                    result["state"] = "RUNNING"
            except (OSError, ValueError, urllib.error.URLError):
                pass
        return result
    try:
        with socket.create_connection(("127.0.0.1", 8580), timeout=0.5):
            result["state"] = "PORT_IN_USE"
    except OSError:
        pass
    return result


def host(lab):
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    lease_fd = os.open(RUNTIME / "local-server.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("LOCAL_SERVER_ALREADY_RUNNING")
    if status()["state"] == "PORT_IN_USE":
        raise RuntimeError("LOCAL_SERVER_PORT_IN_USE")
    os.set_inheritable(lease_fd, True)
    log_fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(log_fd, 0o600)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    if log_fd > 2:
        os.close(log_fd)
    with open(os.devnull, "rb") as null:
        os.dup2(null.fileno(), 0)
    record = {
        "pid": os.getpid(), "start_ticks": start_ticks(os.getpid()),
        "root": str(ROOT), "runtime": str(RUNTIME.resolve()), "lab": lab,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with tempfile.NamedTemporaryFile("w", dir=RUNTIME, delete=False) as temp:
        json.dump(record, temp)
        temp.write("\n")
    Path(temp.name).replace(STATE)
    os.chdir(ROOT)
    os.environ["GRID_RUNTIME"] = str(RUNTIME.resolve())
    os.environ["PYTHONPATH"] = str(ROOT)
    os.environ.pop("GRID_LAB", None)
    args = [PYTHON, "-m", "services.cli", "serve"]
    if lab:
        args.append("--lab")
    os.execv(PYTHON, args)


def stop():
    try:
        record = json.loads(STATE.read_text())
    except (OSError, ValueError):
        record = {}
    if not owned_process(record):
        result = status()
        if result["state"] == "PORT_IN_USE":
            raise RuntimeError("PORT_IN_USE_BY_UNMANAGED_PROCESS; no process was stopped")
        return result
    os.kill(record["pid"], signal.SIGTERM)
    deadline = time.monotonic() + 40
    while owned_process(record) and time.monotonic() < deadline:
        time.sleep(0.2)
    if owned_process(record):
        raise RuntimeError("LOCAL_SERVER_STOP_TIMEOUT; process was not force-killed")
    return status()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["server-host", "status", "stop"])
    parser.add_argument("--lab", action="store_true")
    args = parser.parse_args()
    if args.lab and args.command != "server-host":
        parser.error("--lab is only valid when starting the server")
    try:
        if args.command == "server-host":
            host(args.lab)
        print(json.dumps(stop() if args.command == "stop" else status()))
        return 0
    except (OSError, RuntimeError) as exc:
        print(json.dumps({"state": "ERROR", "error": str(exc), "log": str(LOG)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())

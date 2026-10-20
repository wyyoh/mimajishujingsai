import hashlib
import json
import os
import socket
import secrets
import subprocess
import sys
import time
import uuid
import fcntl
from pathlib import Path

from .dataset import generate, windows
from .encoding import digest, Rejected
from .initialization import ROOT, RUNTIME, initialize_keys
from .native import utc
from .schemas import ALL_MODELS
from .storage import read, write, event
from .versioning import source_version

RUNS = ROOT / "artifacts/runs"


def free_port(excluded=()):
    # A bind(0) probe uses the kernel's outbound ephemeral range. Releasing
    # that probe before the GW connects to UC can let its client socket take
    # the future L1 listener port. Choose outside that range and avoid peers.
    low, high = map(int, Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split())
    ranges = [(1024, low-1), (high+1, 65535)]
    candidates = [(start, end) for start, end in ranges if start <= end]
    if not candidates:
        raise Rejected('LISTENER_PORT_RANGE_UNAVAILABLE')
    for _ in range(256):
        start, end = secrets.choice(candidates)
        port = start + secrets.randbelow(end-start+1)
        if port in excluded:
            continue
        with socket.socket() as probe:
            try:
                probe.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise Rejected('LISTENER_PORT_ALLOCATION_FAILED')


def initialize():
    from .agility import preflight
    preflight()
    initialize_keys()
    from .agility import initialize_sm_keys
    initialize_sm_keys()
    if not (RUNTIME / "public/parameters.json").exists():
        p = subprocess.run(
            [sys.executable, str(ROOT / "scripts/core_probe.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if p.returncode:
            raise RuntimeError(p.stderr)
    from .custody import enable, enabled, protect_existing
    with (RUNTIME / 'security-init.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not enabled(RUNTIME):
            enable(RUNTIME)
        else:
            protect_existing(RUNTIME)
        from .trust import initialize as initialize_trust
        initialize_trust(RUNTIME)
        from .management import verify_program
        verify_program(bootstrap=True)
    from .expansion_schemas import MODELS as EXPANSION_MODELS
    from .security_schemas import MODELS as SECURITY_MODELS
    for model in (*ALL_MODELS, *EXPANSION_MODELS, *SECURITY_MODELS):
        write(
            ROOT / "shared/schemas" / f"{model.__name__}.json",
            model.model_json_schema(),
        )
    return read(RUNTIME / "public/parameters.json")


def _execute(
    nodes=120,
    slots=4,
    profile="SAB",
    region="A",
    resources=None,
    scenario="normal",
    run_id=None,
    lab=True,
    governance=None,
):
    if profile not in ("S0", "SA", "SB", "SAB"):
        raise Rejected("PROFILE_INVALID")
    if not lab and (profile != "SAB" or scenario != "normal"):
        raise Rejected("BUSINESS_POLICY_FORBIDS_LAB")
    resources = resources if resources is not None else ["residential", "charging"]
    if governance is not None:
        from .governance import check_policy
        governance = check_policy(governance, digest(governance), profile, business=not lab)
        if (governance["region"] != region or set(governance["resources"]) != set(resources)
                or governance["node_count"] != nodes or governance["slot_count"] != slots):
            raise Rejected("POLICY_EXECUTION_CONTEXT_MISMATCH")
    if (
        region not in ("A", "B")
        or len(resources) != len(set(resources))
        or any(r not in ("residential", "commercial", "charging") for r in resources)
    ):
        raise Rejected("POLICY_INVALID")
    public = initialize()
    run_id = run_id or uuid.uuid4().hex
    if len(run_id) != 32 or any(x not in "0123456789abcdef" for x in run_id):
        raise Rejected("RUN_ID_INVALID")
    job = RUNTIME / "runs" / run_id
    run = RUNS / run_id
    if job.exists():
        raise Rejected("RUN_ALREADY_EXISTS")
    for role in ("utility", "gateway", "source"):
        (job / role).mkdir(parents=True, mode=0o700)
    run.mkdir(parents=True, exist_ok=True)
    dataset = generate(nodes, slots)
    selected = [
        n["node_id"]
        for n in dataset["nodes"]
        if n["region"] == region and n["resource_class"] in resources
    ]
    injection = {"omitted": {}, "modified": {}}
    if scenario == "missing":
        for slot in windows(slots):
            injection["omitted"][slot["slot_id"]] = (
                selected[: max(1, len(selected) // 5)] if selected else []
            )
    if scenario == "modified_report" and selected:
        injection["modified"]["slot-0"] = [selected[0]]
    if scenario == "zero":
        for node in dataset["nodes"]:
            node["values_W"] = [0] * slots
        dataset["dataset_digest"] = digest(
            {k: v for k, v in dataset.items() if k != "dataset_digest"}
        )
    if scenario == "no_matching_reports":
        # Keep an independently specified task, suppress all target reports in this fixture.
        for slot in windows(slots):
            injection["omitted"][slot["slot_id"]] = selected
    context = {
        "object_type": "GRID_PUBLIC_TASK_V1",
        "schema_version": 1,
        "task_id": uuid.uuid4().hex,
        "run_id": run_id,
        "task_nonce": uuid.uuid4().hex,
        "metric_id": "average_active_power_W",
        "param_id": public["param_id"],
        "slots": windows(slots),
    }
    if governance is not None:
        context.update(object_type="GRID_PUBLIC_TASK_V2", schema_version=2, governance=governance,
                       policy_digest=digest(governance), task_nonce=governance["request_nonce"])
        write(run / "governance.json", governance)
    write(job / "utility/context.json", context, True)
    write(
        job / "utility/config.json",
        {
            "region": region,
            "resources": resources,
            "expected_target_count": len(selected),
            "node_count": nodes,
        },
        True,
    )
    write(job / "source/dataset.json", dataset, True)
    write(job / "source/injection.json", injection, True)
    start = time.perf_counter_ns()
    manifest = {
        "run_id": run_id,
        "task_id": context["task_id"],
        "execution_mode": "REAL",
        "data_source": "SYNTHETIC",
        "dataset_id": dataset["dataset_id"],
        "dataset_digest": dataset["dataset_digest"],
        "param_id": public["param_id"],
        "core_version": public["core_version"],
        "security_profile": profile,
        "scenario": scenario,
        "node_count": nodes,
        "slot_count": slots,
        "logical_source_process_count": 1,
        "started_at": utc(),
        "status": "RUNNING",
        "core_audit_status": public["core_audit_status"],
        "policy_hiding": "DEMONSTRATED_LIMITATION",
        "lab": lab,
        "results": [],
        "signature_evidence_refs": [],
        "connection_evidence_refs": [],
        "benchmark_context": {
            "platform": "WSL Ubuntu x86_64",
            "clock": "monotonic perf_counter_ns",
            "unit": "ns",
            "includes": "role startup, IPC, serialization, signatures, full handshakes, PFDAM and recovery",
            "sample_count": 1,
        },
    }
    manifest.update(source_version())
    if governance is not None:
        manifest.update(protocol_version=2, algorithm_suite=governance["algorithm_suite"], policy_digest=digest(governance),
                        asset_id=governance["asset_id"], data_level=governance["data_level"], function=governance["function"],
                        requester_id=governance["requester_id"], classification_scope="SIMULATED_NOT_OFFICIAL")
    write(run / "run_manifest.json", manifest)
    l1 = free_port()
    l2 = free_port({l1})
    processes = {}
    logs = {}
    env = {**os.environ, "PYTHONPATH": str(ROOT), "GRID_RUNTIME": str(RUNTIME)}

    def spawn(role):
        log = (job / role / "process.log").open("wb")
        logs[role] = log
        cmd = [
            sys.executable,
            "-m",
            "services.workers",
            "--role",
            role,
            "--runtime",
            str(RUNTIME),
            "--job",
            str(job),
            "--run-id",
            run_id,
            "--profile",
            profile,
            "--fault",
            scenario,
            "--l1",
            str(l1),
            "--l2",
            str(l2),
        ]
        if governance is not None:
            cmd.extend(["--suite", governance["algorithm_suite"]])
        from .custody import worker_environment
        with worker_environment(RUNTIME, role) as (role_env, inherited):
            processes[role] = subprocess.Popen(cmd, cwd=ROOT, env={**role_env, 'PYTHONPATH': str(ROOT), 'GRID_RUNTIME': str(RUNTIME)},
                pass_fds=inherited, stdout=log, stderr=subprocess.STDOUT)

    def ready(role):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if (job / "cancel.request").exists():
                raise InterruptedError("CANCELLED_BY_USER")
            if (job / role / "ready.json").exists():
                return
            if processes[role].poll() is not None:
                raise RuntimeError(f"{role} startup failed")
            time.sleep(0.05)
        raise TimeoutError(f"{role} startup timed out")

    failure = None
    peak_role_rss = 0
    try:
        spawn("utility")
        ready("utility")
        spawn("gateway")
        ready("gateway")
        spawn("source")
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            states = {r: p.poll() for r, p in processes.items()}
            sampled_rss = 0
            for process in processes.values():
                try:
                    status = Path(f"/proc/{process.pid}/status").read_text()
                    sampled_rss += next((int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:")), 0)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            peak_role_rss = max(peak_role_rss, sampled_rss)
            if (job / "cancel.request").exists():
                raise InterruptedError("CANCELLED_BY_USER")
            if any(code is not None and code != 0 for code in states.values()):
                raise RuntimeError("role process failed")
            if all(code == 0 for code in states.values()):
                break
            time.sleep(0.05)
        else:
            raise TimeoutError("run timed out")
    except Exception as exc:
        failure = str(exc)
    finally:
        for p in processes.values():
            if p.poll() is None:
                p.terminate()
        for p in processes.values():
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for log in logs.values():
            log.close()
    manifest["finished_at"] = utc()
    manifest["elapsed_ns"] = time.perf_counter_ns() - start
    all_events = []
    for path in (job / "events").glob("*.jsonl") if (job / "events").exists() else []:
        for line in path.read_text().splitlines():
            if line.strip():
                all_events.append(json.loads(line))
    all_events.sort(key=lambda x: x["at"])
    for i, x in enumerate(all_events):
        x["sequence"] = i + 1
    write(run / "events.json", all_events)
    connections = []
    timings = []
    for role in processes:
        for name, target in (
            ("connections.json", connections),
            ("timings.json", timings),
        ):
            if (job / role / name).exists():
                target.extend(read(job / role / name))
    write(run / "connection_evidence.json", connections)
    write(run / "performance_raw.json", timings)
    role_resources = [read(job / role / "resources.json") for role in processes if (job / role / "resources.json").exists()]
    write(run / "resource_evidence.json", {"roles": role_resources, "cpu_role_total_ns": sum(item["cpu_user_ns"] + item["cpu_system_ns"] for item in role_resources),
          "peak_sampled_role_rss_KiB": peak_role_rss, "sampling_interval_ms": 50,
          "scope": "Sum of live role RSS sampled by orchestrator; shared pages may be counted more than once. Excludes API/browser and is not PSS or whole-host peak."})
    isolation = {
        role: read(job / role / "isolation.json")
        for role in processes
        if (job / role / "isolation.json").exists()
    }
    write(run / "role_isolation.json", isolation)
    manifest["role_file_isolation"] = all(
        all(c["read_denied"] for c in record["checks"]) for record in isolation.values()
    ) and len(isolation) == len(processes)
    manifest["connection_evidence_refs"] = ["connection_evidence.json"]
    if (job / "gateway/authorization_evidence.json").exists():
        write(
            run / "authorization_evidence.json",
            read(job / "gateway/authorization_evidence.json"),
        )
        manifest["signature_evidence_refs"].append("authorization_evidence.json")
    if failure:
        published_path = job / "utility/published.json"
        if published_path.exists():
            published = read(published_path)
            manifest["results"] = published["results"]
            write(run / "receipts.json", published["receipts"])
            write(run / "signature_evidence.json", published["signature_evidence"])
            if "signature_evidence.json" not in manifest["signature_evidence_refs"]:
                manifest["signature_evidence_refs"].append("signature_evidence.json")
        manifest["status"] = (
            "CANCELLED" if failure == "CANCELLED_BY_USER" else "REJECTED"
        )
        errors = []
        for role in processes:
            if (job / role / "error.json").exists():
                errors.append(read(job / role / "error.json"))
        manifest["errors"] = errors or [
            {"code": "CANCELLED_BY_USER" if failure == "CANCELLED_BY_USER" else "ROLE_STARTUP_OR_TIMEOUT", "message": failure}
        ]
        rejections = {
            role: read(job / role / "rejection.json")
            for role in processes
            if (job / role / "rejection.json").exists()
        }
        write(run / "rejection_evidence.json", rejections)
    else:
        published = read(job / "utility/published.json")
        manifest["results"] = published["results"]
        manifest["status"] = (
            "PARTIAL"
            if any(
                x["counts"]["accepted"] < len(selected) for x in published["results"]
            )
            else "COMPLETED"
        )
        write(run / "receipts.json", published["receipts"])
        write(run / "signature_evidence.json", published["signature_evidence"])
        manifest["signature_evidence_refs"].append("signature_evidence.json")
        if lab:
            from tests.oracle.reference import expected, compare

            accepted = read(job / "gateway/accepted.json")
            mapping = read(job / "source/oracle_mapping.json")
            checks = []
            for i, result in enumerate(published["results"]):
                slot = result["slot_id"]
                ref = expected(
                    dataset,
                    region,
                    resources,
                    i,
                    injection["omitted"].get(slot, []),
                    injection["modified"].get(slot, []),
                )
                checks.append(
                    {
                        "slot_id": slot,
                        **compare(
                            ref, accepted[slot], mapping[slot], result["value_W"]
                        ),
                    }
                )
            write(run / "oracle_summary.json", checks)
            manifest["oracle_match"] = all(
                x["set_match"] and x["value_match"] for x in checks
            )
            if not manifest["oracle_match"]:
                manifest["status"] = "FAILED"
    if governance is not None:
        # Only expose checkpoints that are anchored by an actually published receipt.
        signed_slots = {result["slot_id"] for result in manifest["results"]}
        for name in ("snapshots.json", "audit_checkpoints.json", "accepted_manifests.json"):
            path = job / "gateway" / name
            durable = published.get(name.removesuffix(".json")) if (job / "utility/published.json").exists() else None
            if durable is not None or path.exists():
                value = durable if durable is not None else read(path)
                write(run / name, {key: item for key, item in value.items() if key in signed_slots})
    write(run / "run_manifest.json", manifest)
    write(ROOT / "artifacts/latest_run.json", {"run_id": run_id})
    return manifest


def execute(*args, **kwargs):
    # Serialize owned runs so a browser task cannot overlap a measured run.
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (RUNTIME / "execution.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        run_id = kwargs.get("run_id")
        if run_id and (RUNS / run_id / "cancel.request").exists():
            current = read(RUNS / run_id / "run_manifest.json")
            current["status"] = "CANCELLED"
            write(RUNS / run_id / "run_manifest.json", current)
            return current
        return _execute(*args, **kwargs)

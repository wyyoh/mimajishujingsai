import argparse
import random
import statistics
import time
from pathlib import Path

from .encoding import canonical
from .initialization import ROOT, RUNTIME
from .native import sign, verify, utc
from .orchestrator import execute, initialize
from .storage import write, read
from .versioning import source_version

DIRECTORY = ROOT / "artifacts/benchmarks"


def summarize(rows, profiles, repeats):
    summaries = []
    for profile in profiles:
        group = [r for r in rows if r["profile"] == profile]
        successful = sorted(r["elapsed_ns"] for r in group if r["success"])
        summaries.append(
            {
                "profile": profile,
                "sample_count": len(successful),
                "failure_count": sum(not r["success"] for r in group),
                "median_ns": int(statistics.median(successful)) if successful else 0,
                "p90_ns": successful[
                    min(len(successful) - 1, int(len(successful) * 0.9))
                ]
                if successful
                else 0,
            }
        )
    return {
        "status": "COMPLETED"
        if len(rows) == repeats * len(profiles)
        else "IN_PROGRESS",
        "profiles": summaries,
        "planned_repeats_per_profile": repeats,
        "nodes": 120,
        "slots": 4,
        "clock": "perf_counter_ns",
        "latency_interval": "after local fixture preparation and execution-lock acquisition, before role startup, through final role exit; includes serialization, IPC, native operations and both full TLS handshakes; excludes TA setup and queue wait",
        "unit": "ns",
        "raw_result_file": "raw.json",
        "updated_at": utc(),
        "security_scope": "functional migration costs; policy-hiding limitation and parameter review remain explicit",
    }


def run(profiles=("S0", "SA", "SB", "SAB"), repeats=30):
    if (
        len(profiles) != len(set(profiles))
        or any(p not in ("S0", "SA", "SB", "SAB") for p in profiles)
        or repeats < 1
    ):
        raise ValueError("Invalid benchmark plan")
    initialize()
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    if (DIRECTORY / "raw.json").exists():
        raise RuntimeError(
            "Existing raw benchmark records are preserved; use a separate checkout for another series"
        )
    frozen = source_version()
    rng = random.Random(20261015)
    rows = []
    write(
        DIRECTORY / "environment.json", read(ROOT / "artifacts/probes/environment.json")
    )
    write(
        DIRECTORY / "plan.json",
        {
            "profiles": list(profiles),
            "repeats": repeats,
            "order_seed": 20261015,
            "warmup": "preceding acceptance and browser runs; no discarded measured samples",
            "concurrency": "one owned role run at a time, one source process, loopback transport",
            "started_at": utc(),
            **frozen,
        },
    )
    for round_id in range(repeats):
        order = list(profiles)
        rng.shuffle(order)
        for profile in order:
            if source_version() != frozen:
                raise RuntimeError(
                    "Frozen source or native library changed during benchmark"
                )
            load = [round(x * 100) for x in __import__("os").getloadavg()]
            result = execute(profile=profile, nodes=120, slots=4)
            rows.append(
                {
                    "round": round_id + 1,
                    "profile": profile,
                    "run_id": result["run_id"],
                    "elapsed_ns": result["elapsed_ns"],
                    "success": result["status"] == "COMPLETED"
                    and result.get("oracle_match") is True,
                    "param_id": result["param_id"],
                    "dataset_digest": result["dataset_digest"],
                    "loadavg_times100": load,
                    "result_W": [r["value_W"] for r in result["results"]],
                    "core_source_digest": result["core_source_digest"],
                    "native_library_sha256": result["native_library_sha256"],
                }
            )
            write(DIRECTORY / "raw.json", rows)
            write(DIRECTORY / "summary.json", summarize(rows, profiles, repeats))
            print(
                f"round {round_id + 1}/{repeats} {profile} {result['status']} {result['elapsed_ns'] // 1000000}ms",
                flush=True,
            )
    # Native signatures include key loading, matching actual application behavior.
    micro = []
    objects = (
        (
            "authorization",
            "utility",
            "GRID-TASK-AUTH-V1",
            read(RUNTIME / "runs" / result["run_id"] / "utility/authorization.json")[
                "payload"
            ],
        ),
        (
            "receipt",
            "gateway",
            "GRID-AGG-RECEIPT-V1",
            read(ROOT / "artifacts/runs" / result["run_id"] / "receipts.json")[0][
                "payload"
            ],
        ),
    )
    for object_type, role, domain, payload in objects:
        message = canonical(payload)
        for algorithm, pq in (("ecdsa", False), ("mldsa", True)):
            for sample in range(100):
                t = time.perf_counter_ns()
                signature = sign(
                    RUNTIME / role / f"{algorithm}.key",
                    message,
                    domain,
                    pq,
                )
                sign_ns = time.perf_counter_ns() - t
                t = time.perf_counter_ns()
                valid = verify(
                    RUNTIME / "public" / f"{role}-{algorithm}-1.pem",
                    message,
                    domain,
                    signature,
                    pq,
                )
                verify_ns = time.perf_counter_ns() - t
                assert valid
                micro.append(
                    {
                        "algorithm": algorithm,
                        "object_type": object_type,
                        "source_run_id": result["run_id"],
                        "sample": sample,
                        "sign_ns": sign_ns,
                        "verify_ns": verify_ns,
                        "signature_bytes": len(signature),
                        "payload_bytes": len(message),
                    }
                )
    write(DIRECTORY / "signatures_raw.json", micro)
    return summarize(rows, profiles, repeats)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--profiles", default="S0,SA,SB,SAB")
    p.add_argument("--repeats", type=int, default=30)
    a = p.parse_args()
    run(a.profiles.split(","), a.repeats)

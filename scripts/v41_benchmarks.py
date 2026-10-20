"""Registered V4.1 descriptive experiments; raw failures and source drift remain visible."""
import argparse
import concurrent.futures
import ctypes as C
import hashlib
import json
import os
import random
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.agility import PROVIDERS, sm2_sign, sm2_verify
from services.encoding import canonical, Rejected
from services.governance import decide
from services.initialization import ROOT, RUNTIME
from services.native import sign, verify, utc, LIB
from services.orchestrator import execute, initialize, RUNS
from services.storage import read, write
from services.versioning import source_version


def percentile(values, fraction):
    values = sorted(values)
    return values[max(0, (len(values) * fraction + 99) // 100 - 1)]


def policy(suite, nodes, slots, function="SUM"):
    return decide({"asset_id": "household-load-demo", "region": "A", "resources": ["residential", "charging"],
                   "function": function, "algorithm_suite": suite, "request_nonce": uuid.uuid4().hex},
                  "grid_operator_A", experimental=True, nodes=nodes, slots=slots)


def row(run, submitted_ns):
    directory = RUNS / run["run_id"]
    connections = read(directory / "connection_evidence.json")
    clients = [item for item in connections if item["link_id"] == "L1" and item["peer_role"] == "gateway" or item["link_id"] == "L2" and item["peer_role"] == "utility"]
    resources = read(directory / "resource_evidence.json")
    return {"run_id": run["run_id"], "suite": run["algorithm_suite"], "security_profile": run["security_profile"],
            "param_id": run["param_id"], "dataset_digest": run["dataset_digest"], "core_source_digest": run["core_source_digest"],
            "native_library_sha256": run["native_library_sha256"], "status": run["status"], "oracle_match": run.get("oracle_match"),
            "elapsed_ns": run["elapsed_ns"], "caller_elapsed_including_queue_ns": time.perf_counter_ns() - submitted_ns,
            "started_at": run["started_at"], "finished_at": run["finished_at"],
            "cpu_role_total_ns": resources["cpu_role_total_ns"], "peak_sampled_role_rss_KiB": resources["peak_sampled_role_rss_KiB"],
            "tls_bytes_two_links": sum(item["tls_record_bytes_sent"] + item["tls_record_bytes_received"] for item in clients),
            "application_bytes_two_links": sum(item["application_bytes_sent"] + item["application_bytes_received"] for item in clients),
            "handshakes": [{key: item[key] for key in ("link_id", "actual_group", "handshake_ns", "handshake_bytes_sent", "handshake_bytes_received")} for item in clients],
            "totals_W": [value["value_W"] for value in run["results"]], "accepted_counts": [value["counts"]["accepted"] for value in run["results"]],
            "errors": run.get("errors", [])}


def signature_samples(data, repeats):
    rows = []
    for algorithm, name, pq in (("ECDSA-P256-SHA256", "ecdsa", False), ("ML-DSA-65", "mldsa", True), ("SM2-SM3", "sm2", False)):
        secret, public = RUNTIME / "gateway" / (name + ".key"), RUNTIME / "public" / f"gateway-{name}-1.pem"
        for sample in range(repeats):
            begin, cpu_begin = time.perf_counter_ns(), time.process_time_ns()
            signed = sm2_sign(secret, data, "GRID-V41-BENCHMARK") if name == "sm2" else sign(secret, data, "GRID-V41-BENCHMARK", pq)
            signed_ns, signed_cpu = time.perf_counter_ns() - begin, time.process_time_ns() - cpu_begin
            begin, cpu_begin = time.perf_counter_ns(), time.process_time_ns()
            valid = sm2_verify(public, data, "GRID-V41-BENCHMARK", signed) if name == "sm2" else verify(public, data, "GRID-V41-BENCHMARK", signed, pq)
            verify_ns, verify_cpu = time.perf_counter_ns() - begin, time.process_time_ns() - cpu_begin
            if not valid:
                raise Rejected("BENCHMARK_SIGNATURE_SELF_CHECK_FAILED")
            rows.append({"algorithm": algorithm, "sample": sample, "payload_bytes": len(data), "sign_ns": signed_ns, "verify_ns": verify_ns,
                         "sign_cpu_ns": signed_cpu, "verify_cpu_ns": verify_cpu, "signature_bytes": len(signed), "verified": valid})
    return rows


def kem_samples(repeats):
    # Direct EVP calls to the same local OpenSSL. No shared secrets are persisted.
    path = str(Path(json.loads(LIB.grid_library_info())["ssl_path"]).with_name("libcrypto.so.3"))
    lib = C.CDLL(path)
    pointer, size = C.c_void_p, C.POINTER(C.c_size_t)
    lib.EVP_PKEY_CTX_new_from_name.argtypes = [pointer, C.c_char_p, C.c_char_p]
    lib.EVP_PKEY_CTX_new_from_name.restype = pointer
    lib.EVP_PKEY_CTX_new_from_pkey.argtypes = [pointer, pointer, C.c_char_p]
    lib.EVP_PKEY_CTX_new_from_pkey.restype = pointer
    lib.EVP_PKEY_keygen_init.argtypes = [pointer]
    lib.EVP_PKEY_generate.argtypes = [pointer, C.POINTER(pointer)]
    for name in ("EVP_PKEY_encapsulate_init", "EVP_PKEY_decapsulate_init"):
        getattr(lib, name).argtypes = [pointer, pointer]
    lib.EVP_PKEY_encapsulate.argtypes = [pointer, pointer, size, pointer, size]
    lib.EVP_PKEY_decapsulate.argtypes = [pointer, pointer, size, pointer, C.c_size_t]
    lib.EVP_PKEY_CTX_free.argtypes = lib.EVP_PKEY_free.argtypes = [pointer]
    rows = []
    def success(result):
        if result != 1:
            raise Rejected("EVP_KEM_BENCHMARK_FAILED")
    for sample in range(repeats):
        context = lib.EVP_PKEY_CTX_new_from_name(None, b"ML-KEM-768", None)
        key = pointer()
        encoder = decoder = None
        try:
            success(lib.EVP_PKEY_keygen_init(context))
            begin = time.perf_counter_ns()
            success(lib.EVP_PKEY_generate(context, C.byref(key)))
            generation = time.perf_counter_ns() - begin
            encoder, decoder = lib.EVP_PKEY_CTX_new_from_pkey(None, key, None), lib.EVP_PKEY_CTX_new_from_pkey(None, key, None)
            success(lib.EVP_PKEY_encapsulate_init(encoder, None)); success(lib.EVP_PKEY_decapsulate_init(decoder, None))
            ciphertext_size, secret_size = C.c_size_t(), C.c_size_t()
            success(lib.EVP_PKEY_encapsulate(encoder, None, C.byref(ciphertext_size), None, C.byref(secret_size)))
            ciphertext, first, second = C.create_string_buffer(ciphertext_size.value), C.create_string_buffer(secret_size.value), C.create_string_buffer(secret_size.value)
            begin = time.perf_counter_ns()
            success(lib.EVP_PKEY_encapsulate(encoder, ciphertext, C.byref(ciphertext_size), first, C.byref(secret_size)))
            encapsulation = time.perf_counter_ns() - begin
            begin = time.perf_counter_ns()
            success(lib.EVP_PKEY_decapsulate(decoder, second, C.byref(secret_size), ciphertext, ciphertext_size.value))
            decapsulation = time.perf_counter_ns() - begin
            if first.raw != second.raw:
                raise Rejected("KEM_SHARED_SECRET_MISMATCH")
            changed = C.create_string_buffer(ciphertext.raw)
            changed[0] = bytes([ciphertext.raw[0] ^ 1])
            implicit = C.create_string_buffer(secret_size.value)
            status = lib.EVP_PKEY_decapsulate(decoder, implicit, C.byref(secret_size), changed, ciphertext_size.value)
            if status != 1 or implicit.raw == first.raw:
                raise Rejected("KEM_IMPLICIT_REJECTION_CHECK_FAILED")
            rows.append({"algorithm": "ML-KEM-768", "sample": sample, "keygen_ns": generation, "encapsulate_ns": encapsulation,
                         "decapsulate_ns": decapsulation, "ciphertext_bytes": ciphertext_size.value, "shared_secret_bytes": secret_size.value,
                         "secret_match": True, "modified_ciphertext_implicit_secret_differs": True})
        finally:
            lib.EVP_PKEY_CTX_free(encoder); lib.EVP_PKEY_CTX_free(decoder); lib.EVP_PKEY_free(key); lib.EVP_PKEY_CTX_free(context)
    return rows


def api_admission():
    """Four real HTTP callers, each asking for a distinct governed task."""
    import threading
    import urllib.error
    from tests.test_recovery import isolated_runtime, start_server, stop_group, wait_terminal
    runtime = isolated_runtime()
    process, log, request_api = start_server(runtime)
    barrier = threading.Barrier(4)
    def submit(index):
        request = {"asset_id": "household-load-demo", "region": "A", "resources": ["residential", "charging"],
                   "function": "SUM", "algorithm_suite": "V41_HYBRID_SM", "request_nonce": uuid.uuid4().hex}
        barrier.wait(timeout=10)
        begin = time.perf_counter_ns()
        try:
            response = request_api("/api/collaborations", request, uuid.uuid4().hex)
            return {"http_status": 202, "run_id": response["run_id"], "response_ns": time.perf_counter_ns() - begin}
        except urllib.error.HTTPError as exc:
            return {"http_status": exc.code, "detail": json.load(exc)["detail"], "response_ns": time.perf_counter_ns() - begin}
    try:
        begin = time.perf_counter_ns()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(submit, range(4)))
        admitted = [value for value in responses if value["http_status"] == 202]
        busy = [value for value in responses if value.get("detail") == "RUN_IN_PROGRESS"]
        if len(admitted) != 1 or len(busy) != 3:
            raise Rejected("API_ADMISSION_UNEXPECTED_RESULTS")
        task = wait_terminal(request_api, admitted[0]["run_id"])
        from services.dataset import generate
        fixture = generate()
        expected = [sum(node["values_W"][slot] for node in fixture["nodes"] if node["region"] == "A" and node["resource_class"] in ("residential", "charging")) for slot in range(4)]
        if task["status"] != "COMPLETED" or [value["value_W"] for value in task["results"]] != expected:
            raise Rejected("API_ADMISSION_TASK_VALUE_MISMATCH")
        return {"attempted_callers": 4, "admitted": 1, "busy_rejected": 3, "responses": responses,
                "completed_run_id": task["run_id"], "independent_value_match": True,
                "total_wall_ns": time.perf_counter_ns() - begin,
                "scope": "Distinct simultaneous HTTP tasks on an isolated cloned-credential API runtime. Current API admits one computation and rejects other new tasks; no parallel-compute claim."}
    finally:
        stop_group(process, log)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--nodes", type=int, default=120)
    parser.add_argument("--slots", type=int, default=4)
    parser.add_argument("--micro-repeats", type=int, default=100)
    parser.add_argument("--probe-only", action="store_true")
    args = parser.parse_args()
    initialize()
    if args.probe_only:
        result = kem_samples(3)
        print(json.dumps({"scope": "EVP primitive preflight; not formal measured series", "cases": result, **source_version()}))
        return 0
    assert 3 <= args.repeats <= 30 and 1 <= args.micro_repeats <= 1000
    directory = ROOT / "artifacts/iterations/v41/benchmarks" / utc().replace(":", "-")
    directory.mkdir(parents=True)
    frozen = source_version()
    plan = {"schema": "GRID_V41_EXPERIMENT_PLAN", "registered_at": utc(), **frozen,
            "command": [sys.executable, "scripts/v41_benchmarks.py", *sys.argv[1:]],
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "control_script_sha256": hashlib.sha256((ROOT / "scripts/v41_plaintext.py").read_bytes()).hexdigest(),
            "admission_helper_sha256": hashlib.sha256((ROOT / "tests/test_recovery.py").read_bytes()).hexdigest(),
            "nodes": args.nodes, "slots": args.slots, "repeats_per_suite": args.repeats, "warmups_per_suite": 1,
            "providers": [value.public() for value in PROVIDERS.values()], "micro_repeats": args.micro_repeats,
            "ordering": "One seeded shuffled provider order per repeat, seed=41016; cryptographic randomness is not seeded",
            "inference": "DESCRIPTIVE_ONLY_NO_SIGNIFICANCE_OR_EQUIVALENT_SECURITY_CLAIM",
            "latency_scope": "Run manifest measured interval: excludes fixture preparation/queue wait; includes role startup, actual two TLS handshakes, crypto, serialization, audit and recovery",
            "wire_scope": "Two client endpoints only, sent+received OpenSSL socket BIO TLS bytes including handshake, excludes TCP/IP headers",
            "memory_scope": "Peak sum of live role RSS sampled every 50ms; shared pages may be double counted; excludes API/browser",
            "concurrency": "4 caller threads; filesystem execution lock serializes computation. Measure queue-inclusive latency, no parallel-compute claim."}
    write(directory / "plan.json", plan)
    def guard():
        current = source_version()
        if current["core_source_digest"] != frozen["core_source_digest"] or current["native_library_sha256"] != frozen["native_library_sha256"]:
            raise Rejected("EXPERIMENT_SOURCE_CHANGED")
    warmups, rows, plain = [], [], []
    try:
        for suite, selected in PROVIDERS.items():
            guard(); begin = time.perf_counter_ns()
            warmups.append(row(execute(nodes=args.nodes, slots=args.slots, profile=selected.profile, governance=policy(suite, args.nodes, args.slots)), begin))
        write(directory / "warmups.json", warmups)
        if not all(item["status"] == "COMPLETED" and item["oracle_match"] for item in warmups):
            raise Rejected("V41_WARMUP_FAILED")
        rng = random.Random(41016)
        for repeat in range(args.repeats):
            suites = list(PROVIDERS); rng.shuffle(suites)
            control = json.loads(subprocess.check_output([sys.executable, str(ROOT / "scripts/v41_plaintext.py"), "--nodes", str(args.nodes), "--slots", str(args.slots)], text=True))
            plain.append({"repeat": repeat, **control})
            for suite in suites:
                guard(); selected = PROVIDERS[suite]; begin = time.perf_counter_ns()
                measured = row(execute(nodes=args.nodes, slots=args.slots, profile=selected.profile, governance=policy(suite, args.nodes, args.slots)), begin)
                measured["repeat"] = repeat
                measured["plaintext_control_matches"] = measured["totals_W"] == control["totals_W"] and measured["accepted_counts"] == control["counts"] and measured["dataset_digest"] == control["dataset_digest"]
                rows.append(measured)
                write(directory / "raw.json", rows); write(directory / "plaintext.json", plain)
                print(json.dumps({"repeat": repeat, "suite": suite, "status": measured["status"], "run_id": measured["run_id"]}), flush=True)
        guard()
        receipt = read(RUNS / rows[-1]["run_id"] / "receipts.json")[0]["payload"]
        signatures = signature_samples(canonical(receipt), args.micro_repeats)
        kem = kem_samples(args.micro_repeats)
        write(directory / "signatures.json", signatures); write(directory / "kem.json", kem)
        concurrent_begin = time.perf_counter_ns()
        def concurrent_task(index):
            begin = time.perf_counter_ns()
            return row(execute(nodes=12, slots=1, governance=policy("V41_HYBRID_SM", 12, 1)), begin)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            concurrency = list(pool.map(concurrent_task, range(4)))
        concurrent_elapsed = time.perf_counter_ns() - concurrent_begin
        write(directory / "concurrency.json", {"callers": 4, "compute_serialized": True, "total_wall_ns": concurrent_elapsed, "runs": concurrency})
        admission = api_admission()
        write(directory / "api_admission.json", admission)
        guard()
        profiles = []
        for suite in PROVIDERS:
            samples = [item for item in rows if item["suite"] == suite]
            good = [item for item in samples if item["status"] == "COMPLETED" and item["oracle_match"] and item["plaintext_control_matches"]]
            profile = {"suite": suite, "sample_count": len(samples), "success_count": len(good), "failure_count": len(samples)-len(good)}
            for metric in ("elapsed_ns", "cpu_role_total_ns", "peak_sampled_role_rss_KiB", "tls_bytes_two_links", "application_bytes_two_links"):
                values = [item[metric] for item in good]
                profile[metric] = {"median": int(statistics.median(values)), "p90": percentile(values, 90), "min": min(values), "max": max(values)} if values else None
            profiles.append(profile)
        result = {"schema": "GRID_V41_EXPERIMENT_SUMMARY", "status": "COMPLETED", "finished_at": utc(), **frozen,
                  "plan": str((directory / "plan.json").relative_to(ROOT)), "raw_directory": str(directory.relative_to(ROOT)), "profiles": profiles,
                  "signature_samples": len(signatures), "kem_samples": len(kem), "plaintext_samples": len(plain),
                  "concurrency": {"callers": 4, "completed": sum(item["status"] == "COMPLETED" for item in concurrency), "total_wall_ns": concurrent_elapsed, "compute_serialized": True},
                  "api_admission": {key: admission[key] for key in ("attempted_callers", "admitted", "busy_rejected", "completed_run_id", "independent_value_match")},
                  "inference": plan["inference"], "wire_scope": plan["wire_scope"], "memory_scope": plan["memory_scope"],
                  "cryptographic_scope": "SM means additional SM2/SM3/application SM4, not TLCP. PQ means ML-KEM768 key establishment with classical certificates; PFDAM remains classical.",
                  "signature_timing_scope": "Same public receipt payload for all algorithms; native call includes key loading/parsing and FFI; benchmark domain, not new business objects",
                  "kem_timing_scope": "Standalone same-OpenSSL EVP ML-KEM-768 keygen/encapsulation/decapsulation; excludes context setup; not TLS handshake cost"}
        write(directory / "summary.json", result)
        if all(item["failure_count"] == 0 for item in profiles) and all(item["oracle_match"] for item in concurrency):
            write(ROOT / "artifacts/iterations/v41/benchmarks/summary.json", result)
            print(json.dumps({"status": "COMPLETED", "summary": str((directory / "summary.json").relative_to(ROOT))}), flush=True)
            return 0
        raise Rejected("V41_EXPERIMENT_HAS_FAILURES")
    except Exception as exc:
        write(directory / "interrupted.json", {"status": "FAILED" if getattr(exc, "code", None) == "V41_EXPERIMENT_HAS_FAILURES" else "INCOMPLETE", "at": utc(), "error": str(exc), "code": getattr(exc, "code", type(exc).__name__), "completed_samples": len(rows), **frozen})
        raise


if __name__ == "__main__":
    raise SystemExit(main())

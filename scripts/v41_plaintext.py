"""Unprotected local control, independent arithmetic over the same synthetic input."""
import argparse
import json
import resource
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.dataset import generate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes", type=int, default=120)
    parser.add_argument("--slots", type=int, default=4)
    args = parser.parse_args()
    data = generate(args.nodes, args.slots)
    begin, cpu_begin = time.perf_counter_ns(), time.process_time_ns()
    totals, participants = [], []
    for slot in range(args.slots):
        total, count = 0, 0
        for node in data["nodes"]:
            if node["region"] == "A" and node["resource_class"] in ("residential", "charging"):
                total += node["values_W"][slot]
                count += 1
        totals.append(total if count else None)
        participants.append(count)
    elapsed, cpu = time.perf_counter_ns() - begin, time.process_time_ns() - cpu_begin
    print(json.dumps({"totals_W": totals, "counts": participants, "dataset_digest": data["dataset_digest"],
                      "elapsed_ns": elapsed, "cpu_ns": cpu, "process_peak_rss_KiB": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                      "security": "NONE", "scope": "Single-process local plaintext arithmetic; excludes fixture preparation/process startup, has no authorization, transport or signatures. Not an equivalent-security alternative."}))


if __name__ == "__main__":
    main()

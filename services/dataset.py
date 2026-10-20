"""Deterministic synthetic measurements; never used as crypto entropy."""

import random
from datetime import datetime, timedelta, timezone

from .encoding import digest

RESOURCES = ("residential", "commercial", "charging")


def generate(nodes=120, slots=4, seed=20261015):
    if nodes % 2 or not 2 <= nodes <= 900 or not 1 <= slots <= 4:
        raise ValueError("unsupported fixture size")
    rng = random.Random(seed)
    result = []
    half = nodes // 2
    for region in ("A", "B"):
        nres = int(half * 0.4)
        ncom = int(half / 3)
        classes = (
            ["residential"] * nres
            + ["commercial"] * ncom
            + ["charging"] * (half - nres - ncom)
        )
        for i, resource in enumerate(classes):
            base = {"residential": 1800, "commercial": 24000, "charging": 9000}[
                resource
            ]
            values = [
                max(0, base + (j * base // 12) + rng.randint(-base // 3, base // 3))
                for j in range(slots)
            ]
            result.append(
                {
                    "node_id": f"{region}-{i:04d}",
                    "region": region,
                    "resource_class": resource,
                    "values_W": values,
                }
            )
    data = {
        "dataset_id": "SYN-120-V3"
        if nodes == 120 and slots == 4
        else f"SYN-{nodes}-{slots}-PROBE",
        "seed": seed,
        "nodes": result,
        "node_count": nodes,
        "slot_count": slots,
        "unit": "W",
        "source": "SYNTHETIC",
    }
    data["dataset_digest"] = digest(data)
    return data


def windows(slots=4):
    start = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)

    def fmt(t):
        return t.isoformat(timespec="seconds").replace("+00:00", "Z")

    return [
        {
            "slot_id": f"slot-{i}",
            "slot_start": fmt(start + timedelta(minutes=15 * i)),
            "slot_end": fmt(start + timedelta(minutes=15 * (i + 1))),
        }
        for i in range(slots)
    ]

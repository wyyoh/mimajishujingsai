"""Reproduce candidate policy membership testing directly from V-B/V-D."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services import pfdam
from services.pairing import Element, ORDER
from services.initialization import RUNTIME, ROOT
from services.orchestrator import initialize
from services.storage import read, write
from services.native import utc

public = initialize()
uc = read(RUNTIME / "utility/pfdam.json")
context = {
    "task_nonce": "public-audit-namespace",
    "metric_id": "average_active_power_W",
}
candidates = [
    pfdam.tag(context, "slot-0", region, resource)
    for region in ("A", "B")
    for resource in ("residential", "commercial", "charging")
]
rows = []
for chosen in ([0], [0, 2], [0, 2, 4], [0, 1, 2, 3, 4]):
    token = pfdam.authorize(public, uc, [candidates[i] for i in chosen])
    # The actual test below uses only public S,V, the issued token and candidate tags.
    powers = [
        pfdam.pairing(Element.decode("G1", s), Element.decode("G2", w))
        for s, w in zip(public["S"], token, strict=True)
    ]
    matches = []
    for index, label in enumerate(candidates):
        h = pfdam.scalar_hash(label)
        value = powers[0]
        for j in range(1, len(powers)):
            value = value.multiply(powers[j].scale(pow(h, j, ORDER)))
        if value == Element.decode("GT", public["V"]):
            matches.append(index)
    assert matches == chosen
    rows.append(
        {
            "authorized_candidate_indices": chosen,
            "recovered_candidate_indices": matches,
            "real_pairing": True,
        }
    )
record = {
    "status": "DEMONSTRATED_LIMITATION",
    "scope": "authorization-set hiding for singleton and multi-tag policies in this reproduction",
    "formula": "product_j e(S_j,omega_j)^(H(candidate)^j) == V iff candidate is a polynomial root",
    "source": "PFDAM V-B/V-D public parameters and token formulas",
    "param_id": public["param_id"],
    "cases": rows,
    "command": ".venv/bin/python scripts/policy_audit.py",
    "exit_code": 0,
    "finished_at": utc(),
    "warning": "does not break ML-DSA or hybrid TLS; does not by itself recover household readings",
}
write(ROOT / "artifacts/probes/policy_audit.json", record)
print(json.dumps(record, ensure_ascii=False))

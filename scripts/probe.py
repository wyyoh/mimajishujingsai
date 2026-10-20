"""Reproducible real primitive probes; not a complete PFDAM run."""

import hashlib
import json
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.initialization import initialize_keys
from services import native
from services.pairing import Element, G1, G2, GT, ORDER, pairing


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    runtime = initialize_keys()
    checks = []
    started = native.utc()
    message = b'{"object_type":"GRID_TASK_AUTH_V1","task_id":"real-probe"}'
    for pq, alg in ((False, "ecdsa"), (True, "mldsa")):
        path = runtime / "utility" / f"{alg}.key"
        pub = runtime / "public" / f"utility-{alg}-1.pem"
        t = time.perf_counter_ns()
        sig = native.sign(path, message, "GRID-TASK-AUTH-V1", pq)
        ns = time.perf_counter_ns() - t
        valid = native.verify(pub, message, "GRID-TASK-AUTH-V1", sig, pq)
        modified = native.verify(pub, message + b" ", "GRID-TASK-AUTH-V1", sig, pq)
        context_rejected = (
            not native.verify(pub, message, "GRID-AGG-RECEIPT-V1", sig, pq)
            if pq
            else None
        )
        checks.append(
            {
                "name": alg,
                "valid": valid,
                "modified_rejected": not modified,
                "wrong_context_rejected": context_rejected,
                "signature_bytes": len(sig),
                "sign_ns": ns,
            }
        )
        assert valid and not modified and (context_rejected if pq else True)
    links = []
    for link, client, server in (
        ("L1", "source", "gateway"),
        ("L2", "gateway", "utility"),
    ):
        port = free_port()
        listener = native.Listener(
            port, server, client, "X25519MLKEM768", runtime, link
        )
        result = {}

        def serve():
            try:
                with listener.accept() as connection:
                    received = connection.receive()
                    assert received["payload"] == "actual application frame"
                    connection.send(
                        {"request_id": received["request_id"], "received": True}
                    )
                    result["evidence"] = connection.evidence
            except BaseException as exc:
                result["error"] = str(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        with native.TLS.connect(
            port, client, server, "X25519MLKEM768", runtime, link
        ) as connection:
            connection.send(
                {"request_id": f"probe-{link}", "payload": "actual application frame"}
            )
            assert connection.receive()["received"]
            client_ev = connection.evidence
        thread.join(5)
        listener.close()
        assert "error" not in result and "evidence" in result
        links.append({"client": client_ev, "server": result["evidence"]})
    # Strict group refusal: a SAB listener is never allowed to fall back to X25519.
    port = free_port()
    listener = native.Listener(
        port, "gateway", "source", "X25519MLKEM768", runtime, "L1"
    )
    refusal = {}

    def incompatible_server():
        try:
            c = listener.accept()
            c.close()
            refusal["accepted"] = True
        except Exception as exc:
            refusal["server_error"] = str(exc)

    thread = threading.Thread(target=incompatible_server, daemon=True)
    thread.start()
    try:
        c = native.TLS.connect(port, "source", "gateway", "X25519", runtime, "L1")
        c.close()
        refusal["client_accepted"] = True
    except Exception as exc:
        refusal["client_error"] = str(exc)
    thread.join(5)
    listener.close()
    assert "accepted" not in refusal and "client_accepted" not in refusal
    # Real pairing calculation of the exact singleton-token candidate relation.
    v = int.from_bytes(__import__("secrets").token_bytes(32), "big") % ORDER
    s = int.from_bytes(__import__("secrets").token_bytes(32), "big") % ORDER or 1
    candidates = [b"A:residential", b"A:commercial", b"B:charging"]
    h = [int.from_bytes(hashlib.sha256(x).digest(), "big") % ORDER for x in candidates]
    token = G2.scale((v - h[0]) * pow(s, -1, ORDER))
    exposed = GT.scale(v).divide(pairing(G1.scale(s), token))
    matches = [i for i, x in enumerate(h) if GT.scale(x) == exposed]
    assert matches == [0]
    checks.append(
        {
            "name": "singleton_policy_candidate_relation",
            "result": "DEMONSTRATED_LIMITATION",
            "matched_candidate_indices": matches,
            "real_pairing": True,
            "scope": "authorization-set hiding; not a break of ML-DSA or TLS",
        }
    )
    output = {
        "probe_type": "REAL_PRIMITIVES_NOT_VERTICAL_SAB",
        "started_at": started,
        "finished_at": native.utc(),
        "library": json.loads(native.LIB.grid_library_info()),
        "checks": checks,
        "connections": links,
        "strict_group_refusal": refusal,
        "command": ".venv/bin/python scripts/probe.py",
        "exit_code": 0,
    }
    path = Path(__file__).resolve().parents[1] / "artifacts/probes/primitives.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "probe": str(path),
                "primitive_checks": "PASS",
                "singleton_policy_hiding": "DEMONSTRATED_LIMITATION",
                "links": [x["client"]["actual_group"] for x in links],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()

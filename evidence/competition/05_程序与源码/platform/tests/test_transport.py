import copy
import json
import os
import select
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from services import native, pfdam
from services.dataset import windows
from services.encoding import digest
from services.initialization import ROOT, RUNTIME, command
from services.orchestrator import initialize, free_port
from services.signatures import sign_object
from services.storage import read, write
from tests.provenance import observe


def attempt(
    server="gateway",
    peer="source",
    client="source",
    client_peer=None,
    client_runtime=RUNTIME,
    raw=False,
):
    port = free_port()
    listener = native.Listener(port, server, peer, "X25519MLKEM768", RUNTIME, "L1")
    result = {}

    def serve():
        try:
            with listener.accept() as c:
                obj = c.receive()
                result["received"] = True
                c.send({"request_id": obj["request_id"], "ok": True})
        except Exception as e:
            result["server_error"] = str(e)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        if raw:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as c:
                c.sendall(b"POST /report HTTP/1.1\r\n\r\n")
        else:
            with native.TLS.connect(
                port,
                client,
                client_peer or server,
                "X25519MLKEM768",
                client_runtime,
                "L1",
            ) as c:
                c.send({"request_id": "test-actual-frame", "probe": True})
                result["response"] = c.receive()
    except Exception as e:
        result["client_error"] = str(e)
    thread.join(4)
    listener.close()
    assert not thread.is_alive()
    return result


@pytest.mark.acceptance("T29")
def test_untrusted_certificate_rejected(tmp_path):
    initialize()
    test = tmp_path / "pki"
    shutil.copytree(RUNTIME / "public", test / "public")
    shutil.copytree(RUNTIME / "source", test / "source")
    command('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', test/'source/tls.key')
    command(
        "openssl",
        "req",
        "-new",
        "-x509",
        "-key",
        test / "source/tls.key",
        "-out",
        test / "source/tls.pem",
        "-days",
        "1",
        "-subj",
        "/CN=source.grid",
        "-addext",
        "subjectAltName=DNS:source.grid",
    )
    result = attempt(client_runtime=test)
    assert "received" not in result and "server_error" in result


@pytest.mark.acceptance("T30")
def test_trusted_chain_wrong_hostname_and_wrong_role():
    initialize()
    name = attempt(client_peer="utility")
    role = attempt(server="utility", peer="gateway", client="source")
    assert "received" not in name and "received" not in role
    assert "TLS_PEER_IDENTITY_INVALID" in role["server_error"]


@pytest.mark.acceptance("T31")
def test_expired_certificate_rejected(tmp_path):
    initialize()
    test = tmp_path / "pki"
    shutil.copytree(RUNTIME / "public", test / "public")
    shutil.copytree(RUNTIME / "source", test / "source")
    command('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', test/'source/tls.key')
    command('openssl', 'req', '-new', '-key', test/'source/tls.key', '-out', test/'source/tls.csr', '-subj', '/CN=source.grid')
    (test / "index").write_text("")
    (test / "serial").write_text("1000\n")
    (test / "newcerts").mkdir()
    conf = test / "ca.conf"
    conf.write_text(
        f"[ca]\ndefault_ca=test_ca\n[test_ca]\ndatabase={test}/index\nnew_certs_dir={test}/newcerts\nserial={test}/serial\ncertificate={RUNTIME}/public/ca.pem\nprivate_key={RUNTIME}/ta/ca.key\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n[rolecert]\nsubjectAltName=DNS:source.grid\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n"
    )
    command(
        "openssl",
        "ca",
        "-config",
        conf,
        '-keyfile',
        RUNTIME/'ta/ca.key',
        "-batch",
        "-notext",
        "-in",
        test / "source/tls.csr",
        "-out",
        test / "source/tls.pem",
        "-startdate",
        "20200101000000Z",
        "-enddate",
        "20210101000000Z",
        "-extensions",
        "rolecert",
    )
    result = attempt(client_runtime=test)
    assert "received" not in result and "server_error" in result


@pytest.mark.acceptance("T32")
def test_plaintext_cannot_reach_tls_application():
    initialize()
    result = attempt(raw=True)
    assert "received" not in result and "server_error" in result


@pytest.mark.acceptance("T34")
def test_tls_record_mutation_is_rejected_at_transport():
    initialize()
    port = free_port()
    listener = native.Listener(
        port, "gateway", "source", "X25519MLKEM768", RUNTIME, "L1"
    )
    proxy = socket.socket()
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(1)
    proxy_port = proxy.getsockname()[1]
    armed = threading.Event()
    handshake_ready = threading.Event()
    result = {"mutated_records": 0}

    def serve():
        try:
            with listener.accept() as c:
                handshake_ready.set()
                c.receive()
                result["application_received"] = True
        except Exception as e:
            result["server_error"] = str(e)

    def relay():
        downstream = None
        upstream = None
        try:
            downstream, _ = proxy.accept()
            upstream = socket.create_connection(("127.0.0.1", port))
            while True:
                ready, _, _ = select.select([downstream, upstream], [], [], 5)
                if not ready:
                    break
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    if (
                        source is downstream
                        and armed.is_set()
                        and result["mutated_records"] == 0
                    ):
                        data = data[:-1] + bytes([data[-1] ^ 1])
                        result["mutated_records"] += 1
                    (upstream if source is downstream else downstream).sendall(data)
        except OSError:
            pass
        finally:
            if downstream:
                downstream.close()
            if upstream:
                upstream.close()

    server_thread = threading.Thread(target=serve, daemon=True)
    proxy_thread = threading.Thread(target=relay, daemon=True)
    server_thread.start()
    proxy_thread.start()
    try:
        with native.TLS.connect(
            proxy_port, "source", "gateway", "X25519MLKEM768", RUNTIME, "L1"
        ) as c:
            assert handshake_ready.wait(5)
            armed.set()
            c.send({"request_id": "tls-mutation", "probe": True})
            c.receive()
    except Exception as e:
        result["client_error"] = str(e)
    server_thread.join(5)
    proxy_thread.join(5)
    listener.close()
    proxy.close()
    assert result["mutated_records"] == 1 and "application_received" not in result
    assert "TLS_READ_FAILED" in result["server_error"]
    write(
        ROOT / "artifacts/probes/tls_record_mutation.json",
        {
            "result": result,
            "classification": "TLS_RECORD_INTEGRITY_NOT_PFDAM",
            "scope": "owned loopback test connections only",
        },
    )


def utility_session(start_only=False):
    initialize()
    run_id = uuid.uuid4().hex
    job = RUNTIME / "runs" / run_id
    port = free_port()
    for role in ("utility", "gateway", "source"):
        (job / role).mkdir(parents=True)
    write(job / "source/dataset.json", {"private_test_fixture": True}, True)
    public = read(RUNTIME / "public/parameters.json")
    context = {
        "object_type": "GRID_PUBLIC_TASK_V1",
        "schema_version": 1,
        "task_id": uuid.uuid4().hex,
        "run_id": run_id,
        "task_nonce": uuid.uuid4().hex,
        "metric_id": "average_active_power_W",
        "param_id": public["param_id"],
        "slots": windows(1),
    }
    write(job / "utility/context.json", context, True)
    write(
        job / "utility/config.json",
        {
            "region": "A",
            "resources": ["residential"],
            "expected_target_count": 1,
            "node_count": 1,
        },
        True,
    )
    log = (job / "utility/process.log").open("wb")
    args = [
        sys.executable,
        "-m",
        "services.workers",
        "--role",
        "utility",
        "--runtime",
        str(RUNTIME),
        "--job",
        str(job),
        "--run-id",
        run_id,
        "--profile",
        "SAB",
        "--fault",
        "normal",
        "--l1",
        str(free_port()),
        "--l2",
        str(port),
    ]
    from services.custody import worker_environment
    with worker_environment(RUNTIME, 'utility') as (environment, inherited):
        proc = subprocess.Popen(args, cwd=ROOT, env={**environment, 'PYTHONPATH': str(ROOT)}, pass_fds=inherited, stdout=log, stderr=log)
    deadline = time.monotonic() + 15
    while not (job / "utility/ready.json").exists():
        if proc.poll() is not None:
            raise AssertionError((job / "utility/process.log").read_text())
        if time.monotonic() > deadline:
            proc.kill()
            raise AssertionError("utility ready timeout")
        time.sleep(0.05)
    if start_only:
        return proc, log, job, port, context, public
    conn = native.TLS.connect(
        port, "gateway", "utility", "X25519MLKEM768", RUNTIME, "L2"
    )
    conn.send(
        {"type": "pull_authorization", "run_id": run_id, "request_id": uuid.uuid4().hex}
    )
    reply = conn.receive()
    auth = reply["authorization"]["payload"]
    gw = read(RUNTIME / "gateway/pfdam.json")
    value = pfdam.report(
        public, 42, pfdam.tag(context, "slot-0", "A", "residential"), native.utc()
    )
    envelope = {
        "task_id": context["task_id"],
        "run_id": run_id,
        "slot_id": "slot-0",
        "param_id": public["param_id"],
        "report": value,
    }
    envelope["report_id"] = digest(envelope)
    agg, accepted, _ = pfdam.match_and_aggregate(
        public, gw, auth["token_bundle"]["slot-0"], [envelope]
    )
    stamp = native.utc()
    payload = {
        "object_type": "GRID_AGG_RECEIPT_V1",
        "schema_version": 1,
        "task_id": context["task_id"],
        "run_id": run_id,
        "authorization_digest": digest(auth),
        "snapshot_id": uuid.uuid4().hex,
        "slot_id": "slot-0",
        "param_id": public["param_id"],
        "aggregate_ciphertext": str(agg),
        "native_signature": pfdam.native_sign(gw, agg, stamp),
        "native_timestamp": stamp,
        "counts": {
            "received": 1,
            "accepted": 1,
            "joint_check_failed": 0,
            "invalid": 0,
            "duplicate": 0,
            "late": 0,
        },
        "status": "AGGREGATED",
        "issued_at": stamp,
        "input_digest": digest([envelope["report_id"]]),
        "key_epoch": 1,
        "security_profile": "SAB",
    }
    return conn, payload, proc, log, job


def close_session(conn, proc, log):
    conn.close()
    if proc.poll() is None:
        proc.terminate()
    proc.wait(timeout=5)
    log.close()


@pytest.mark.acceptance("T24")
def test_receipt_idempotency_uses_payload_not_random_signature_bits():
    conn, payload, proc, log, job = utility_session()
    try:
        first, _ = sign_object(payload, RUNTIME)
        second, _ = sign_object(payload, RUNTIME)
        assert first["signatures"] != second["signatures"]
        for obj, duplicate in ((first, False), (first, True), (second, True)):
            conn.send(
                {
                    "type": "submit_receipt",
                    "run_id": payload["run_id"],
                    "request_id": uuid.uuid4().hex,
                    "receipt": obj,
                }
            )
            ack = conn.receive()
            assert ack["accepted"] and ack["idempotent"] is duplicate
        with sqlite3.connect(job / "utility/state.sqlite") as db:
            assert db.execute("SELECT count(*) FROM results").fetchone()[0] == 1
        conn.send(
            {
                "type": "finish",
                "run_id": payload["run_id"],
                "request_id": uuid.uuid4().hex,
            }
        )
        conn.receive()
        proc.wait(timeout=5)
        assert proc.returncode == 0
    finally:
        close_session(conn, proc, log)


@pytest.mark.acceptance("T23")
def test_valid_cross_task_receipt_rejected_by_actual_utility():
    conn, payload, proc, log, job = utility_session()
    try:
        payload["task_id"] = uuid.uuid4().hex
        obj, _ = sign_object(payload, RUNTIME)
        conn.send(
            {
                "type": "submit_receipt",
                "run_id": payload["run_id"],
                "request_id": uuid.uuid4().hex,
                "receipt": obj,
            }
        )
        ack = conn.receive()
        assert not ack["accepted"] and ack["code"] == "RECEIPT_CONTEXT_MISMATCH"
        proc.wait(timeout=5)
        record = read(job / "utility/rejection.json")
        assert record["signature_evidence"]["signature_valid"] is True
    finally:
        close_session(conn, proc, log)

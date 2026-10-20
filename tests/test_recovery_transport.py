"""Concurrent producers and post-seal input over the actual role TLS protocol."""
import os
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from services import native, pfdam
from services.encoding import digest
from services.initialization import ROOT, RUNTIME
from services.orchestrator import free_port
from services.signatures import sign_object
from services.storage import read
from tests.provenance import observe
from tests.test_transport import utility_session, close_session


@pytest.mark.recovery('R01')
@pytest.mark.acceptance('T24')
def test_concurrent_receipt_producers_publish_one_snapshot():
    conn, payload, process, log, job = utility_session()
    try:
        objects = [sign_object(payload, RUNTIME)[0] for _ in range(2)]
        barrier = threading.Barrier(2)
        send_lock = threading.Lock()

        def send(envelope):
            barrier.wait(timeout=5)
            with send_lock:  # one GW TLS stream must preserve complete frame boundaries
                conn.send({'type': 'submit_receipt', 'run_id': payload['run_id'],
                           'request_id': uuid.uuid4().hex, 'receipt': envelope})

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(send, obj) for obj in objects]
            for future in futures:
                future.result(timeout=10)
        acks = [conn.receive() for _ in range(2)]
        assert all(r['accepted'] for r in acks)
        assert sorted(r['idempotent'] for r in acks) == [False, True]
        with sqlite3.connect(job / 'utility/state.sqlite') as db:
            count = db.execute('SELECT count(*) FROM results').fetchone()[0]
        assert count == 1
        assert len(read(job / 'utility/published.json')['results']) == 1
        observe('concurrent_receipts', {'acknowledgements': acks, 'persisted_result_rows': count,
                                       'scope': 'two concurrent producers on one authenticated GW/UC stream; UC serializes frames'})
        conn.send({'type': 'finish', 'run_id': payload['run_id'], 'request_id': uuid.uuid4().hex})
        conn.receive()
        process.wait(timeout=5)
        assert process.returncode == 0
    finally:
        close_session(conn, process, log)


@pytest.mark.recovery('R02')
def test_sealed_gateway_rejects_changed_late_batch_and_keeps_old_result():
    utility, utility_log, job, l2, context, public = utility_session(start_only=True)
    l1 = free_port()
    gateway_log = (job / 'gateway/process.log').open('wb')
    from services.custody import worker_environment
    with worker_environment(RUNTIME, 'gateway') as (environment, inherited):
        gateway = subprocess.Popen([sys.executable, '-m', 'services.workers', '--role', 'gateway', '--runtime', str(RUNTIME),
             '--job', str(job), '--run-id', context['run_id'], '--profile', 'SAB', '--fault', 'normal', '--l1', str(l1), '--l2', str(l2)],
            cwd=ROOT, env={**environment, 'PYTHONPATH': str(ROOT)}, pass_fds=inherited, stdout=gateway_log, stderr=gateway_log)
    conn = None
    try:
        deadline = time.monotonic() + 15
        while not (job / 'gateway/ready.json').exists():
            assert gateway.poll() is None
            assert time.monotonic() < deadline
            time.sleep(.02)
        conn = native.TLS.connect(l1, 'source', 'gateway', 'X25519MLKEM768', RUNTIME, 'L1')
        conn.send({'type': 'pull_context', 'run_id': context['run_id'], 'request_id': uuid.uuid4().hex})
        actual_context = conn.receive()['context']

        def batch(value):
            envelope = {k: actual_context[k] for k in ('task_id', 'run_id', 'param_id')}
            envelope.update(slot_id='slot-0', report=pfdam.report(
                public, value, pfdam.tag(actual_context, 'slot-0', 'A', 'residential'), native.utc()))
            envelope['report_id'] = digest(envelope)
            return {'type': 'report_batch', 'run_id': context['run_id'], 'request_id': uuid.uuid4().hex,
                    'slot_id': 'slot-0', 'reports': [envelope]}

        conn.send(batch(42))
        assert conn.receive()['received'] is True
        original = read(job / 'utility/published.json')
        assert original['results'][0]['value_W'] == 42
        conn.send(batch(43))
        with pytest.raises(Exception):
            conn.receive()
        gateway.wait(timeout=5)
        error = read(job / 'gateway/error.json')
        assert error['code'] == 'REPORT_SNAPSHOT_SEALED'
        assert read(job / 'utility/published.json') == original
        observe('late_sealed_batch', {'gateway_error_code': error['code'],
                                      'published_snapshot_count': len(original['results']),
                                      'published_receipt_digest': original['results'][0]['receipt_digest']})
    finally:
        if conn is not None:
            conn.close()
        for process, log in ((gateway, gateway_log), (utility, utility_log)):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            log.close()

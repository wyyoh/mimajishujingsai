"""Fail-closed API restart recovery of previously UC-verified durable snapshots."""
import os
import select
import signal
import sqlite3
from pathlib import Path

from .encoding import digest, canonical, Rejected
from .initialization import ROOT, RUNTIME
from .native import utc
from .signatures import verify_object
from .storage import read, write
from .versioning import source_version


def _matches_role(pid, run_id, job):
    try:
        args = (Path('/proc') / str(pid) / 'cmdline').read_bytes().decode().split('\0')
        if not any(module in args for module in ('services.workers', 'services.expansion_workers')):
            return False
        expected = {'--run-id': run_id, '--runtime': str(RUNTIME), '--job': str(job)}
        return all(flag in args and args[args.index(flag) + 1] == value for flag, value in expected.items())
    except (OSError, UnicodeError, IndexError):
        return False


def stop_orphan_roles(run_id, job):
    stopped = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        if not _matches_role(pid, run_id, job):
            continue
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            continue
        try:
            # Recheck after obtaining the kernel process handle; never signal a recycled PID.
            if not _matches_role(pid, run_id, job):
                continue
            signal.pidfd_send_signal(fd, signal.SIGTERM)
            poll = select.poll()
            poll.register(fd, select.POLLIN)
            if not poll.poll(1000):
                signal.pidfd_send_signal(fd, signal.SIGKILL)
                poll.poll(1000)
            stopped.append(True)
        except ProcessLookupError:
            pass
        finally:
            os.close(fd)
    return len(stopped)


def recover_interrupted_submissions():
    database = RUNTIME / 'api.sqlite'
    if not database.exists():
        return []
    with sqlite3.connect(database) as db:
        if not db.execute("SELECT name FROM sqlite_master WHERE name='submissions'").fetchone():
            return []
        run_ids = [r[0] for r in db.execute('SELECT run_id FROM submissions')]
    recovered = []
    for run_id in run_ids:
        if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
            raise Rejected('RECOVERY_RUN_ID_INVALID')
        directory = ROOT / 'artifacts/runs' / run_id
        path = directory / 'run_manifest.json'
        if not path.exists():
            continue
        manifest = read(path)
        if manifest['status'] != 'RUNNING':
            continue
        job = RUNTIME / 'runs' / run_id
        write(directory / 'cancel.request', {'requested': True, 'reason': 'SERVER_RESTARTED'})
        if job.exists():
            write(job / 'cancel.request', {'requested': True, 'reason': 'SERVER_RESTARTED'}, True)
        stopped = stop_orphan_roles(run_id, job)
        if manifest.get('protocol_version')==5:
            for child_path in (ROOT/'artifacts/runs').glob('*/run_manifest.json'):
                child=read(child_path)
                if child.get('parent_evaluation')==run_id:
                    stopped+=stop_orphan_roles(child['run_id'],RUNTIME/'runs'/child['run_id'])
                    if child.get('status') in ('RUNNING','COMPUTED'):
                        child.update(status='CANCELLED',results=[],publication_status='NOT_PUBLISHED')
                        write(child_path,child)
            from .publication_runtime import recover
            recovered.append(recover(manifest))
            continue
        record = {
            'run_id': run_id, 'at': utc(), 'previous_status': 'RUNNING',
            'code': 'SERVER_RESTARTED', 'stopped_owned_role_count': stopped,
            'retained_snapshot_count': 0, 'receipt_signatures_reverified': None,
            'recovery_source_digest': source_version()['core_source_digest'],
            'scope': 'Retain previously UC-verified durable snapshots; unfinished task is not resumed. Receipt signatures do not independently prove plaintext correspondence.',
        }
        errors = [{'code': 'SERVER_RESTARTED', 'stage': 'RECOVERY',
                   'message': '服务重启中断了任务；已发布快照保留，未完成计算不续跑。'}]
        published_path = job / 'utility/published.json'
        results = []
        if published_path.exists():
            try:
                published = read(published_path)
                if published['run_id'] != run_id or not (len(published['results']) == len(published['receipts']) == len(published['signature_evidence'])):
                    raise Rejected('RECOVERY_SNAPSHOT_SHAPE_INVALID')
                for result, envelope in zip(published['results'], published['receipts'], strict=True):
                    kind = f"GRID_AGG_RECEIPT_V{manifest.get('protocol_version', 1)}"
                    receipt, verification = verify_object(envelope, kind, manifest['security_profile'], RUNTIME, usage='history')
                    if any(receipt[k] != manifest[k] for k in ('run_id', 'task_id', 'param_id')):
                        raise Rejected('RECOVERY_RECEIPT_CONTEXT_MISMATCH')
                    if result['slot_id'] != receipt['slot_id'] or result['receipt_digest'] != digest(receipt) or canonical(result['counts']) != canonical(receipt['counts']):
                        raise Rejected('RECOVERY_RESULT_RECEIPT_MISMATCH')
                    if verification['signature_valid'] is not True:
                        raise Rejected('RECOVERY_RECEIPT_SIGNATURE_INVALID')
                    if manifest.get('protocol_version') in (2, 3, 4):
                        from .v41_evidence import verify_links
                        if manifest.get('protocol_version') in (3, 4):
                            from .expansion_evidence import verify_links
                        slot = receipt['slot_id']
                        verify_links(receipt, published['snapshots'][slot], published['audit_checkpoints'][slot],
                                     published['accepted_manifests'][slot], published['governance'])
                        if manifest.get('protocol_version') == 4:
                            from .result_attestation import verify_statement
                            candidates = [item for item in published['result_statements'] if item['payload']['selected_slot']['slot_id'] == slot]
                            if len(candidates) != 1:
                                raise Rejected('RECOVERY_UC_STATEMENT_MISSING')
                            verify_statement(candidates[0], result, receipt, published['governance'], RUNTIME)
                results = published['results']
                write(directory / 'receipts.json', published['receipts'])
                write(directory / 'signature_evidence.json', published['signature_evidence'])
                if manifest.get('protocol_version') in (2, 3, 4):
                    for name in ('snapshots', 'audit_checkpoints', 'accepted_manifests', 'governance'):
                        write(directory / (name + '.json'), published[name])
                    if manifest.get('protocol_version') == 4:
                        write(directory / 'result_statements.json', published['result_statements'])
                record['retained_snapshot_count'] = len(results)
                record['receipt_signatures_reverified'] = True
            except (AssertionError, KeyError, Rejected) as exc:
                errors.append({'code': 'RECOVERY_SNAPSHOT_INVALID', 'stage': 'RECOVERY',
                               'message': '恢复快照未通过校验，保留私有原件供复核。'})
                record['retained_snapshot_count'] = 0
                record['receipt_signatures_reverified'] = False
        manifest.update(status='FAILED', results=results, errors=errors, finished_at=record['at'])
        manifest.pop('oracle_match', None)
        manifest.setdefault('signature_evidence_refs', [])
        if results and 'signature_evidence.json' not in manifest['signature_evidence_refs']:
            manifest['signature_evidence_refs'].append('signature_evidence.json')
        write(directory / 'recovery_evidence.json', record)
        write(path, manifest)
        recovered.append(record)
    return recovered

"""Authenticated V4.2 data, scenarios and V3 task routes; legacy routes remain intact."""
import os
import sqlite3
from contextlib import closing
from types import SimpleNamespace
from typing import Literal
from fastapi import Header, HTTPException, Request

from .encoding import Rejected, digest
from .expansion_data import catalogue, curve
from .expansion_governance import SCENES
from .publication import prepare
from .expansion_schemas import ExpansionRequest
from .initialization import ROOT,RUNTIME
from .sessions import principal
from .storage import read
from .versioning import source_version

class LabRequest(ExpansionRequest):
    fault: Literal['normal', 'modified_report', 'missing', 'source_identity', 'snapshot_tamper', 'invalid_receipt', 'invalid_authorization'] = 'normal'

def install(app, enqueue, summary):
    @app.get('/api/expansion/catalog')
    def catalog():
        return {'datasets': catalogue(), 'scenes': [{'scene_id': key, **value} for key, value in SCENES.items()],
                'version': 'V5', 'source_count_options': [1, 2, 3], 'max_periods_per_task': 4, 'physical_host_count': 1,
                'lab_enabled': os.environ.get('GRID_LAB') == '1'}

    def authorized(data, request):
        try:
            return prepare(data, principal(request))
        except Rejected as exc:
            raise HTTPException(403, exc.code) from exc

    @app.post('/api/expansion/preview')
    def preview(data: ExpansionRequest, request: Request):
        policy, _, _ = authorized(data, request)
        return {'execution_mode': 'PREVIEW', 'authorization_signed': False, 'policy': policy, 'policy_digest': digest(policy)}

    @app.post('/lab/expansion/curve')
    def daily_curve(data: ExpansionRequest, request: Request):
        if os.environ.get('GRID_LAB') != '1':
            raise HTTPException(403, 'LAB_DISABLED')
        if data.dataset_id == 'SYN-WEEK-V42':
            raise HTTPException(403, 'PRIVATE_SOURCE_PREVIEW_DISABLED')
        policy, _, _ = authorized(data, request)
        return curve(data.dataset_id, data.nodes, data.day, policy['region'], policy['resources'])

    def submit(data, request, key, lab, fault):
        body = data.model_dump()
        body.pop('fault', None)
        policy, _, _ = authorized(ExpansionRequest(**body), request)
        adapter = SimpleNamespace(region=policy['region'], resources=policy['resources'], scenario=fault,
                                  model_dump=lambda: {**body, 'scenario': fault})
        return enqueue(adapter, key, lab, governance=policy,
                       request_digest=digest({'request': body, 'fault': fault, 'lab': lab, 'subject': policy['requester_id']}))

    @app.post('/api/expansion/collaborations', status_code=202)
    def create(data: ExpansionRequest, request: Request, idempotency_key: str | None = Header(default=None)):
        return submit(data, request, idempotency_key, False, 'normal')

    @app.post('/lab/expansion/collaborations', status_code=202)
    def laboratory(data: LabRequest, request: Request, idempotency_key: str | None = Header(default=None)):
        if os.environ.get('GRID_LAB') != '1':
            raise HTTPException(403, 'LAB_DISABLED')
        return submit(data, request, idempotency_key, True, data.fault)

    @app.get('/api/expansion/runs')
    def history(request: Request):
        subject = principal(request)
        from .custody import trust_pin
        authority=trust_pin(RUNTIME)['registry_pin']
        records = []
        # API submissions already have a runtime-local, subject-indexed nonce
        # record. Do not scan private experiments or every historical artifact.
        index=RUNTIME/'api.sqlite'
        if not index.is_file():
            return records
        with closing(sqlite3.connect(index.resolve().as_uri()+'?mode=ro',uri=True)) as database:
            if not database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='v41_nonces'").fetchone():
                return records
            identifiers=database.execute('SELECT run_id FROM v41_nonces WHERE subject=? ORDER BY rowid DESC LIMIT 200',(subject,)).fetchall()
        for (identifier,) in identifiers:
            if not isinstance(identifier,str) or len(identifier)!=32 or any(c not in '0123456789abcdef' for c in identifier):
                continue
            path=ROOT/'artifacts/runs'/identifier/'run_manifest.json'
            try:
                record=read(path)
            except FileNotFoundError:
                continue
            if record.get('protocol_version') == 5 and record.get('input_binding_scheme')=='ROLE_HMAC_SHA384_V1' and (path.parent/'publication_rules.json').is_file() and record.get('runtime_instance')==authority and not record.get('private_experiment') and record.get('parent_evaluation','none')=='none' and record.get('requester_id') == subject and (not record.get('lab') or os.environ.get('GRID_LAB') == '1'):
                records.append({key: record.get(key) for key in ('run_id', 'status', 'started_at', 'scene_id', 'data_source', 'dataset_id', 'node_count', 'slot_count', 'logical_source_process_count', 'algorithm_suite')})
            if len(records) >= 20:
                break
        return records

    @app.get('/api/runs/{run_id}/expansion')
    def details(run_id: str, request: Request):
        subject = principal(request)
        current = summary(run_id)
        if current.get('protocol_version') != 5 or current.get('requester_id') != subject:
            raise HTTPException(403, 'V42_RUN_ACCESS_DENIED')
        directory = ROOT / 'artifacts/runs' / run_id
        result = {name: read(directory / f'{name}.json') if (directory / f'{name}.json').exists() else None
                  for name in ('governance', 'data_provenance', 'audit_checkpoints', 'connection_evidence', 'role_isolation', 'signature_evidence', 'receipts', 'result_statements', 'release', 'release_statement')}
        if os.environ.get('GRID_LAB') != '1':
            result.pop('oracle_summary', None)
        snapshots = read(directory / 'snapshots.json') if (directory / 'snapshots.json').exists() else {}
        result['snapshots'] = {slot: {key: value for key, value in item.items() if key != 'records'} for slot, item in snapshots.items()}
        return result

    @app.post('/api/runs/{run_id}/expansion/verify')
    def verify(run_id: str, request: Request):
        principal(request)
        current = summary(run_id)
        if current.get('protocol_version') != 5:
            raise HTTPException(409, 'V42_RECORD_REQUIRED')
        from .evidence import export_public, verify_export
        try:
            return verify_export(export_public(run_id), expected_context={key: current[key] for key in
                                 ('run_id', 'task_id', 'param_id', 'security_profile', 'slot_count', 'algorithm_suite', 'policy_digest', 'dataset_digest', 'scene_id', 'logical_source_process_count')})
        except Rejected as exc:
            raise HTTPException(422, exc.code) from exc

    @app.get('/lab/expansion/benchmarks')
    def benchmarks():
        if os.environ.get('GRID_LAB') != '1':
            raise HTTPException(403, 'LAB_DISABLED')
        path = ROOT / 'artifacts/iterations/v42/benchmarks/summary.json'
        result = read(path) if path.exists() else {'status': 'NOT_RUN', 'rows': []}
        result['current_version_matches'] = result.get('core_source_digest') == source_version()['core_source_digest']
        return result

"""Actual V3 data/source computations and tampering, with independent source oracles."""
import copy
import hashlib
import json
import time
import uuid
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from services.encoding import Rejected, canonical
from services.expansion_data import PUBLIC_ID, SYNTHETIC_ID, catalogue, curve, load, select
from services.expansion_governance import prepare
from services.expansion_orchestrator import execute
from services.expansion_schemas import ExpansionRequest
from services.evidence import export_public, verify_export
from services.initialization import ROOT, RUNTIME
from services.storage import read
from tests.provenance import record_run

def test_listener_ports_stay_outside_outbound_ephemeral_range():
    import socket
    from services.orchestrator import free_port
    low, high = map(int, (Path('/proc/sys/net/ipv4/ip_local_port_range')).read_text().split())
    selected=set()
    sockets=[]
    try:
        for _ in range(12):
            port=free_port(selected)
            assert port not in selected and not low<=port<=high
            listener=socket.socket();listener.bind(('127.0.0.1',port));listener.listen(1)
            sockets.append(listener);selected.add(port)
            with socket.create_connection(('127.0.0.1',port)) as client:
                connection,_=listener.accept()
                with connection:
                    assert client.getsockname()[1] not in selected
    finally:
        for listener in sockets:
            listener.close()

def request(**values):
    return ExpansionRequest(request_nonce=uuid.uuid4().hex, **values)

def run(**values):
    fault = values.pop('fault', 'normal')
    policy, _, _ = prepare(request(**values), 'grid_operator_A')
    result = execute(policy, fault=fault)
    record_run(result['run_id'])
    return result

def test_public_data_provenance_and_day_selection():
    metadata = next(item for item in catalogue() if item['dataset_id'] == PUBLIC_ID)
    assert metadata['provenance']['license'] == 'CC BY 4.0'
    assert metadata['provenance']['point_count'] == 248640
    data = load(PUBLIC_ID, 120)
    assert len(data['nodes']) == 120 and len(data['slots']) == 672
    assert all(len(node['values_W']) == 672 for node in data['nodes'])
    assert {node['resource_class'] for node in data['nodes']} == {'residential', 'commercial', 'charging'}
    view = select(PUBLIC_ID, 120, 3, [68, 70])
    assert view['period_indices'] == [356, 358]
    by_id = {node['node_id']: node for node in data['nodes']}
    assert all(node['values_W'] == [by_id[node['node_id']]['values_W'][356], by_id[node['node_id']]['values_W'][358]] for node in view['nodes'])
    assert 'original_column' not in view['nodes'][0]
    preview = curve(PUBLIC_ID, 120, 3, 'A', ['residential'])
    assert preview['execution_mode'] == 'PREVIEW' and len(preview['points']) == 96
    assert preview['points'][68]['sum_W'] == sum(node['values_W'][356] for node in data['nodes'] if node['region'] == 'A' and node['resource_class'] == 'residential')
    with pytest.raises(Rejected):
        select(PUBLIC_ID, 600, 0, [0])
    with pytest.raises(Rejected):
        select(PUBLIC_ID, 120, 0, [1, 0])

def test_expansion_offline_fresh_runtime_record():
    from services.versioning import source_version
    record = read(ROOT / 'artifacts/iterations/privacy/current/v4-offline.json')
    assert record['exit_code'] == 0 and record['protocol_version'] == 4
    assert record['source_count'] == 3 and record['data_source'] == 'PUBLIC_OBSERVED_SIMULATED_GROUPS'
    assert record['network_disabled'] and record['fresh_runtime'] and record['fresh_virtual_environment']
    assert record['oracle_match'] and record['role_file_isolation'] and record['public_receipt_links_verified']
    assert record['core_source_digest'] == source_version()['core_source_digest']
    publication=read(ROOT/'artifacts/iterations/privacy/current/publication-offline.json')
    assert publication['exit_code']==0 and publication['protocol_version']==5 and publication['business_metrics_recomputed']
    assert publication['data_source']=='PUBLIC_OBSERVED_SIMULATED_GROUPS' and publication['oracle_match'] and publication['role_file_isolation']
    assert publication['core_source_digest']==source_version()['core_source_digest']

def test_expansion_browser_record():
    from services.versioning import source_version
    result = read(ROOT / 'artifacts/iterations/privacy/current/browser.json')
    assert result['exit_code'] == 0 and result['daily_preview_points'] == 96
    assert result['public_real_multi_source'] and result['business_metrics_recomputed'] and result['source_identity_and_isolation_visible']
    assert result['replay_preserves_source'] and result['real_401_login_recovery'] and result['protocol_version']==5
    assert result['core_source_digest'] == source_version()['core_source_digest']
    for filename, sha in result['ui_fingerprint']['files'].items():
        assert filename.startswith('apps/web/') and hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() == sha
    record_run(result['run_id'])

@pytest.mark.parametrize('scene,function,sources', [('residential','SUM',1), ('park','AVG',2), ('charging','COUNT',3)])
def test_observed_load_scenarios_and_independent_sources(scene, function, sources):
    result = run(dataset_id=PUBLIC_ID, scene_id=scene, function=function, source_count=sources, periods=[68, 69])
    assert result['status'] == 'COMPLETED' and result['oracle_match'] is True
    assert result['logical_source_process_count'] == sources and result['role_file_isolation'] is True
    directory = ROOT / 'artifacts/runs' / result['run_id']
    connections = read(directory / 'connection_evidence.json')
    assert len(connections) == 2*(sources+1)
    assert all(row['actual_group'] == 'X25519MLKEM768' and row['application_cipher'] == 'SM4-GCM' for row in connections)
    assert len({row['peer_certificate_sha256'] for row in connections if row['peer_role'].startswith('source-')}) == sources
    verified = verify_export(export_public(result['run_id']), expected_context={'run_id':result['run_id'], 'dataset_digest': result['dataset_digest'], 'logical_source_process_count':sources})
    assert verified['receipt_authenticity_verified'] and all(row['source_bindings_verified'] for row in verified['v41_checks'])
    receipts = read(directory/'receipts.json')
    for receipt in receipts:
        assert len(receipt['payload']['source_snapshots']) == sources
        assert {item['algorithm'] for item in receipt['signatures']} == {'ECDSA-P256-SHA256','ML-DSA-65','SM2-SM3'}
    with zipfile.ZipFile(export_public(result['run_id'])) as archive:
        serialized = b'\n'.join(archive.read(name) for name in archive.namelist())
        assert all(secret not in serialized for secret in (b'token_bundle', b'values_W', b'original_column', b'BEGIN PRIVATE KEY'))

@pytest.mark.parametrize('fault,expected', [('source_identity','SOURCE_REPORT_IDENTITY_OR_CONTEXT_MISMATCH'),('snapshot_tamper','SOURCE_SNAPSHOT_OR_PARTITION_MISMATCH'),('invalid_authorization','OBJECT_SIGNATURE_INVALID'),('invalid_receipt','OBJECT_SIGNATURE_INVALID')])
def test_multi_source_real_faults_fail_closed(fault, expected):
    result = run(source_count=3, scene_id='park', periods=[68], fault=fault)
    assert result['status'] == 'REJECTED' and not result['results']
    assert expected in {error['code'] for error in result['errors']}

def test_multi_source_missing_and_modified_reports():
    for fault in ('missing', 'modified_report'):
        result = run(source_count=3, scene_id='charging', periods=[72], fault=fault)
        assert result['status'] == 'PARTIAL' and result['oracle_match'] is True
        assert result['results'][0]['counts']['accepted'] < result['results'][0]['expected_target_count']

def test_v3_export_rejects_data_source_and_period_replacement(tmp_path):
    result = run(source_count=3, periods=[68])
    original = export_public(result['run_id'])
    with zipfile.ZipFile(original) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    for kind in ('source', 'data', 'period', 'unsigned_origin', 'count_type', 'provenance'):
        altered = dict(entries)
        receipts = json.loads(altered['receipts.json'])
        policy = json.loads(altered['governance.json'])
        manifest = json.loads(altered['run_manifest.json'])
        if kind == 'source':
            receipts[0]['payload']['source_snapshots'][0]['certificate_sha256'] = '0'*64
        elif kind == 'data':
            receipts[0]['payload']['dataset_digest'] = '0'*96
        elif kind == 'period':
            policy['period_indices'][0] += 1
        elif kind == 'count_type':
            receipts[0]['payload']['key_epoch'] = True
        elif kind == 'provenance':
            value = json.loads(altered['data_provenance.json'])
            value['dataset_digest'] = '0'*96
            altered['data_provenance.json'] = canonical(value)
        else:
            manifest['data_source'] = 'PUBLIC_OBSERVED_SIMULATED_GROUPS'
        altered['receipts.json'], altered['governance.json'], altered['run_manifest.json'] = canonical(receipts), canonical(policy), canonical(manifest)
        export = json.loads(altered['export_manifest.json'])
        export['files'] = {name: hashlib.sha256(value).hexdigest() for name,value in altered.items() if name != 'export_manifest.json'}
        altered['export_manifest.json'] = canonical(export)
        target = tmp_path / f'{kind}.zip'
        with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as archive:
            for name,value in altered.items():
                archive.writestr(name,value)
        with pytest.raises(Rejected):
            verify_export(target,expected_context={'run_id':result['run_id']})
    assert verify_export(original,expected_context={'run_id':result['run_id']})['receipt_authenticity_verified']

def test_expansion_api_permissions_and_normal_task(monkeypatch):
    from services import api
    from services.sessions import ACCESS_PATH
    with TestClient(api.app) as client:
        body = request(nodes=300,source_count=3, periods=[68]).model_dump()
        assert client.post('/api/expansion/preview',json=body).status_code == 401
        access = read(ACCESS_PATH)['accounts']
        assert client.post('/api/session',json={'subject':'grid_operator_A','password':access['grid_operator_A']}).status_code == 200
        for changes, status in [({'region':'B'},403),({'algorithm_suite':'V41_CLASSIC'},422),({'source_count':4},422),({'periods':[1,0]},403),({'periods':[1,2,3,4,5]},422)]:
            assert client.post('/api/expansion/preview',json={**body,**changes}).status_code == status
        key = uuid.uuid4().hex
        created = client.post('/api/expansion/collaborations',json=body,headers={'Idempotency-Key':key})
        assert created.status_code == 202
        run_id = created.json()['run_id'];record_run(run_id)
        repeat = client.post('/api/expansion/collaborations',json=body,headers={'Idempotency-Key':key})
        assert repeat.status_code == 202 and repeat.json()['run_id'] == run_id
        deadline = time.monotonic()+90
        while time.monotonic()<deadline:
            result = client.get('/api/runs/'+run_id).json()
            if result['status'] != 'RUNNING':
                break
            time.sleep(.1)
        assert result['status'] == 'COMPLETED'
        assert client.post(f'/api/runs/{run_id}/expansion/verify',json={}).status_code == 200
        assert client.post('/api/session',json={'subject':'grid_operator_B','password':access['grid_operator_B']}).status_code == 200
        assert client.get('/api/runs/'+run_id).status_code == 403
        assert client.get(f'/api/runs/{run_id}/expansion').status_code == 403

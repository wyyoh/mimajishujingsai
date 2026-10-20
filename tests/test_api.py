import time
import uuid
import threading
import pytest
from fastapi.testclient import TestClient
from services import api
from tests.provenance import record_run


def test_business_entry_enforces_local_profile_and_idempotency(monkeypatch,tmp_path):
    from services.storage import read,write
    from services.expansion_data import select
    from services.expansion_schemas import ExpansionRequest
    snapshot=tmp_path/'concurrent-snapshot.json';write(snapshot,{'revision':0})
    finished,errors=threading.Event(),[]
    def replace_snapshots():
        try:
            for revision in range(1,201):write(snapshot,{'revision':revision})
        except Exception as exc:errors.append(exc)
        finally:finished.set()
    writer=threading.Thread(target=replace_snapshots);writer.start()
    while not finished.is_set():assert 0<=read(snapshot)['revision']<=200
    writer.join();assert not errors and read(snapshot)=={'revision':200}
    with pytest.raises(FileNotFoundError):read(tmp_path/'permanently-missing.json')
    snapshot.write_bytes(b'invalid-json')
    with pytest.raises(ValueError,match='INVALID_JSON'):read(snapshot)
    monkeypatch.setattr(api,'LAB',False)
    key=uuid.uuid4().hex
    body=ExpansionRequest(nodes=300,periods=[68],source_count=3,request_nonce=uuid.uuid4().hex).model_dump()
    route='/api/expansion/collaborations'
    with TestClient(api.app) as client:
        from services.sessions import ACCESS_PATH
        access=read(ACCESS_PATH)['accounts']
        assert client.post(route,json=body,headers={'Idempotency-Key':key}).status_code==401
        assert client.post('/api/session',json={'subject':'grid_operator_A','password':access['grid_operator_A']}).status_code==200
        assert client.get('/api/config').json()['default_profile']=='SAB'
        for field in ('security_profile','key_path','token_bundle','private_control','minimum_cohort','input_binding_scheme'):
            assert client.post(route,json={**body,field:'S0'},headers={'Idempotency-Key':key}).status_code==422
        assert client.post(route,content='{"region":"A","region":"B"}',headers={'Content-Type':'application/json','Idempotency-Key':key}).status_code==422
        for legacy in ('/api/runs','/lab/runs','/api/collaborations','/lab/collaborations'):
            response=client.post(legacy,json={'region':'A','resources':['residential']},headers={'Idempotency-Key':key})
            assert response.status_code==409 and response.json()['detail']=='PROTECTED_WORKSPACE_REQUIRED'
        assert client.post('/lab/expansion/collaborations',json={**body,'fault':'missing'},headers={'Idempotency-Key':key}).status_code==403
        assert client.post(route,json={**body,'scenario':'invalid_receipt'},headers={'Idempotency-Key':key}).status_code==422
        assert client.post(route,json=body,headers={'Origin':'https://external.example','Idempotency-Key':key}).status_code==403
        created=client.post(route,json=body,headers={'Idempotency-Key':key})
        assert created.status_code==202
        identifier=created.json()['run_id'];record_run(identifier)
        assert client.post(route,json=body,headers={'Idempotency-Key':key}).json()=={'run_id':identifier,'idempotent':True}
        assert client.post(route,json={**body,'scene_id':'park'},headers={'Idempotency-Key':key}).status_code==409
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            result=client.get('/api/runs/'+identifier).json()
            if result['status']!='RUNNING':break
            time.sleep(.1)
        assert result['status']=='COMPLETED' and result['security_profile']=='SAB'
        assert result['lab'] is False and 'oracle_match' not in result and result['protocol_version']==5
        data=select(body['dataset_id'],body['nodes'],body['day'],body['periods'])
        expected=sum(node['values_W'][0] for node in data['nodes'] if node['region']=='A' and node['resource_class']=='residential')
        assert result['results'][0]['value_W']==expected
        assert 'oracle_summary' not in client.get('/api/runs/'+identifier+'/evidence').json()
        assert api.JOBS[identifier].join(5) is None
        # A malformed artifact outside this runtime's API submission index
        # cannot stall or break the ordinary recent-task list.
        orphan=api.RUNS/uuid.uuid4().hex/'run_manifest.json'
        orphan.parent.mkdir();orphan.write_bytes(b'not-json-from-another-experiment')
        try:
            recent=client.get('/api/expansion/runs')
            assert recent.status_code==200 and identifier in {row['run_id'] for row in recent.json()}
            assert orphan.parent.name not in {row['run_id'] for row in recent.json()}
        finally:
            orphan.unlink()
        replayed=client.post(route,json=body,headers={'Idempotency-Key':uuid.uuid4().hex})
        assert replayed.status_code==409 and replayed.json()['detail']=='POLICY_REQUEST_NONCE_REPLAY'
        assert client.post('/api/session',json={'subject':'grid_operator_B','password':access['grid_operator_B']}).status_code==200
        assert client.get('/api/runs/'+identifier).status_code==403
        assert identifier not in {row['run_id'] for row in client.get('/api/expansion/runs').json()}

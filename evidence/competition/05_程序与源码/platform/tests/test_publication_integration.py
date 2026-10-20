"""Real PFDAM, signed releases, protected egress and operational participation."""
import copy
import hashlib
import json
import uuid
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from services.encoding import Rejected,canonical,digest
from services.initialization import ROOT,RUNTIME
from services.storage import read,write
from services.publication import prepare,candidates,verify_statement
from services.expansion_schemas import ExpansionRequest
from services.expansion_orchestrator import execute
from services.evidence import export_public,verify_export
from tests.provenance import record_run


def real(*,function='SUM',period=68,fault='normal'):
    policy,_,_=prepare(ExpansionRequest(nodes=300,periods=[period],scene_id='park',source_count=3,function=function,request_nonce=uuid.uuid4().hex),'grid_operator_A')
    value=execute(policy,lab=True,fault=fault)
    return value,policy


@pytest.fixture(scope='module')
def examples():
    return {'sum':real(),'count':real(function='COUNT'),'withheld':real(period=67,fault='missing')}


def test_real_publication_and_withheld_egress(examples,monkeypatch):
    from services import api
    from services.sessions import ACCESS_PATH
    monkeypatch.setenv('GRID_LAB','1');monkeypatch.setattr(api,'LAB',True)
    for label,(result,_) in examples.items():
        record_run(result['run_id'])
        assert result['oracle_match'] and result['role_file_isolation']
        assert result['status']==('WITHHELD' if label=='withheld' else 'COMPLETED')
        verified=verify_export(export_public(result['run_id']),expected_context={'run_id':result['run_id']})
        assert verified['release_decision_verified'] and verified['expected_context_checked']
    hidden=examples['withheld'][0]
    private=read(RUNTIME/'runs'/hidden['run_id']/'utility/computed.json')
    hidden_value=private['results'][0]['value_W']
    def no_hidden_scalars(value):
        if isinstance(value,dict):
            return not ({'value_W','published_value','registered_metering_points'}&set(value)) and all(no_hidden_scalars(v) for v in value.values())
        if isinstance(value,list):return all(no_hidden_scalars(v) for v in value)
        return value not in (hidden_value,str(hidden_value),digest(hidden_value),digest(private['results'][0]))
    with TestClient(api.app) as client:
        credentials=read(ACCESS_PATH)['accounts']
        assert client.post('/api/session',json={'subject':'grid_operator_A','password':credentials['grid_operator_A']}).status_code==200
        for suffix in ('','/events','/evidence','/expansion'):
            response=client.get('/api/runs/'+hidden['run_id']+suffix)
            assert response.status_code==200
            assert no_hidden_scalars(response.json()),'withheld data reached a normal JSON output'
        streamed=client.get('/api/runs/'+hidden['run_id']+'/stream')
        assert streamed.status_code==200
        assert all(no_hidden_scalars(json.loads(line[6:])) for line in streamed.text.splitlines() if line.startswith('data: '))
        response=client.get('/api/runs/'+hidden['run_id']+'/export')
        assert response.status_code==200
        with zipfile.ZipFile(export_public(hidden['run_id'])) as archive:
            assert 'receipts.json' not in archive.namelist() and 'snapshots.json' not in archive.namelist()
            assert all(no_hidden_scalars(json.loads(archive.read(name))) for name in archive.namelist())
        assert client.post('/api/expansion/collaborations',json={'private_control':True},headers={'Idempotency-Key':uuid.uuid4().hex}).status_code==422
        assert client.post('/api/runs',json={'region':'A','resources':['residential']},headers={'Idempotency-Key':uuid.uuid4().hex}).status_code==409
        assert client.post('/lab/expansion/curve',json=ExpansionRequest(nodes=300,request_nonce=uuid.uuid4().hex).model_dump()).status_code==403
        assert client.get('/lab/runs/'+hidden['run_id']+'/source-preview').status_code==409
        assert client.post('/api/session',json={'subject':'grid_operator_B','password':credentials['grid_operator_B']}).status_code==200
        assert client.get('/api/runs/'+hidden['run_id']).status_code==403
    count=examples['count'][0]
    assert count['results'][0]['publication_id']==examples['sum'][0]['results'][0]['publication_id']
    with zipfile.ZipFile(export_public(count['run_id'])) as archive:
        assert all(b'"value_W"' not in archive.read(name) for name in archive.namelist())


def test_operational_participation_rejects_same_meter_twice(examples):
    result,policy=examples['sum'];private=RUNTIME/'runs'/result['run_id']/'utility'
    computed,plan,participation=read(private/'computed.json'),read(private/'release-plan.json'),read(private/'participation.json')
    slot=policy['selected_slots'][0]['slot_id']
    accepted=set(computed['accepted_manifests'][slot])
    altered=copy.deepcopy(participation)
    for claim in altered.values():
        ids=[identifier for identifier in claim['slots'][slot] if identifier in accepted]
        if len(ids)>=2:
            claim['slots'][slot][ids[1]]=claim['slots'][slot][ids[0]]
            break
    with pytest.raises(Rejected,match='PARTICIPATION_DUPLICATE_CONTRIBUTOR'):
        candidates(policy,computed,altered,plan)
    stale=copy.deepcopy(participation)
    next(iter(stale.values()))['run_id']=uuid.uuid4().hex
    with pytest.raises(Rejected,match='PARTICIPATION_SOURCE_CONTEXT_INVALID'):
        candidates(policy,computed,stale,plan)
    public_policy,_,_=prepare(ExpansionRequest(nodes=300,periods=[68],scene_id='park',source_count=1,
                    function='SUM',asset_id='public-load-demo',request_nonce=uuid.uuid4().hex),'grid_analyst_A')
    public_plan=read(RUNTIME/'utility/release-plans'/(public_policy['release_plan_id']+'.json'))
    assert public_policy['release_domain']==policy['release_domain']
    assert public_plan['cells']==plan['cells']
    assert set(public_plan['owners'])==set(plan['owners'])
    assert set(public_plan['owners'].values())=={'source-1'} and len(set(plan['owners'].values()))==3


def test_public_input_bindings_do_not_offer_a_plaintext_dictionary(examples):
    from services.publication import input_binding
    from services.expansion_governance import prepare as legacy_prepare
    legacy_policy,_,legacy_parts=legacy_prepare(ExpansionRequest(nodes=300,source_count=3,periods=[68],scene_id='park',request_nonce=uuid.uuid4().hex),'grid_operator_A')
    legacy_body={key:value for key,value in legacy_parts[0].items() if key!='partition_digest'}
    legacy_value=legacy_body['nodes'][0]['values_W'][0]
    legacy_matches=[]
    for value in (legacy_value-1,legacy_value,legacy_value+1):
        candidate=copy.deepcopy(legacy_body);candidate['nodes'][0]['values_W'][0]=value
        if digest(candidate)==legacy_policy['sources'][0]['partition_digest']:legacy_matches.append(value)
    assert legacy_matches==[legacy_value]
    result,policy=examples['sum']
    part=read(RUNTIME/'runs'/result['run_id']/'source-1/dataset.json')
    body={key:value for key,value in part.items() if key!='partition_digest'}
    actual=body['nodes'][0]['values_W'][0]
    candidate_values=[actual-1,actual,actual+1]
    raw_hash=digest(body)
    recovered=[];public_matches=[]
    for value in candidate_values:
        candidate=copy.deepcopy(body);candidate['nodes'][0]['values_W'][0]=value
        if digest(candidate)==raw_hash:recovered.append(value)
        if digest(candidate)==policy['sources'][0]['partition_digest']:public_matches.append(value)
    assert recovered==[actual] and public_matches==[]
    assert input_binding('source-1','source-partition',body)==part['partition_digest']==policy['sources'][0]['partition_digest']
    assert input_binding('gateway','source-partition',body)!=part['partition_digest']
    assert input_binding('source-1','wrong-domain',body)!=part['partition_digest']
    changed=copy.deepcopy(body);changed['nodes'][0]['values_W'][0]+=1
    assert input_binding('source-1','source-partition',changed)!=part['partition_digest']
    assert policy['input_binding_scheme']=='ROLE_HMAC_SHA384_V1'


def test_other_runtime_records_are_not_visible_in_business_api(examples,monkeypatch):
    from services import api
    from services.sessions import ACCESS_PATH
    monkeypatch.setenv('GRID_LAB','1');monkeypatch.setattr(api,'LAB',True)
    fake=copy.deepcopy(examples['sum'][0]);fake['run_id']=uuid.uuid4().hex;fake['runtime_instance']='0'*96
    write(ROOT/'artifacts/runs'/fake['run_id']/'run_manifest.json',fake)
    with TestClient(api.app) as client:
        access=read(ACCESS_PATH)['accounts']
        assert client.post('/api/session',json={'subject':'grid_operator_A','password':access['grid_operator_A']}).status_code==200
        for suffix in ('','/expansion','/evaluation','/evidence','/events','/export'):
            assert client.get('/api/runs/'+fake['run_id']+suffix).status_code==403
        assert fake['run_id'] not in {row['run_id'] for row in client.get('/api/expansion/runs').json()}
    (ROOT/'artifacts/runs'/fake['run_id']/'run_manifest.json').unlink()


def test_release_signatures_conjunctive_and_archive_semantics(examples,tmp_path):
    result,policy=examples['sum'];directory=ROOT/'artifacts/runs'/result['run_id']
    signed,content=read(directory/'release_statement.json'),read(directory/'release.json')
    for index in range(len(signed['signatures'])):
        broken=copy.deepcopy(signed);broken['signatures'].pop(index)
        with pytest.raises(Rejected):verify_statement(broken,content)
    from services.publication import statement
    wrong_kind,_=statement('GRID_UC_RESULT_V2',content,policy,{key:result[key] for key in ('run_id','task_id','param_id')},
                           content['publication_id'],content['publication_sequence'],content['decision'])
    with zipfile.ZipFile(export_public(result['run_id'])) as archive:
        original={name:archive.read(name) for name in archive.namelist()}
    for field in ('node_count','dataset_digest','requester_id','provenance','object_type','rules'):
        entries=dict(original);run=json.loads(entries['run_manifest.json'])
        if field=='object_type':
            entries['release_statement.json']=canonical(wrong_kind)
        elif field=='rules':
            changed_rules=json.loads(entries['publication_rules.json']);changed_rules['minimum_contributors']=1
            entries['publication_rules.json']=canonical(changed_rules)
        elif field=='provenance':
            provenance=json.loads(entries['data_provenance.json']);provenance['dataset_digest']='0'*96
            entries['data_provenance.json']=canonical(provenance)
        else:
            run[field]=1 if field=='node_count' else '0'*96 if field=='dataset_digest' else 'grid_operator_B'
            entries['run_manifest.json']=canonical(run)
        manifest=json.loads(entries['export_manifest.json'])
        manifest['files']={name:hashlib.sha256(raw).hexdigest() for name,raw in entries.items() if name!='export_manifest.json'}
        entries['export_manifest.json']=canonical(manifest)
        target=tmp_path/(field+'.zip')
        with zipfile.ZipFile(target,'w') as archive:
            for name,raw in entries.items():archive.writestr(name,raw)
        with pytest.raises(Rejected):verify_export(target)


def test_restart_recovers_only_a_root_committed_public_view():
    from services.publication_runtime import recover
    result,_=real(period=66)
    assert result['status']=='COMPLETED'
    result['status']='RUNNING';result['results']=[]
    restored=recover(result)
    assert restored['status']=='COMPLETED' and restored['results']
    record_run(result['run_id'])
    fake=copy.deepcopy(result);fake['run_id']=uuid.uuid4().hex;fake['status']='RUNNING';fake['results']=[]
    write(RUNTIME/'runs'/fake['run_id']/'utility/published.json',{'results':[{'value_W':42424242}]},True)
    restored=recover(fake)
    assert restored['status']=='CANCELLED' and restored['results']==[]


def test_four_day_real_evaluation_is_publicly_recomputable(monkeypatch):
    from services.response import execute as evaluate,EvaluationRequest,verify_evaluation
    from services import response
    from tests.provenance import observe
    original_collect=response.collect_child_evidence
    readiness=[]
    def collect_after_projection(manifest,directory):
        persisted=read(directory/'run_manifest.json')
        assert persisted['status']=='RUNNING' and persisted['results']==[]
        original_collect(manifest,directory)
        assert len(read(directory/'connection_evidence.json'))==32
        readiness.append(True)
    monkeypatch.setattr(response,'collect_child_evidence',collect_after_projection)
    result=evaluate(EvaluationRequest(nodes=300,source_count=3,request_nonce=uuid.uuid4().hex),'grid_operator_A',lab=True)
    assert result['status']=='COMPLETED' and len(result['children'])==4
    assert readiness==[True]
    observe('response_terminal_manifest_after_evidence',{'pending_before_collection':True,'links_ready_before_completion':32})
    directory=ROOT/'artifacts/runs'/result['run_id']
    content,envelope,inputs=[read(directory/f'{name}.json') for name in ('evaluation','evaluation_statement','evaluation_inputs')]
    policy=read(directory/'governance.json')
    check=verify_evaluation(content,envelope,inputs,expected={'run_id':result['run_id']},parent_policy=policy)
    assert check['business_metrics_recomputed'] and len(check['child_receipt_checks'])==16
    for corruption in ('date','cohort','missing','formula','unit','parent'):
        altered=copy.deepcopy(inputs);body=copy.deepcopy(content);parent=copy.deepcopy(policy)
        if corruption=='date':altered[0],altered[1]=altered[1],altered[0]
        elif corruption=='cohort':altered[0]['policy']['node_count']=120
        elif corruption=='missing':altered.pop()
        elif corruption=='formula':body['metrics']['formula_version']='WRONG_FORMULA'
        elif corruption=='unit':altered[0]['results'][0]['unit']='kWh'
        else:parent['response_basis_points']=2000
        with pytest.raises((Rejected,ValueError)):
            verify_evaluation(body,envelope,altered,parent_policy=parent)
    from fractions import Fraction
    from services.expansion_data import select
    totals=[]
    for day in [1,2,3,4]:
        data=select('SYN-WEEK-V42',300,day,[68,69,70,71])
        selected=[node for node in data['nodes'] if node['region']=='A']
        totals.append([sum((node['values_W'][period]*9000//10000 if day==4 else node['values_W'][period]) for node in selected) for period in range(4)])
    changes=[Fraction(totals[0][i]+totals[1][i]+totals[2][i],3)-totals[3][i] for i in range(4)]
    actual=content['metrics']['energy_difference_kWh']
    if Fraction(actual['numerator'])/int(actual['denominator']) != sum(changes)/4000:
        raise AssertionError('independent energy calculation mismatch')
    verified=verify_export(export_public(result['run_id']),expected_context={'run_id':result['run_id']})
    assert verified['business_metrics_recomputed'] and verified['release_decision_verified']
    record_run(result['run_id'])

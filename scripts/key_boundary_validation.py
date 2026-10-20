"""Real in-flight task/management ordering and fresh-process trust verification."""
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT_PATH=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT_PATH))
runtime=Path(tempfile.mkdtemp(prefix='grid-key-boundary-',dir=str(Path.home())))
os.environ['GRID_RUNTIME']=str(runtime)
os.environ['GRID_CUSTODY_PASSPHRASE']=secrets.token_urlsafe(32)
from services import management, trust
from services.encoding import Rejected
from services.evidence import export_public, verify_export
from services.expansion_governance import prepare
from services.expansion_orchestrator import execute
from services.expansion_schemas import ExpansionRequest
from services.initialization import ROOT, RUNTIME
from services.native import LIB, utc
from services.sessions import ACCESS_PATH, initialize_access
from services.storage import read, write
from services.versioning import source_version


def main():
    started, frozen=utc(),source_version()
    policy,_,_=prepare(ExpansionRequest(source_count=2,scene_id='park',function='SUM',periods=[68,69,70,71],request_nonce=uuid.uuid4().hex),'grid_operator_A')
    initialize_access()
    accounts=read(ACCESS_PATH)['accounts']
    requested=management.request('rotate-signing','','Actual in-flight boundary validation','grid_key_manager',accounts['grid_key_manager'])
    management.approve(requested['request_id'],'grid_security_approver',accounts['grid_security_approver'])
    run_id=uuid.uuid4().hex
    manifest_path=ROOT/'artifacts/runs'/run_id/'run_manifest.json'
    with ThreadPoolExecutor(max_workers=2) as pool:
        task=pool.submit(execute,policy,run_id=run_id)
        until=time.monotonic()+45
        while time.monotonic()<until:
            if (RUNTIME/'runs'/run_id/'gateway/ready.json').exists(): break
            if task.done(): raise AssertionError('Task finished before the in-flight observation')
            time.sleep(.025)
        else: raise AssertionError('Real gateway readiness timed out')
        assert read(manifest_path)['status']=='RUNNING'
        rotating=pool.submit(management.execute,requested['request_id'],'grid_key_manager',accounts['grid_key_manager'])
        time.sleep(.15)
        assert not rotating.done() and read(manifest_path)['status']=='RUNNING'
        assert trust.current_binding(RUNTIME)['key_epoch']==1
        assert management._requests()[requested['request_id']]['state']=='APPROVED'
        original=task.result(timeout=90)
        rotation=rotating.result(timeout=90)
    assert original['status']=='COMPLETED' and original['oracle_match'] and original['uc_result_signatures_verified']
    assert rotation['state']=='COMPLETED' and trust.current_binding(RUNTIME)['key_epoch']==2
    original_receipts=read(ROOT/'artifacts/runs'/run_id/'receipts.json')
    assert all(item['payload']['key_epoch']==1 for item in original_receipts)
    checked=verify_export(export_public(run_id),expected_context={'run_id':run_id})
    assert checked['receipt_authenticity_verified'] and checked['uc_result_origin_and_integrity_verified']
    try:
        execute(policy)
    except Rejected as exc:
        stale_code=exc.code
        assert stale_code=='TRUST_REGISTRY_CHANGED',stale_code
    else: raise AssertionError('Stale queued policy accepted after rotation')
    current,_,_=prepare(ExpansionRequest(source_count=2,scene_id='park',function='SUM',periods=[68],request_nonce=uuid.uuid4().hex),'grid_operator_A')
    new=execute(current)
    assert new['status']=='COMPLETED' and new['oracle_match'] and new['uc_result_signatures_verified']
    assert read(ROOT/'artifacts/runs'/new['run_id']/'receipts.json')[0]['payload']['key_epoch']==2
    command=[sys.executable,'-c',
        'from services import trust,management; from services.initialization import RUNTIME; import json; print(json.dumps({"epoch":trust.current_binding(RUNTIME)["key_epoch"],"program":bool(management.verify_program()),"audit":management.verify_audit()["integrity_verified"]}))']
    fresh=json.loads(subprocess.run(command,cwd=ROOT,env=os.environ.copy(),capture_output=True,text=True,check=True,timeout=20).stdout)
    assert fresh=={'epoch':2,'program':True,'audit':True}
    assert source_version()==frozen
    record={'schema':'GRID_REAL_TASK_KEY_BOUNDARY_VALIDATION_V1','started_at':started,'finished_at':utc(),**frozen,
            'command':[sys.executable,'scripts/key_boundary_validation.py'],'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'versions':json.loads(LIB.grid_library_info()),'inputs':{'dataset':'SYN-WEEK-V42','nodes':120,'sources':2,'old_task_periods':[68,69,70,71],'function':'SUM'},
            'old_run_id':run_id,'new_run_id':new['run_id'],'management_waited_for_real_task':True,'old_task_completed_with_epoch':1,
            'new_task_epoch':2,'stale_prepared_policy_rejected':stale_code,'fresh_process_verification':fresh,
            'private_runtime':str(runtime),'exit_code':0,'scope':'Same-host real job and two authenticated management identities; task-boundary activation, not immediate cancellation or human duty certification'}
    destination=ROOT/'artifacts/iterations/standards/key-boundary'/(started.replace(':','-')+'.json')
    write(destination,record)
    print(json.dumps({'record':str(destination.relative_to(ROOT)),'old_epoch':1,'new_epoch':2,'exit_code':0}))

if __name__=='__main__':main()

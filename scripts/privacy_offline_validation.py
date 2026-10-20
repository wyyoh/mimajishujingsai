"""Same-host fresh source/venv/key validation in a network namespace."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def inside():
    from services.orchestrator import initialize
    from services.initialization import RUNTIME
    from services.publication import prepare
    from services.expansion_schemas import ExpansionRequest
    from services.expansion_orchestrator import execute
    from services.response import execute as evaluate,EvaluationRequest
    from services.evidence import export_public,verify_export
    from services.storage import read,write
    from services.versioning import source_version
    from services.native import LIB
    assert not subprocess.check_output(['ip','route'],text=True).strip()
    initialize()
    policy,_,_=prepare(ExpansionRequest(dataset_id='UCI370-WEEK-20130603-V1',nodes=300,source_count=3,
                        function='COUNT',periods=[67],scene_id='park',request_nonce=uuid.uuid4().hex),'grid_operator_A')
    run=execute(policy,lab=True)
    assert run['status']=='COMPLETED' and run['oracle_match'] and run['role_file_isolation']
    check=verify_export(export_public(run['run_id']),expected_context={'run_id':run['run_id']})
    assert check['release_decision_verified'] and check['receipt_authenticity_verified']
    parent=evaluate(EvaluationRequest(dataset_id='UCI370-WEEK-20130603-V1',nodes=300,source_count=3,request_nonce=uuid.uuid4().hex),'grid_operator_A',lab=True)
    assert parent['status']=='COMPLETED' and parent['role_file_isolation']
    check=verify_export(export_public(parent['run_id']),expected_context={'run_id':parent['run_id']})
    assert check['release_decision_verified'] and check['business_metrics_recomputed']
    assert all(read(ROOT/'artifacts/runs'/child['run_id']/'run_manifest.json')['oracle_match'] for child in parent['children'])
    evaluation=read(ROOT/'artifacts/runs'/parent['run_id']/'evaluation.json')
    assert evaluation['mode']=='HISTORICAL_COMPARISON' and evaluation['simulation_basis_points']==0
    connections=read(ROOT/'artifacts/runs'/parent['run_id']/'connection_evidence.json')
    assert len(connections)==32 and all(row['actual_group']=='X25519MLKEM768' and row.get('application_cipher')=='SM4-GCM' for row in connections)
    result={'schema':'GRID_V5_FRESH_OFFLINE_RESULT_V1','run_id':parent['run_id'],'count_run_id':run['run_id'],
            'param_id':parent['param_id'],'protocol_version':5,'source_count':3,'data_source':parent['data_source'],
            'network_disabled':True,'fresh_runtime':True,'fresh_virtual_environment':True,'oracle_match':True,
            'role_file_isolation':True,'public_receipt_links_verified':True,'business_metrics_recomputed':True,
            'versions':json.loads(LIB.grid_library_info()),'scope':'New source copy, venv, keys and parameters in a same-host network namespace. Native libraries and public data pre-staged. Not a second physical host.',**source_version()}
    write(ROOT/'publication_offline_result.json',result)
    print(json.dumps({'v5_response':parent['run_id'],'status':'PASS'}),flush=True)


def main():
    if '--inside' in sys.argv:return inside()
    from services.versioning import source_version
    from services.storage import write
    from services.native import utc
    frozen=source_version();started=utc()
    base=Path(tempfile.mkdtemp(prefix='grid-privacy-offline-',dir=str(Path.home())));source=base/'source';source.mkdir()
    runtime=base/'private-runtime';runtime.mkdir()
    output=ROOT/'artifacts/iterations/privacy/offline'/started.replace(':','-');output.mkdir(parents=True)
    current=ROOT/'artifacts/iterations/privacy/current';current.mkdir(parents=True,exist_ok=True)
    for directory in ('services','native','tests','scripts','contracts','shared'):
        shutil.copytree(ROOT/directory,source/directory,ignore=shutil.ignore_patterns('__pycache__','.writing-*'))
    for name in ('requirements.txt','requirements.lock.txt','pytest.ini'):shutil.copy2(ROOT/name,source/name)
    (source/'.build').mkdir();shutil.copy2(ROOT/'.build/libgridcrypto.so',source/'.build/libgridcrypto.so')
    shutil.copytree(ROOT/'.build/wheelhouse',source/'.build/wheelhouse')
    shutil.copytree(ROOT/'third_party/mcl/lib',source/'third_party/mcl/lib')
    shutil.copytree(ROOT/'references/datasets/uci321',source/'references/datasets/uci321')
    data_runtime=Path(os.environ.get('GRID_DATA_RUNTIME',str(Path.home()/'.local/share/grid-collaboration'/hashlib.sha256(str(ROOT).encode()).hexdigest()[:12])))
    shutil.copytree(data_runtime/'datasets/uci321',runtime/'datasets/uci321',ignore=shutil.ignore_patterns('original.zip','*.part'))
    subprocess.run([sys.executable,'-m','venv',str(source/'.venv')],check=True)
    installation=[str(source/'.venv/bin/python'),'-m','pip','--isolated','install','--no-index','--find-links',str(source/'.build/wheelhouse'),'-r',str(source/'requirements.lock.txt')]
    namespace=['unshare','--user','--map-root-user','--net','bash','-c',
               'ip link set lo up && "$@"','privacy-install',*installation]
    with (output/'offline-install.log').open('wb') as log:
        subprocess.run(namespace,cwd=source,stdout=log,stderr=subprocess.STDOUT,check=True)
    commands=[['scripts/offline_run.py'],['scripts/v41_offline_run.py'],['scripts/v42_offline_run.py'],['scripts/privacy_offline_validation.py','--inside']]
    environment={**os.environ,'GRID_RUNTIME':str(runtime),'GRID_CUSTODY_PASSPHRASE':secrets.token_urlsafe(32),'PYTHONPATH':str(source)}
    with (output/'offline-run.log').open('wb') as log:
        for command in commands:
            invocation=['unshare','--user','--map-root-user','--net','bash','-c','ip link set lo up && "$@"','privacy-run',str(source/'.venv/bin/python'),*command]
            process=subprocess.run(invocation,cwd=source,env=environment,stdout=log,stderr=subprocess.STDOUT)
            if process.returncode:raise RuntimeError('Offline validation failed; inspect preserved log')
    names={'legacy-offline.json':'offline_result.json','v41-offline.json':'v41_offline_result.json',
           'v4-offline.json':'v42_offline_result.json','publication-offline.json':'publication_offline_result.json'}
    for target,filename in names.items():
        record=json.loads((source/filename).read_text())
        assert record['core_source_digest']==frozen['core_source_digest']
        record.update(exit_code=0,install_command=installation,commands=commands,reproduction_directory=str(base),started_at=started,finished_at=utc())
        write(output/target,record);shutil.copy2(output/target,current/target)
    shutil.copytree(source/'artifacts/runs',ROOT/'artifacts/runs',dirs_exist_ok=True)
    for filename in ('offline-install.log','offline-run.log'):shutil.copy2(output/filename,current/filename)
    assert source_version()==frozen
    write(output/'validation.json',{'status':'PASS','exit_code':0,**frozen,'records':names,'source':str(source),'runtime':str(runtime),
          'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'command':[sys.executable,*sys.argv],
          'scope':'Same-host fresh environment; original records copied without re-signing or relabeling their core version'})
    print(json.dumps({'record':str((output/'validation.json').relative_to(ROOT)),'status':'PASS'}))


if __name__=='__main__':main()

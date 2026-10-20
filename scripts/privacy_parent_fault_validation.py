"""Real missing reports in one required date; never an ordinary API switch."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    os.environ['GRID_RUNTIME']=tempfile.mkdtemp(prefix='grid-private-parent-fault-',dir=str(Path.home()))
    os.environ.pop('GRID_CUSTODY_PASSPHRASE',None)
    from services.orchestrator import initialize
    from services.initialization import RUNTIME
    from services.storage import read,write
    from services.native import utc
    from services.versioning import source_version
    from services import expansion_orchestrator
    from services.response import execute,EvaluationRequest
    from services.evidence import export_public,verify_export
    from services.custody import load_root
    initialize();frozen=source_version();original=expansion_orchestrator._execute;calls=[]
    output=ROOT/'artifacts/iterations/privacy/negative'/utc().replace(':','-')
    write(output/'plan.json',{'command':[sys.executable,*sys.argv],**frozen,'registered_at':utc(),
          'fault':'REAL_MISSING_REPORTS_EVENT_CHILD_ONLY','input_nodes':300,'source_count':3,'lab_only':True})
    def injected(policy,**kwargs):
        calls.append(policy['period_indices'])
        assert kwargs['lab'] and kwargs['defer_publication'] and kwargs['fault']=='normal'
        if len(calls)==4:kwargs['fault']='missing'
        return original(policy,**kwargs)
    expansion_orchestrator._execute=injected
    result=execute(EvaluationRequest(nodes=300,source_count=3,request_nonce=uuid.uuid4().hex),'grid_operator_A',lab=True)
    assert result['status']=='WITHHELD' and not result['results'] and len(result['children'])==4
    anchor=load_root(RUNTIME)['publication_state']
    assert not anchor['views'] and not anchor['inputs'] and not anchor['cells'] and len(anchor['commits'])==1
    checked=verify_export(export_public(result['run_id']),expected_context={'run_id':result['run_id']})
    assert checked['release_decision_verified'] and checked['release_decision']=='WITHHELD'
    for child in result['children']:
        assert read(ROOT/'artifacts/runs'/child['run_id']/'run_manifest.json')['oracle_match']
    assert not any((ROOT/'artifacts/runs'/result['run_id']/name).exists() for name in ('evaluation.json','evaluation_inputs.json','receipts.json'))
    assert source_version()==frozen
    report={'status':'PASS',**frozen,'finished_at':utc(),'command':[sys.executable,*sys.argv],
            'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'run_id':result['run_id'],
            'independent_children_verified':4,'entire_evaluation_withheld':True,'partial_reference_release_count':0,
            'scope':'One event child has real 20% omissions in all four periods, other three dates complete. Whole 16-window batch withheld with no staged numeric publication history.'}
    write(output/'result.json',report)
    print(json.dumps({'record':str((output/'result.json').relative_to(ROOT)),'status':'PASS'}))


if __name__=='__main__':main()

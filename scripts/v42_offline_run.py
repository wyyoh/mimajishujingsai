"""Fresh offline V3 run over pre-staged observed data and independent Source identities."""
import json
import sys
import uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.expansion_governance import prepare
from services.expansion_schemas import ExpansionRequest
from services.expansion_orchestrator import execute
from services.evidence import export_public, verify_export
from services.initialization import ROOT
from services.storage import read, write
from services.versioning import source_version

policy,_,_=prepare(ExpansionRequest(dataset_id='UCI370-WEEK-20130603-V1',source_count=3,scene_id='park',function='AVG',periods=[68,69],request_nonce=uuid.uuid4().hex), 'grid_operator_A')
run=execute(policy)
assert run['status']=='COMPLETED' and run.get('oracle_match') is True and run['role_file_isolation']
verified=verify_export(export_public(run['run_id']),expected_context={'run_id':run['run_id'],'dataset_digest':run['dataset_digest'],'logical_source_process_count':3})
assert len(verified['v41_checks'])==2 and all(item['source_bindings_verified'] for item in verified['v41_checks'])
assert run['protocol_version']==4 and verified['uc_result_origin_and_integrity_verified']
connections=read(ROOT/'artifacts/runs'/run['run_id']/'connection_evidence.json')
assert len(connections)==8 and all(item['actual_group']=='X25519MLKEM768' and item.get('application_cipher')=='SM4-GCM' for item in connections)
routes=Path('/proc/net/route').read_text().splitlines()
assert len(routes)==1
record={'schema':'GRID_V43_FRESH_OFFLINE_RESULT','run_id':run['run_id'],'param_id':run['param_id'],'protocol_version':4,
        'oracle_match':True,'public_receipt_links_verified':True,'uc_result_signature_verified':True,'role_file_isolation':True,'source_count':3,
        'data_source':run['data_source'],'dataset_digest':run['dataset_digest'],'routes':routes,'network_disabled':True,
        'fresh_runtime':True,'fresh_virtual_environment':True,**source_version(),
        'scope':'Same-host network namespace, fresh venv/keys/trust/PFDAM parameters; pre-staged normalized observed week and attribution, no network download in the namespace; not a second physical host'}
write(ROOT/'v42_offline_result.json',record)
print(json.dumps(record))

import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.orchestrator import execute
from services.initialization import ROOT
from services.storage import write

rows=[]
for scenario in ("normal","modified_report","missing","invalid_authorization","invalid_receipt","incompatible_tls"):
    result=execute(nodes=120,slots=4,profile="SAB",scenario=scenario)
    should_reject=scenario in ("invalid_authorization","invalid_receipt","incompatible_tls")
    passed=(result['status']=='REJECTED' and not result['results']) if should_reject else result.get('oracle_match') is True
    rows.append({'scenario':scenario,'run_id':result['run_id'],'nodes':120,'slots':4,
                 'status':result['status'],'oracle_match':result.get('oracle_match'),
                 'passed':passed,'core_source_digest':result['core_source_digest']})
    write(ROOT/'artifacts/tests/scenario_catalog.json',rows)
    print(f"{scenario} {result['run_id']} {result['status']} passed={passed}",flush=True)
assert all(x['passed'] for x in rows)

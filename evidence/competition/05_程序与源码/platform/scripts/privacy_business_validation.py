"""Private known-intervention controls and pre-registered availability models."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid
from fractions import Fraction

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    os.environ['GRID_RUNTIME']=tempfile.mkdtemp(prefix='grid-private-business-',dir=str(Path.home()))
    os.environ.pop('GRID_CUSTODY_PASSPHRASE',None)
    from services.initialization import RUNTIME
    from services.orchestrator import initialize
    from services.expansion_governance import initialize_sources
    from services.expansion_data import select
    from services.response import execute,EvaluationRequest
    from services.publication import check_candidates
    from services.storage import read,write
    from services.native import utc,LIB
    from services.encoding import digest
    from services.versioning import source_version
    from tests.test_publication import item,solve
    initialize();initialize_sources()
    frozen=source_version()
    directory=ROOT/'artifacts/iterations/privacy/business'/utc().replace(':','-')
    directory.mkdir(parents=True)
    plan={'schema':'GRID_PRIVATE_BUSINESS_PLAN_V1','registered_at':utc(),**frozen,
          'command':[sys.executable,*sys.argv],'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'versions':json.loads(LIB.grid_library_info()),'runtime':str(RUNTIME),'input_nodes':300,'source_count':3,
          'reference_days':[1,2,3],'event_day':4,'periods':[68,69,70,71],'response_basis_points':[0,1000,2000],
          'placebo':{'event_day':3,'reference_days':[0,1,2],'response_basis_points':0,'mode':'PRIVATE_REFERENCE_ONLY'},
          'baseline_methods':['THREE_PRIOR_DAYS_MEAN','NEAREST_PRIOR_DAY'],
          'availability_sizes':[4,5,9,10,11,19,20,21],'availability_thresholds':[5,10,20],
          'availability_states':['complete','one_missing'],'public_numeric_business_outputs':False}
    write(directory/'plan.json',plan)
    original=[]
    for day in range(5):
        data=select('SYN-WEEK-V42',300,day,plan['periods'])
        original.append([[node['values_W'][period] for node in data['nodes'] if node['region']=='A'] for period in range(4)])
    sums=[[sum(values) for values in periods] for periods in original]
    private_rows=[];public_rows=[]
    for rate in plan['response_basis_points']:
        if source_version()!=frozen:raise RuntimeError('Source changed')
        run=execute(EvaluationRequest(nodes=300,source_count=3,request_nonce=uuid.uuid4().hex),'grid_operator_A',
                    lab=True,private_control=True,private_measurement=True,simulation_bps=rate)
        assert run['status']=='EXPERIMENT_ONLY' and not run['results']
        package=read(RUNTIME/'runs'/run['run_id']/'utility/release-ready.json')
        treated=[sum(value*(10000-rate)//10000 for value in values) for values in original[4]]
        for day,child in enumerate(package['evaluation_inputs'],1):
            expected=treated if day==4 else sums[day]
            assert [row['value_W'] for row in child['results']]==expected
        truth=[sums[4][i]-treated[i] for i in range(4)]
        estimates={
            'THREE_PRIOR_DAYS_MEAN':[Fraction(sums[1][i]+sums[2][i]+sums[3][i],3)-treated[i] for i in range(4)],
            'NEAREST_PRIOR_DAY':[Fraction(sums[3][i]-treated[i]) for i in range(4)]}
        errors={name:[abs(value-truth[i]) for i,value in enumerate(values)] for name,values in estimates.items()}
        def rational(value):return {'numerator':str(value.numerator),'denominator':str(value.denominator)}
        private_rows.append({'basis_points':rate,'run_id':run['run_id'],'untreated_W':sums[4],'treated_W':treated,'truth_W':truth,
              'errors':{name:{'mean_absolute_error_W':rational(sum(values)/4),'maximum_absolute_error_W':rational(max(values))} for name,values in errors.items()},
              'business_metrics':package['evaluation']['metrics']})
        public_rows.append({'basis_points':rate,'run_id':run['run_id'],'independent_integer_sums_match':True,
                            'private_numeric_outputs_only':True,'all_children_oracle_match':all(read(ROOT/'artifacts/runs'/child['run_id']/'run_manifest.json')['oracle_match'] for child in run['children'])})
        print(json.dumps({'basis_points':rate,'validated':True}),flush=True)
    placebo=[Fraction(sums[0][i]+sums[1][i]+sums[2][i],3)-sums[3][i] for i in range(4)]
    private=RUNTIME/'utility/experiments'/(directory.name+'.json')
    write(private,{'controls':private_rows,'placebo_differences_W':[str(value) for value in placebo]},True)
    availability=[]
    for threshold in plan['availability_thresholds']:
        rows=[]
        for size in plan['availability_sizes']:
            points=list(map(str,range(size)))
            for status in plan['availability_states']:
                candidate=item({'fixed':points},actual=points if status=='complete' else points[:-1])
                outcome,reason=check_candidates({},[candidate],minimum=threshold)
                expected=size>=threshold and status=='complete'
                assert (outcome is not None)==expected
                rows.append({'registered':size,'state':status,'publishable':outcome is not None,'reason':reason,'false_reject':expected and outcome is None})
        availability.append({'minimum':threshold,'requests':len(rows),'publishable':sum(row['publishable'] for row in rows),
                             'policy_withheld':sum(not row['publishable'] for row in rows),'false_reject':sum(row['false_reject'] for row in rows),'rows':rows})
    h=[[1]]
    for _ in range(6):h=[row+row for row in h]+[row+[-v for v in row] for row in h]
    matrix=[[1]*64]+[[(value+1)//2 for value in row] for row in h[1:]]
    sets=[{i for i,v in enumerate(row) if v} for row in matrix]
    secrets=list(range(100,164));answers=[sum(secrets[i] for i in group) for group in sets]
    reconstructed=solve(matrix,answers)==list(map(Fraction,secrets))
    assert reconstructed and all(len(a)>=10 and all(not a-b or len(a-b)>=10 for b in sets) for a in sets)
    fixed={f'cell-{j}':[str(i) for i in range(j*16,(j+1)*16)] for j in range(4)}
    state=check_candidates({},[item(fixed,total=sum(secrets))])[0][0];blocked=0
    for group,total in zip(sets,answers,strict=True):
        subset={name:[m for m in members if int(m) in group] for name,members in fixed.items()}
        proposed={name:members for name,members in subset.items() if members}
        outcome,_=check_candidates(state,[item(proposed,total=total)])
        if outcome is None:blocked+=1
    expected_cuts=sum(any(0<len(group & {int(member) for member in cell})<len(cell) for cell in fixed.values()) for group in sets)
    assert blocked==expected_cuts and blocked>0
    report={'schema':'GRID_PRIVATE_BUSINESS_VALIDATION_V1','status':'PASS','finished_at':utc(),**frozen,
            'controls':public_rows,'availability':availability,
            'risk_models':{'queries':64,'minimum_only_reconstruction':reconstructed,'minimum_plus_pairwise_reconstruction':reconstructed,'fixed_partition_cuts_withheld':blocked},
            'baseline_errors_evaluated_privately':True,'placebo_executed_privately':True,
            'private_record_ciphertext_sha256':hashlib.sha256(private.read_bytes()).hexdigest(),'private_record_path':str(private),
            'scope':'Synthetic known intervention only; exact estimates and method errors kept UC-private. No field-response causality or method superiority claim.',
            'plan_sha256':hashlib.sha256((directory/'plan.json').read_bytes()).hexdigest()}
    # The exact rational is retained privately; this flag demonstrates the expected
    # baseline bias without exposing an experimental numeric result.
    report['zero_injection_estimate_nonzero']=private_rows[0]['business_metrics']['mean_reduction_kW']['numerator']!='0'
    assert all(row['all_children_oracle_match'] for row in public_rows) and source_version()==frozen
    write(directory/'result.json',report)
    print(json.dumps({'record':str((directory/'result.json').relative_to(ROOT))}),flush=True)


if __name__=='__main__':main()

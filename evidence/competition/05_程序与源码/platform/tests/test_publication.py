"""Release boundaries and composition counterexamples, independent of GW sets."""
import copy
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction
import secrets
import uuid
import pytest
from services.encoding import digest, Rejected
from services.publication import check_candidates,transact

INTERVAL='2026-10-13T17:00:00Z/2026-10-13T17:15:00Z'


def item(groups,*,actual=None,total=None,function='SUM',domain='test-private-domain'):
    members=sorted(point for group in groups.values() for point in group)
    return {'domain':domain,'interval':INTERVAL,'cells':{name:{'members':list(points),'inputs':{INTERVAL:digest(list(points))}} for name,points in groups.items()},
            'members':members if actual is None else actual,'sum_W':len(members)*100 if total is None else total,
            'count':len(members) if actual is None else len(actual),'function':function}


@pytest.mark.parametrize('size,allowed',[(9,False),(10,True),(11,True)])
def test_minimum_independent_contributors_and_zero(size,allowed):
    value=item({'cell':list(map(str,range(size)))},total=0)
    outcome,reason=check_candidates({},[value])
    assert (outcome is not None)==allowed
    if allowed:
        assert next(iter(outcome[0]['views'].values()))['numeric']=={'sum_W':0,'count':size}
    else:
        assert reason=='MINIMUM_COHORT'


def test_union_queries_use_whole_disjoint_cells():
    groups={'residential':[f'a-{i}' for i in range(10)],'commercial':[f'b-{i}' for i in range(10)]}
    outcome,_=check_candidates({},[item(groups)])
    state=outcome[0]
    allowed,_=check_candidates(state,[item({'residential':groups['residential']})])
    assert allowed is not None
    split={'new-cell':groups['residential'][:5]+groups['commercial'][:5]}
    rejected,reason=check_candidates(state,[item(split)])
    assert rejected is None and reason=='CELL_PARTITION_CHANGED'
    assert len(state['views'])==1


def test_incomplete_and_duplicate_members_never_pass_as_complete():
    points=[f'a-{i}' for i in range(12)]
    for observed in (points[:-1],points+[points[-1]]):
        result,reason=check_candidates({},[item({'cell':points},actual=observed)])
        assert result is None and reason=='INCOMPLETE_REGISTERED_COHORT'


def test_cross_task_function_identity_and_revision_cannot_reset_history():
    value=item({'cell':list(map(str,range(10)))})
    state=check_candidates({},[value])[0][0]
    for function in ('SUM','AVG','COUNT'):
        changed=copy.deepcopy(value);changed['function']=function
        result,reason=check_candidates(state,[changed])
        assert reason is None and result[1][0]['reused']
        assert result[1][0]['publication_id']==next(iter(state['views'].values()))['publication_id']
    revised=copy.deepcopy(value);revised['cells']['cell']['inputs'][INTERVAL]=digest('late-revision')
    assert check_candidates(state,[revised])[1]=='PUBLISHED_INPUT_REVISION'
    changed=copy.deepcopy(value);changed['sum_W']+=1
    assert check_candidates(state,[changed])[1]=='PUBLISHED_VALUE_CHANGED'
    altered=copy.deepcopy(value);altered['cells']['cell']['members'][-1]='another-point'
    assert check_candidates(state,[altered])[1]=='REGISTERED_MEMBERS_CHANGED'


def solve(matrix,values):
    rows=[[Fraction(v) for v in row]+[Fraction(value)] for row,value in zip(matrix,values,strict=True)]
    for column in range(len(matrix)):
        pivot=next(i for i in range(column,len(rows)) if rows[i][column])
        rows[column],rows[pivot]=rows[pivot],rows[column]
        scale=rows[column][column]
        rows[column]=[v/scale for v in rows[column]]
        for index in range(len(rows)):
            if index!=column and rows[index][column]:
                factor=rows[index][column]
                rows[index]=[a-factor*b for a,b in zip(rows[index],rows[column],strict=True)]
    return [row[-1] for row in rows]


def test_pairwise_threshold_is_insufficient_but_fixed_cells_block_reconstruction():
    # Hypothetical query model, not a claim that normal API accepts arbitrary sets.
    h=[[1]]
    for _ in range(6):
        h=[row+row for row in h]+[row+[-v for v in row] for row in h]
    matrix=[[1]*64]+[[(value+1)//2 for value in row] for row in h[1:]]
    sets=[{i for i,value in enumerate(row) if value} for row in matrix]
    assert all(len(group)>=10 for group in sets)
    assert all(len(a-b)==0 or len(a-b)>=10 for a in sets for b in sets)
    secret_values=list(range(100,164))
    observed=[sum(secret_values[i] for i in group) for group in sets]
    assert solve(matrix,observed)==list(map(Fraction,secret_values))
    groups={f'fixed-{j}':[str(i) for i in range(j*16,(j+1)*16)] for j in range(4)}
    state=check_candidates({},[item(groups,total=sum(secret_values))])[0][0]
    rejections=0
    for group,number in zip(sets,observed,strict=True):
        proposed={name:[member for member in members if int(member) in group] for name,members in groups.items()}
        proposed={name:members for name,members in proposed.items() if members}
        result,_=check_candidates(state,[item(proposed,total=number)])
        if result is None:
            rejections+=1
        else:
            state=result[0]
    assert rejections>0


def test_root_anchored_transaction_concurrency_and_staging(tmp_path,monkeypatch):
    from services.custody import enable,load_root
    from services.storage import read,write
    runtime=tmp_path/uuid.uuid4().hex
    monkeypatch.setenv('GRID_CUSTODY_PASSPHRASE',secrets.token_urlsafe(32))
    enable(runtime)
    value=item({'cell':list(map(str,range(10)))})
    def run(total):
        candidate=copy.deepcopy(value);candidate['sum_W']=total
        identifier=uuid.uuid4().hex
        result=transact(runtime,[candidate],identifier,lambda decision,approvals,sequence:{'decision':decision,'sequence':sequence,'results':[total] if decision=='PUBLISHED' else []})
        return identifier,result
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(run,[1000,1100]))
    assert sorted(row['decision'] for _,row in results)==['PUBLISHED','WITHHELD']
    state=load_root(runtime)['publication_state']
    assert state['sequence']==2 and len(state['views'])==1
    identifier,package=results[0]
    assert transact(runtime,[value],identifier,lambda *args:pytest.fail('must reuse staged commit'))==package
    path=runtime/'runs'/identifier/'utility/release-ready.json'
    write(path,{'modified':True},True,runtime=runtime)
    with pytest.raises(Rejected,match='PUBLICATION_STAGED_CONTENT_CHANGED'):
        transact(runtime,[value],identifier,lambda *args:None)


def test_no_commit_if_builder_fails(tmp_path,monkeypatch):
    from services.custody import enable,load_root
    monkeypatch.setenv('GRID_CUSTODY_PASSPHRASE',secrets.token_urlsafe(32))
    runtime=tmp_path/uuid.uuid4().hex;enable(runtime)
    def fail(*args):
        raise RuntimeError('interrupted before commit')
    with pytest.raises(RuntimeError):
        transact(runtime,[item({'cell':list(map(str,range(10)))})],uuid.uuid4().hex,fail)
    assert not load_root(runtime).get('publication_state')


def test_cross_process_publication_lock_and_private_control(tmp_path,monkeypatch):
    import multiprocessing
    from services.custody import enable,load_root
    monkeypatch.setenv('GRID_CUSTODY_PASSPHRASE',secrets.token_urlsafe(32))
    runtime=tmp_path/uuid.uuid4().hex;enable(runtime)
    context=multiprocessing.get_context('fork');queue=context.Queue()
    value=item({'cell':list(map(str,range(10)))})
    def publish(number):
        candidate=copy.deepcopy(value);candidate['sum_W']=number
        answer=transact(runtime,[candidate],uuid.uuid4().hex,lambda decision,approvals,sequence:{'decision':decision})
        queue.put(answer['decision'])
    workers=[context.Process(target=publish,args=(total,)) for total in (1000,1100)]
    for process in workers:process.start()
    decisions=[queue.get(timeout=30) for _ in workers]
    for process in workers:process.join(30);assert process.exitcode==0
    assert sorted(decisions)==['PUBLISHED','WITHHELD']
    before=load_root(runtime)
    control=transact(runtime,[value],uuid.uuid4().hex,lambda decision,approvals,sequence:{'decision':decision},private_control=True)
    assert control['decision']=='EXPERIMENT_NOT_RELEASED' and before==load_root(runtime)


def test_late_fill_before_commit_and_runtime_backup_does_not_reset_root(tmp_path,monkeypatch):
    from services.custody import enable,load_root,root_path
    import shutil
    monkeypatch.setenv('GRID_CUSTODY_PASSPHRASE',secrets.token_urlsafe(32))
    runtime=tmp_path/uuid.uuid4().hex;enable(runtime)
    points=list(map(str,range(10)))
    builder=lambda decision,approvals,sequence:{'decision':decision}
    assert transact(runtime,[item({'cell':points},actual=points[:-1])],uuid.uuid4().hex,builder)['decision']=='WITHHELD'
    backup=tmp_path/'old-runtime-backup';shutil.copytree(runtime,backup)
    assert not root_path(runtime).resolve().is_relative_to(runtime.resolve())
    assert transact(runtime,[item({'cell':points})],uuid.uuid4().hex,builder)['decision']=='PUBLISHED'
    anchored=load_root(runtime)['publication_state']
    shutil.copytree(backup,runtime,dirs_exist_ok=True)
    assert load_root(runtime)['publication_state']==anchored
    changed=item({'cell':points},total=9999)
    assert transact(runtime,[changed],uuid.uuid4().hex,builder)['decision']=='WITHHELD'


def test_business_units_negative_delta_and_zero_reference():
    from services.response import metrics
    def inputs(values):
        return [{'results':[{'value_W':v,'registered_metering_points':10,'selected_slot':{'slot_start':str(i)}} for i,v in enumerate(row)]} for row in values]
    normal=metrics(inputs([[1000]*4,[2000]*4,[3000]*4,[1500]*4]))
    assert normal['mean_reduction_kW']=={'numerator':'1','denominator':'2'}
    assert normal['relative_change_percent']=={'numerator':'25','denominator':'1'}
    assert normal['energy_difference_kWh']=={'numerator':'1','denominator':'2'}
    growing=metrics(inputs([[1000]*4]*3+[[2000]*4]))
    assert growing['mean_reduction_kW']['numerator']=='-1'
    assert metrics(inputs([[0]*4]*4))['relative_change_percent'] is None


def test_private_controls_and_availability_record():
    import hashlib
    from services.initialization import ROOT
    from services.storage import read
    from services.versioning import source_version
    record=read(ROOT/'artifacts/iterations/privacy/current/business.json')
    assert record['status']=='PASS' and record['core_source_digest']==source_version()['core_source_digest']
    assert [row['basis_points'] for row in record['controls']]==[0,1000,2000]
    assert all(row['independent_integer_sums_match'] and row['private_numeric_outputs_only'] and row['all_children_oracle_match'] for row in record['controls'])
    assert record['baseline_errors_evaluated_privately'] and record['placebo_executed_privately'] and record['zero_injection_estimate_nonzero']
    assert [row['minimum'] for row in record['availability']]==[5,10,20]
    for row in record['availability']:
        assert row['requests']==16 and row['false_reject']==0 and row['publishable']+row['policy_withheld']==16
    assert record['risk_models']['queries']==64 and record['risk_models']['fixed_partition_cuts_withheld']==60
    private=Path(record['private_record_path'])
    assert hashlib.sha256(private.read_bytes()).hexdigest()==record['private_record_ciphertext_sha256']


def test_original_signed_archive_history_record():
    from services.initialization import ROOT
    from services.storage import read
    from services.versioning import source_version
    import hashlib
    record=read(ROOT/'artifacts/iterations/privacy/current/history.json')
    assert record['exit_code']==0 and record['core_source_digest']==source_version()['core_source_digest']
    assert {row['protocol_version'] for row in record['archives']}=={1,2,3,4}
    for row in record['archives']:
        assert row['receipt_authenticity_verified'] and row['uc_result_statement_present']==(row['protocol_version']==4)
        assert hashlib.sha256((ROOT/row['path']).read_bytes()).hexdigest()==row['sha256']

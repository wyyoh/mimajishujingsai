"""Four-date encrypted demand-response evaluation with exact public arithmetic."""
import fcntl
import time
import uuid
from fractions import Fraction
from typing import Literal
from .encoding import Rejected, canonical, digest
from .initialization import ROOT, RUNTIME
from .storage import read, write
from .native import utc
from .expansion_schemas import ExpansionRequest
from .publication import prepare, candidates, transact, statement, view, verify_statement, rules


class EvaluationRequest(ExpansionRequest):
    scene_id: Literal['park'] = 'park'
    function: Literal['SUM'] = 'SUM'
    day: Literal[4] = 4


def rational(value):
    value = Fraction(value)
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


def metrics(inputs):
    if len(inputs)!=4 or any(len(item['results'])!=4 for item in inputs):
        raise Rejected('EVALUATION_INPUT_WINDOW_COUNT_INVALID')
    curves, baseline, differences = [], [], []
    counts = {row['registered_metering_points'] for item in inputs for row in item['results']}
    if len(counts)!=1:
        raise Rejected('EVALUATION_COHORT_COUNT_CHANGED')
    for index in range(4):
        values = [item['results'][index]['value_W'] for item in inputs]
        base = Fraction(sum(values[:3]),3)
        delta = base-values[3]
        baseline.append(base); differences.append(delta)
        curves.append({'slot':inputs[-1]['results'][index]['selected_slot'],'baseline_W':rational(base),
                       'event_W':values[3],'difference_W':rational(delta)})
    denominator = sum(baseline)
    return {'formula_version':'THREE_PRIOR_DAYS_V1','mean_reduction_kW':rational(sum(differences)/4000),
            'relative_change_percent':rational(sum(differences)*100/denominator) if denominator else None,
            'energy_difference_kWh':rational(sum(differences)*Fraction(900,3600000)),
            'coverage_basis_points':10000,'registered_metering_points':next(iter(counts)), 'curve':curves,
            'interpretation':'Window-relative change; no market settlement or causal response certification'}


def execute(request, subject, *, run_id=None, lab=False, policy=None, private_control=False, private_measurement=False, simulation_bps=None):
    from .orchestrator import initialize
    from .versioning import source_version
    from .expansion_orchestrator import _execute
    initialize()
    body = request.model_dump() if hasattr(request,'model_dump') else dict(request)
    body = EvaluationRequest(**body).model_dump()
    if (private_control or private_measurement) and not lab:
        raise Rejected('PRIVATE_EXPERIMENT_REQUIRES_LAB')
    if body['periods']!=rules()['event_periods']:
        raise Rejected('EVALUATION_FIXED_EVENT_PERIODS_REQUIRED')
    identifier = run_id or uuid.uuid4().hex
    response_bps = (rules()['demo_response_basis_points'] if body['dataset_id']=='SYN-WEEK-V42' else 0) if simulation_bps is None else simulation_bps
    policy = policy or prepare(EvaluationRequest(**body),subject,parent=identifier,response=response_bps)[0]
    if policy['parent_evaluation'] != identifier:
        raise Rejected('EVALUATION_PARENT_CONTEXT_MISMATCH')
    directory, private = ROOT/'artifacts/runs'/identifier, RUNTIME/'runs'/identifier/'utility'
    directory.mkdir(parents=True,exist_ok=True)
    context = {'run_id':identifier,'task_id':uuid.uuid4().hex,'param_id':read(RUNTIME/'public/parameters.json')['param_id']}
    manifest = {'run_id':identifier,'task_id':context['task_id'],'param_id':context['param_id'],'protocol_version':5,
        'requester_id':subject,'evaluation_id':identifier,'parent_evaluation':'none','execution_mode':'REAL','security_profile':'SAB',
        'algorithm_suite':policy['algorithm_suite'],'policy_digest':digest(policy),'release_rules_digest':policy['release_rules_digest'],
        'dataset_id':policy['dataset_version'],'dataset_digest':policy['dataset_digest'],'data_source':policy['data_source'],
        'scene_id':'park','scenario':'normal','asset_id':policy['asset_id'],'data_level':policy['data_level'],
        'node_count':policy['node_count'],'logical_source_process_count':len(policy['sources']),'slot_count':4,
        'runtime_instance':policy['runtime_instance'],'input_binding_scheme':policy['input_binding_scheme'],'private_experiment':private_control or private_measurement,
        'total_computed_intervals':16,'function':'SUM','status':'RUNNING','publication_status':'WAITING_FOR_EVALUATION',
        'started_at':utc(),'results':[],'lab':lab,'children':[],**source_version()}
    write(directory/'run_manifest.json',manifest)
    write(directory/'governance.json',policy)
    write(directory/'publication_rules.json',rules())
    write(private/'task-context.json',context,True)
    started = time.perf_counter_ns()
    coordinator_cpu_started=time.process_time_ns()
    phases={'child_preparation_ns':0,'child_execution_ns':0,'publication_transaction_ns':0,
            'publication_builder_ns':0,'evaluation_verification_ns':0,'public_install_ns':0,'queue_ns':0}
    prepared = []
    try:
        with (RUNTIME/'execution.lock').open('a+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            for day in [*rules()['reference_days'],rules()['event_day']]:
                if (directory/'cancel.request').exists():
                    raise Rejected('CANCELLED_BY_USER')
                child_request = {**body,'day':day,'request_nonce':uuid.uuid4().hex}
                phase_start=time.perf_counter_ns()
                child_policy = prepare(ExpansionRequest(**child_request),subject,parent=identifier,response=response_bps if day==4 else 0)[0]
                phases['child_preparation_ns']+=time.perf_counter_ns()-phase_start
                child_id = uuid.uuid4().hex
                phase_start=time.perf_counter_ns()
                child = _execute(child_policy,run_id=child_id,lab=lab,fault='normal',defer_publication=True)
                phases['child_execution_ns']+=time.perf_counter_ns()-phase_start
                manifest['children'].append({'run_id':child_id,'day':day,'status':child['status']})
                write(directory/'run_manifest.json',manifest)
                if child['status']!='COMPUTED':
                    if child['status']=='CANCELLED' or (directory/'cancel.request').exists():
                        raise Rejected('CANCELLED_BY_USER')
                    raise Rejected('EVALUATION_CHILD_NOT_READY')
                job = RUNTIME/'runs'/child_id/'utility'
                computed, plan, participation = read(job/'computed.json'),read(job/'release-plan.json'),read(job/'participation.json')
                vals = candidates(child_policy,computed,participation,plan)
                prepared.append({'policy':child_policy,'context':read(job/'task-context.json'),'computed':computed,'values':vals})
            if (directory/'cancel.request').exists():
                raise Rejected('CANCELLED_BY_USER')
            all_values = [item for child in prepared for item in child['values']]
            # The exact same private contributor roster is mandatory in all 16 intervals.
            if len({digest(sorted(member for cell in value['cells'].values() for member in cell['members'])) for value in all_values})!=1:
                raise Rejected('EVALUATION_REGISTERED_COHORT_CHANGED')
            def build(decision, approvals, sequence):
                builder_started=time.perf_counter_ns()
                pub_id = approvals[0]['publication_id'] if approvals else uuid.uuid4().hex
                inputs, results, result_statements, timings = [], [], [], []
                evaluation, evaluation_statement = None, None
                if decision!='WITHHELD':
                    offset = 0
                    for child in prepared:
                        values = child['values']; child_results = [] ; child_statements = []
                        for value,approval in zip(values,approvals[offset:offset+len(values)],strict=True):
                            result = view(value,approval)
                            signed,cost = statement('GRID_UC_RESULT_V2',result,child['policy'],child['context'],result['publication_id'],sequence,decision)
                            child_results.append(result); child_statements.append(signed); timings.extend(cost)
                        offset += len(values)
                        inputs.append({'policy':child['policy'],'context':child['context'],'results':child_results,
                                       'result_statements':child_statements,'receipts':child['computed']['receipts']})
                    results = inputs[-1]['results']
                    for result in results:
                        signed,cost = statement('GRID_UC_RESULT_V2',result,policy,context,result['publication_id'],sequence,decision)
                        result_statements.append(signed); timings.extend(cost)
                    evaluation = {'evaluation_id':identifier,'mode':'CONTROLLED_SIMULATION' if response_bps else 'HISTORICAL_COMPARISON',
                        'simulation_basis_points':response_bps,'baseline_days':rules()['reference_days'],'event_day':4,
                        'data_source':policy['data_source'],'metrics':metrics(inputs),
                        'input_statement_digests':[digest(row) for item in inputs for row in item['result_statements']]}
                    evaluation_statement,cost = statement('GRID_RESPONSE_EVALUATION_V1',evaluation,policy,context,pub_id,sequence,decision)
                    timings.extend(cost)
                release = {'run_id':identifier,'decision':decision,'results':results,'rules_digest':policy['release_rules_digest'],
                    'policy_digest':digest(policy),'publication_id':pub_id,'publication_sequence':sequence,
                    'reason':'RELEASED' if decision=='PUBLISHED' else 'PRIVATE_EXPERIMENT' if decision=='EXPERIMENT_NOT_RELEASED' else 'RELEASE_CONDITIONS_NOT_MET'}
                signed,cost = statement('GRID_RELEASE_DECISION_V1',release,policy,context,pub_id,sequence,decision)
                timings.extend(cost)
                package={'release':release,'release_statement':signed,'results':results,'result_statements':result_statements,
                        'private_measurement':private_control or private_measurement,
                        'evaluation':evaluation,'evaluation_statement':evaluation_statement,'evaluation_inputs':inputs,'signing_timings':timings}
                phases['publication_builder_ns']+=time.perf_counter_ns()-builder_started
                return package
            phase_start=time.perf_counter_ns()
            package = transact(RUNTIME,all_values,identifier,build,private_control=private_control)
            phases['publication_transaction_ns']=time.perf_counter_ns()-phase_start
            from .publication_runtime import install_package
            phase_start=time.perf_counter_ns()
            if package['evaluation'] is not None:
                verify_evaluation(package['evaluation'],package['evaluation_statement'],package['evaluation_inputs'],
                                  expected={'run_id':identifier,'policy_digest':digest(policy)},parent_policy=policy)
            phases['evaluation_verification_ns']=time.perf_counter_ns()-phase_start
            phase_start=time.perf_counter_ns()
            if package['release']['decision']=='PUBLISHED' and not private_measurement:
                for name in ('evaluation','evaluation_statement','evaluation_inputs'):
                    write(directory/f'{name}.json',package[name])
            install_package(manifest,{},package)
            phases['public_install_ns']=time.perf_counter_ns()-phase_start
            write(private/'measurement.json',{'signing_timings':package['signing_timings'],
                  'child_runs':[child['context']['run_id'] for child in prepared],'phases':phases},True)
    except Exception as exc:
        write(private/'evaluation-error.json',{'code':getattr(exc,'code','EVALUATION_FAILED'),'message':str(exc)},True)
        manifest.update(status='CANCELLED' if getattr(exc,'code',None)=='CANCELLED_BY_USER' else 'REJECTED',results=[],
                        publication_status='NOT_PUBLISHED',errors=[{'code':getattr(exc,'code','EVALUATION_FAILED')}])
    collect_child_evidence(manifest,directory)
    manifest.update(finished_at=utc(),elapsed_ns=time.perf_counter_ns()-started,
                    coordinator_cpu_ns=time.process_time_ns()-coordinator_cpu_started,phase_timings=phases)
    write(directory/'run_manifest.json',manifest)
    return manifest


def collect_child_evidence(manifest,directory):
    """Expose measured links/isolation, never a deferred child's computed values."""
    combined={name:[] for name in ('connection_evidence','performance_raw','events')}
    isolation={};resources=[];isolation_children=0
    for child in manifest['children']:
        child_dir=ROOT/'artifacts/runs'/child['run_id']
        for name,rows in combined.items():
            path=child_dir/f'{name}.json'
            if path.is_file():rows.extend({**row,'child_run_id':child['run_id'],'evaluation_day':child['day']} for row in read(path))
        path=child_dir/'role_isolation.json'
        if path.is_file():
            isolation_children+=1
            for role,record in read(path).items():
                merged=isolation.setdefault(role,{'checks':[],'mechanism':record['mechanism'],'abi':record['abi']})
                merged['checks'].extend({**check,'child_run_id':child['run_id']} for check in record['checks'])
        path=child_dir/'resource_evidence.json'
        if path.is_file():resources.append({'child_run_id':child['run_id'],**read(path)})
    for name,rows in combined.items():write(directory/f'{name}.json',rows)
    write(directory/'role_isolation.json',isolation)
    write(directory/'resource_evidence.json',{'children':resources,'cpu_role_total_ns':sum(row['cpu_role_total_ns'] for row in resources),
          'peak_sampled_role_rss_KiB':max([row['peak_sampled_role_rss_KiB'] for row in resources],default=0),
          'scope':'Four serial child jobs, one physical host; maximum of sampled child role RSS sums'})
    manifest['role_file_isolation']=isolation_children==4 and len(isolation)==manifest['logical_source_process_count']+2 and all(all(check['read_denied'] for check in role['checks']) for role in isolation.values())


def verify_evaluation(content,envelope,inputs,*,runtime=RUNTIME,expected=None,parent_policy=None):
    if envelope['payload']['object_type']!='GRID_RESPONSE_EVALUATION_V1':
        raise Rejected('PUBLICATION_OBJECT_TYPE_INVALID')
    evaluation_check = verify_statement(envelope,content,runtime=runtime,expected=expected)
    if content['evaluation_id']!=envelope['payload']['run_id'] or content.get('mode') not in ('CONTROLLED_SIMULATION','HISTORICAL_COMPARISON'):
        raise Rejected('EVALUATION_PARENT_CONTEXT_INVALID')
    if parent_policy is not None and (envelope['payload']['policy_digest']!=digest(parent_policy)
            or parent_policy['parent_evaluation']!=content['evaluation_id']
            or content['simulation_basis_points']!=parent_policy['response_basis_points']
            or content['data_source']!=parent_policy['data_source']):
        raise Rejected('EVALUATION_PARENT_POLICY_INVALID')
    if len(inputs)!=4 or content['metrics']!=metrics(inputs):
        raise Rejected('EVALUATION_METRIC_RECOMPUTATION_FAILED')
    if content['baseline_days']!=[1,2,3] or content['event_day']!=4:
        raise Rejected('EVALUATION_REFERENCE_DAYS_INVALID')
    digests, receipts = [], []
    domains = set(); cell_rules = set(); registries = set(); populations = set()
    from .signatures import verify_object
    from .publication_schemas import PublicationPolicy
    from .signatures import validate,time_value
    for day_index,item in enumerate(inputs):
        policy,context = validate(PublicationPolicy,item['policy']),item['context']
        if len(item['results'])!=4 or len(item['receipts'])!=4 or len(item['result_statements'])!=4:
            raise Rejected('EVALUATION_CHILD_WINDOW_COUNT_INVALID')
        if (policy['parent_evaluation']!=content['evaluation_id'] or policy['function']!='SUM'
                or context['run_id']!=item['result_statements'][0]['payload']['run_id']):
            raise Rejected('EVALUATION_CHILD_CONTEXT_INVALID')
        if parent_policy is not None and (any(policy[key]!=parent_policy[key] for key in
                ('requester_id','asset_id','data_level','security_profile','algorithm_suite','key_epoch','trust_registry_digest',
                 'runtime_instance','input_binding_scheme','release_domain','release_rules_digest','region','resources','node_count','dataset_version'))
                or len(policy['sources'])!=len(parent_policy['sources'])
                or context['param_id']!=envelope['payload']['param_id']
                or policy['response_basis_points']!=(parent_policy['response_basis_points'] if day_index==3 else 0)):
            raise Rejected('EVALUATION_CHILD_PARENT_BINDING_INVALID')
        if policy['period_indices']!=[([1,2,3,4][day_index])*96+period for period in [68,69,70,71]]:
            raise Rejected('EVALUATION_REFERENCE_PERIODS_INVALID')
        domains.add(policy['release_domain']); cell_rules.add(policy['release_rules_digest']); registries.add(policy['trust_registry_digest'])
        populations.add((policy['node_count'],policy['region'],tuple(policy['resources'])))
        for index,(result,signed,receipt) in enumerate(zip(item['results'],item['result_statements'],item['receipts'],strict=True)):
            child_expected={'run_id':context['run_id'],'task_id':context['task_id'],'param_id':context['param_id'],
                            'policy_digest':digest(policy),'algorithm_suite':policy['algorithm_suite'],'key_epoch':policy['key_epoch'],
                            'trust_registry_digest':policy['trust_registry_digest'],'release_rules_digest':policy['release_rules_digest'],
                            'decision':envelope['payload']['decision'],'object_type':'GRID_UC_RESULT_V2','schema_version':2,
                            'publication_sequence':envelope['payload']['publication_sequence'],'publication_id':result['publication_id']}
            checked=verify_statement(signed,result,runtime=runtime,expected=child_expected)
            payload,check = verify_object(receipt,'GRID_AGG_RECEIPT_V5','SAB',runtime,usage='history')
            if (digest(payload)!=result['receipt_digest'] or payload['policy_digest']!=digest(policy)
                    or canonical(result['selected_slot'])!=canonical(policy['selected_slots'][index])
                    or payload['slot_id']!=result['slot_id'] or result['coverage_basis_points']!=10000
                    or any(payload[key]!=context[key] for key in ('run_id','task_id','param_id'))
                    or any(payload[key]!=policy[key] for key in ('release_rules_digest','release_plan_id','key_epoch','algorithm_suite','trust_registry_digest'))
                    or type(result['value_W']) is not int or result['unit']!='W'
                    or result['registered_metering_points']!=payload['counts']['accepted']
                    or not time_value(policy['issued_at'])<=time_value(signed['payload']['issued_at'])<time_value(policy['expires_at'])):
                raise Rejected('EVALUATION_RECEIPT_PERIOD_BINDING_INVALID')
            check['uc_result_current_trust_verified']=checked['current_signer_trust_verified']
            digests.append(digest(signed)); receipts.append(check)
    if len(domains)!=1 or len(cell_rules)!=1 or len(registries)!=1 or len(populations)!=1 or digests!=content['input_statement_digests']:
        raise Rejected('EVALUATION_INPUT_SET_INVALID')
    return {'evaluation_statement_verified':True,'business_metrics_recomputed':True,'child_receipt_checks':receipts,
            'scope':'Recomputation from UC-signed inputs; not public decryption or causal field verification'}

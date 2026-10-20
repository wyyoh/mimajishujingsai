"""UC release authority on the trusted coordinator, never on the gateway.

Exact, fixed-cell publication is deliberately not differential privacy. Private
Source participation records and private ledger state never enter exports.
"""
import copy
import hashlib
import hmac
import uuid
from pathlib import Path

from .encoding import Rejected, canonical, digest
from .initialization import ROOT, RUNTIME
from .storage import read, write
from .custody import role_key, root_transaction
from .native import utc


def rules():
    value = read(ROOT / 'contracts/privacy_release.json')
    if value['minimum_contributors'] < 10 or value['completeness'] != 'ALL_REGISTERED' or value['input_binding_scheme']!='ROLE_HMAC_SHA384_V1':
        raise Rejected('RELEASE_RULES_INVALID')
    return value


def opaque(runtime, *parts):
    return hmac.new(role_key(runtime, 'utility'), canonical(list(parts)), hashlib.sha256).hexdigest()


def input_binding(role, purpose, value, *, runtime=RUNTIME):
    """Role-separated keyed binding; never publish a plaintext dictionary oracle."""
    key=hmac.new(role_key(runtime,role),b'GRID-V5-INPUT-BINDING-KEY-V1',hashlib.sha384).digest()
    return hmac.new(key,canonical(['GRID-V5-INPUT-BINDING-V1',purpose,value]),hashlib.sha384).hexdigest()


def protected_partitions(dataset,count,*,runtime=RUNTIME):
    from .expansion_governance import partitions
    parts=partitions(dataset,count)
    for part in parts:
        part['partition_digest']=input_binding(part['source_id'],'source-partition',
                                {key:value for key,value in part.items() if key!='partition_digest'},runtime=runtime)
    return parts


def selected_data(policy,*,runtime=RUNTIME):
    from .expansion_data import select
    indices = policy['period_indices']
    data = select(policy['dataset_version'], policy['node_count'], indices[0] // 96, [i % 96 for i in indices])
    response = policy.get('response_basis_points', 0)
    if response:
        if data['source'] != 'SYNTHETIC':
            raise Rejected('OBSERVED_DATA_RESPONSE_INJECTION_FORBIDDEN')
        for node in data['nodes']:
            if node['region'] == policy['region'] and node['resource_class'] in policy['resources']:
                node['values_W'] = [v * (10000-response) // 10000 for v in node['values_W']]
        data['response_simulation'] = {'basis_points': response, 'rounding': 'FLOOR_INTEGER_W', 'scope': 'CONTROLLED_SIMULATION'}
        data['dataset_digest'] = digest({k: v for k, v in data.items() if k != 'dataset_digest'})
    data['parent_dataset_digest']=input_binding('utility','parent-data',data['parent_dataset_digest'],runtime=runtime)
    data['dataset_digest']=input_binding('utility','selected-data',{key:value for key,value in data.items() if key!='dataset_digest'},runtime=runtime)
    return data


def prepare(request, subject, *, parent='none', response=0, runtime=RUNTIME):
    from .expansion_governance import prepare as base
    from .signatures import validate
    from .publication_schemas import PublicationPolicy
    from .governance import SUBJECTS
    policy, _, _ = base(request, subject)
    if policy['function'] == 'AVG' and not {'SUM', 'COUNT'} <= set(SUBJECTS[subject]['functions']):
        raise Rejected('EXACT_AVERAGE_COMPONENT_GRANT_REQUIRED')
    policy.update(policy_version='V5_RELEASE_POLICY_1', release_rules_digest=digest(rules()),
                  release_domain=digest({'family': policy['dataset_version'], 'metric': 'average_active_power_W'}),
                  release_plan_id=uuid.uuid4().hex, response_basis_points=response, parent_evaluation=parent,input_binding_scheme='ROLE_HMAC_SHA384_V1')
    from .custody import trust_pin
    policy['runtime_instance']=trust_pin(runtime)['registry_pin']
    data = selected_data(policy,runtime=runtime)
    policy['dataset_digest'] = data['dataset_digest']
    policy['parent_dataset_digest']=data['parent_dataset_digest']
    parts = protected_partitions(data, len(policy['sources']),runtime=runtime)
    for binding, part in zip(policy['sources'], parts, strict=True):
        binding['partition_digest'] = part['partition_digest']
    policy = validate(PublicationPolicy, policy)
    plan = make_plan(policy, data, parts, runtime)
    write(Path(runtime) / 'utility/release-plans' / (policy['release_plan_id']+'.json'), plan, True, runtime=runtime)
    return policy, data, parts


def make_plan(policy, data, parts, runtime):
    owners, cells, rosters = {}, {}, {}
    domain = policy['release_domain']
    for part in parts:
        roster = {}
        for node in part['nodes']:
            token = opaque(runtime, 'registered-meter-v1', domain, node['node_id'])
            if token in owners:
                raise Rejected('REGISTERED_CONTRIBUTOR_DUPLICATE')
            owners[token] = part['source_id']
            roster[node['node_id']] = token
            if node['region'] != policy['region'] or node['resource_class'] not in policy['resources']:
                continue
            cell_id = opaque(runtime, 'fixed-cell-v1', domain, node['region'], node['resource_class'])
            cell = cells.setdefault(cell_id, {'members': [], 'inputs': {}})
            cell['members'].append(token)
            for index, slot in enumerate(data['slots']):
                key = slot['slot_start']+'/'+slot['slot_end']
                cell['inputs'].setdefault(key, []).append([token, node['values_W'][index]])
        rosters[part['source_id']] = roster
    for cell in cells.values():
        cell['members'].sort()
        cell['inputs'] = {key: digest(sorted(values)) for key, values in cell['inputs'].items()}
    return {'plan_id': policy['release_plan_id'], 'domain': domain, 'rules_digest': policy['release_rules_digest'],
            'dataset_digest': policy['dataset_digest'], 'owners': owners, 'rosters': rosters, 'cells': cells}


def candidates(policy, computed, participation, plan):
    """Use operational Source records, never tests.oracle or its mapping files."""
    if (plan['plan_id'] != policy['release_plan_id'] or plan['domain'] != policy['release_domain']
            or plan['dataset_digest'] != policy['dataset_digest'] or plan['rules_digest'] != digest(rules())):
        raise Rejected('RELEASE_PRIVATE_PLAN_MISMATCH')
    expected = {member for cell in plan['cells'].values() for member in cell['members']}
    output = []
    for result in computed['results']:
        slot_id = result['slot_id']
        selected_slot = next(slot for slot in policy['selected_slots'] if slot['slot_id'] == slot_id)
        record_map = {}
        for source in policy['sources']:
            claim = participation[source['source_id']]
            if (claim['source_id'] != source['source_id'] or claim['run_id'] != computed['run_id']
                    or claim['plan_id'] != plan['plan_id'] or claim['partition_digest'] != source['partition_digest']):
                raise Rejected('PARTICIPATION_SOURCE_CONTEXT_INVALID')
            for record_id, contributor in claim['slots'].get(slot_id, {}).items():
                if plan['owners'].get(contributor) != source['source_id'] or record_id in record_map:
                    raise Rejected('PARTICIPATION_MAPPING_INVALID')
                record_map[record_id] = contributor
        accepted = computed['accepted_manifests'][slot_id]
        if any(rid not in record_map for rid in accepted):
            raise Rejected('PARTICIPATION_MAPPING_INCOMPLETE')
        distinct = [record_map[rid] for rid in accepted]
        if len(distinct) != len(set(distinct)):
            raise Rejected('PARTICIPATION_DUPLICATE_CONTRIBUTOR')
        if set(distinct) - expected:
            raise Rejected('PARTICIPATION_OUTSIDE_REGISTERED_SCOPE')
        output.append({'domain': plan['domain'], 'cells': copy.deepcopy(plan['cells']),
                       'interval': selected_slot['slot_start']+'/'+selected_slot['slot_end'],
                       'members': sorted(distinct), 'sum_W': result['value_W'], 'count': len(distinct),
                       'received_count':result['counts']['received'],
                       'function': policy['function'], 'slot': selected_slot, 'receipt_digest': result['receipt_digest'],
                       'policy': policy})
    if len(output) != len(policy['selected_slots']):
        raise Rejected('RELEASE_WINDOW_SET_INCOMPLETE')
    return output


def check_candidates(state, values, *, minimum=10):
    """Pure fixed-cell enforcement used by UC; caller holds the ledger lock."""
    staged = copy.deepcopy(state)
    staged.setdefault('cells', {})
    staged.setdefault('inputs', {})
    staged.setdefault('views', {})
    approvals = []
    for item in values:
        domain, interval = item['domain'], item['interval']
        union = set()
        if not item['cells']:
            return None, 'NO_REGISTERED_CELL'
        for cell_id, cell in item['cells'].items():
            members = set(cell['members'])
            if len(members) != len(cell['members']) or union & members:
                raise Rejected('RELEASE_CELL_PARTITION_INVALID')
            if len(members) < minimum:
                return None, 'MINIMUM_COHORT'
            union |= members
            key = domain+':'+cell_id
            for old_key, old_members in staged['cells'].items():
                if old_key.startswith(domain+':') and old_key != key and members & set(old_members):
                    return None, 'CELL_PARTITION_CHANGED'
            if key in staged['cells'] and staged['cells'][key] != sorted(members):
                return None, 'REGISTERED_MEMBERS_CHANGED'
            staged['cells'][key] = sorted(members)
            input_key = key+':'+interval
            fingerprint = cell['inputs'][interval]
            if input_key in staged['inputs'] and staged['inputs'][input_key] != fingerprint:
                return None, 'PUBLISHED_INPUT_REVISION'
            staged['inputs'][input_key] = fingerprint
        if union != set(item['members']) or len(item['members']) != len(set(item['members'])):
            return None, 'INCOMPLETE_REGISTERED_COHORT'
        if type(item['sum_W']) is not int or item['sum_W'] < 0 or item['count'] != len(union):
            raise Rejected('RELEASE_VALUE_OR_COUNT_INVALID')
        key = digest({'domain': domain, 'cells': sorted(item['cells']), 'interval': interval})
        old = staged['views'].get(key)
        numeric = {'sum_W': item['sum_W'], 'count': item['count']}
        if old and canonical(old['numeric']) != canonical(numeric):
            return None, 'PUBLISHED_VALUE_CHANGED'
        if old is None:
            old = {'publication_id': uuid.uuid4().hex, 'numeric': numeric}
            staged['views'][key] = old
        approvals.append({'publication_id': old['publication_id'], 'reused': key in state.get('views', {})})
    return (staged, approvals), None


def transact(runtime, values, run_id, builder, *, private_control=False):
    """Root-encrypted state is the monotonic anchor, outside material backups.

Staging precedes root commit; public visibility follows it. A crash may leave a
conservative committed-but-not-visible release, never an unrecorded release.
"""
    runtime = Path(runtime)
    stage = runtime / 'runs' / run_id / 'utility/release-ready.json'
    if private_control:
        package=builder('EXPERIMENT_NOT_RELEASED',[{'publication_id':uuid.uuid4().hex,'reused':False} for _ in values],0)
        write(stage,package,True,runtime=runtime)
        write(runtime/'runs'/run_id/'utility/release-diagnostic.json',{'reason':'PRIVATE_CONTROL_NO_PUBLICATION'},True,runtime=runtime)
        return package
    with root_transaction(runtime) as root:
        state = root.get('publication_state', {'sequence': 0, 'cells': {}, 'inputs': {}, 'views': {}, 'commits': {}})
        if run_id in state.get('commits', {}):
            package = read(stage, runtime=runtime)
            if digest(package) != state['commits'][run_id]:
                raise Rejected('PUBLICATION_STAGED_CONTENT_CHANGED')
            return package
        outcome, reason = check_candidates(state, values, minimum=rules()['minimum_contributors'])
        updated, approvals = outcome if outcome is not None else (copy.deepcopy(state), [])
        sequence = state['sequence']+1
        decision = 'EXPERIMENT_NOT_RELEASED' if private_control else 'PUBLISHED' if reason is None else 'WITHHELD'
        package = builder(decision, approvals, sequence)
        write(stage, package, True, runtime=runtime)
        write(runtime / 'runs' / run_id / 'utility/release-diagnostic.json', {'reason': reason}, True, runtime=runtime)
        updated['sequence'] = sequence
        updated.setdefault('commits', {})[run_id] = digest(package)
        root['publication_state'] = updated
    return package


def statement(kind, content, policy, context, publication_id, sequence, decision, runtime=RUNTIME):
    from .signatures import sign_object,time_value
    issued=utc()
    if not time_value(policy['issued_at'])<=time_value(issued)<time_value(policy['expires_at']):
        raise Rejected('PUBLICATION_AUTHORIZATION_EXPIRED')
    payload = {'object_type': kind, 'schema_version': 2 if kind=='GRID_UC_RESULT_V2' else 1, 'run_id': context['run_id'], 'task_id': context['task_id'],
               'param_id': context['param_id'], 'security_profile': 'SAB', 'key_epoch': policy['key_epoch'],
               'trust_registry_digest': policy['trust_registry_digest'], 'algorithm_suite': policy['algorithm_suite'],
               'release_rules_digest': policy['release_rules_digest'], 'policy_digest': digest(policy),
               'content_digest': digest(content), 'issued_at': issued, 'publication_sequence': sequence,
               'publication_id': publication_id, 'decision': decision}
    return sign_object(payload, runtime)


def view(item, approval):
    function = item['function']
    from .governance import present_value
    shown = present_value(function,item['sum_W'],item['count'])
    # COUNT intentionally has neither raw sum nor a digest of that raw sum.
    result = {'slot_id': item['slot']['slot_id'], 'selected_slot': item['slot'], 'function': function,
              'published_value': shown, 'unit': 'reports' if function == 'COUNT' else 'W', 'status': 'PUBLISHED',
              'publication_id': approval['publication_id'], 'publication_reused': approval['reused'],
              'receipt_digest': item['receipt_digest'], 'coverage_basis_points': 10000,
              'registered_metering_points': item['count'],
              'counts':{'accepted':item['count'],'received':item.get('received_count',item['count'])}}
    if function == 'SUM':
        result['value_W'] = item['sum_W']
    return result


def release_task(policy, computed, participation, plan, context, *, runtime=RUNTIME, private_control=False):
    values = candidates(policy, computed, participation, plan)
    def build(decision, approvals, sequence):
        identifier = approvals[0]['publication_id'] if approvals else uuid.uuid4().hex
        results = [view(item, approval) for item, approval in zip(values, approvals, strict=True)] if decision != 'WITHHELD' else []
        body = {'run_id': context['run_id'], 'decision': decision, 'results': results,
                'rules_digest': policy['release_rules_digest'], 'policy_digest': digest(policy),
                'publication_id': identifier, 'publication_sequence': sequence,
                'reason': 'RELEASED' if decision == 'PUBLISHED' else 'PRIVATE_EXPERIMENT' if decision == 'EXPERIMENT_NOT_RELEASED' else 'RELEASE_CONDITIONS_NOT_MET'}
        signed, timing = statement('GRID_RELEASE_DECISION_V1', body, policy, context, identifier, sequence, decision, runtime)
        result_statements, timings = [], list(timing)
        for result in results:
            envelope, extra = statement('GRID_UC_RESULT_V2', result, policy, context, result['publication_id'], sequence, decision, runtime)
            result_statements.append(envelope); timings.extend(extra)
        return {'release': body, 'release_statement': signed, 'results': results,
                'result_statements': result_statements, 'signing_timings': timings}
    return transact(runtime, values, context['run_id'], build, private_control=private_control)


def verify_statement(envelope, content, *, runtime=RUNTIME, expected=None, usage='history'):
    from .signatures import verify_object
    payload, evidence = verify_object(envelope, envelope['payload']['object_type'], 'SAB', runtime, usage=usage)
    if payload['content_digest'] != digest(content):
        raise Rejected('PUBLICATION_CONTENT_BINDING_INVALID')
    if expected and any(payload.get(key) != value for key, value in expected.items()):
        raise Rejected('PUBLICATION_EXPECTED_CONTEXT_INVALID')
    return {**evidence, 'content_binding_verified': True, 'publication_decision': payload['decision'],
            'current_signer_trust_verified':all(row['current_status']!='REVOKED' for row in evidence.get('key_trust',[])),
            'scope': 'Trusted UC release statement; no public decryption, source truth or differential privacy proof'}

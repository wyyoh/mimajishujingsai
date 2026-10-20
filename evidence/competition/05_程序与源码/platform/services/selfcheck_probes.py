"""Non-destructive checks of live enforcement and authorized local evidence.

These are application checks under the trusted host/UC model. In particular,
checking a private UC working copy is not public verifiable decryption.
"""
import copy
import os
import re
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone

from .encoding import Rejected, canonical, digest
from .initialization import ROOT, RUNTIME
from .storage import read

RUN_ID = re.compile(r'^[0-9a-f]{32}$')


def require(condition, code):
    if not condition:
        raise Rejected(code)


def rejection(name, call, codes):
    """A different error is not evidence of the expected enforcement."""
    try:
        call()
        observed = 'UNEXPECTED_ACCEPTANCE'
    except Rejected as exc:
        observed = exc.code
    return {'id': name, 'passed': observed in codes, 'observed': observed, 'expected': sorted(codes)}


def choose_run(subject, core):
    """Only use this runtime's bounded subject index; never scan private jobs."""
    if subject is None or not (RUNTIME/'api.sqlite').is_file():
        return None
    from .custody import trust_pin
    authority = trust_pin(RUNTIME)['registry_pin']
    with closing(sqlite3.connect((RUNTIME/'api.sqlite').resolve().as_uri()+'?mode=ro', uri=True)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='v41_nonces'").fetchone():
            return None
        identifiers = db.execute('SELECT run_id FROM v41_nonces WHERE subject=? ORDER BY rowid DESC LIMIT 200', (subject,)).fetchall()
    eligible = []
    for (identifier,) in identifiers:
        if not isinstance(identifier, str) or not RUN_ID.fullmatch(identifier):
            continue
        try:
            row = read(ROOT/'artifacts/runs'/identifier/'run_manifest.json')
        except (FileNotFoundError, Rejected):
            continue
        if (row.get('run_id') == identifier and row.get('protocol_version') == 5
                and row.get('requester_id') == subject and row.get('runtime_instance') == authority
                and not row.get('private_experiment') and row.get('parent_evaluation', 'none') == 'none'
                and row.get('status') in ('COMPLETED', 'WITHHELD')
                and (not row.get('lab') or os.environ.get('GRID_LAB') == '1')):
            eligible.append(row)
    if not eligible:
        return None
    # A current withheld decision is more relevant than a stale successful job.
    return max(eligible, key=lambda row: (row.get('core_source_digest') == core, row['status'] == 'COMPLETED'))['run_id']


def authorization():
    from .governance import decide, check_policy
    request = {'asset_id': 'household-load-demo', 'region': 'A', 'resources': ['residential'],
               'function': 'SUM', 'algorithm_suite': 'V41_HYBRID_SM', 'validity_minutes': 10, 'request_nonce': uuid.uuid4().hex}
    policy = decide(request, 'grid_operator_A')
    check_policy(policy, digest(policy), 'SAB', business=True)
    checks = [rejection('wrong_region', lambda: decide({**request, 'region': 'B'}, 'grid_operator_A'), {'POLICY_REGION_DENIED'}),
              rejection('wrong_level', lambda: decide(request, 'grid_analyst_A'), {'POLICY_DATA_LEVEL_DENIED'}),
              rejection('wrong_function', lambda: decide({**request, 'asset_id': 'public-load-demo', 'function': 'AVG'}, 'grid_analyst_A'), {'POLICY_FUNCTION_DENIED'})]
    for suite in ('V41_CLASSIC', 'V41_SM', 'V41_PQ'):
        checks.append(rejection('business_downgrade_'+suite, lambda suite=suite: decide({**request, 'algorithm_suite': suite}, 'grid_operator_A'), {'POLICY_CRYPTO_DOWNGRADE'}))
    checks.append(rejection('important_data_requires_sm', lambda: decide({**request, 'asset_id': 'critical-load-demo', 'algorithm_suite': 'V41_HYBRID'}, 'grid_operator_A'), {'POLICY_CRYPTO_DOWNGRADE'}))
    expired = {**policy, 'issued_at': (datetime.now(timezone.utc)-timedelta(minutes=20)).isoformat().replace('+00:00', 'Z'),
               'expires_at': (datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat().replace('+00:00', 'Z')}
    checks.append(rejection('expired_policy', lambda: check_policy(expired, digest(expired), 'SAB', business=True), {'POLICY_EXPIRED'}))
    require(all(row['passed'] for row in checks), 'SELF_CHECK_AUTHORIZATION_ENFORCEMENT_FAILED')
    return {'allowed_request_checked': True, 'negative_checks': checks, 'classification_scope': 'SIMULATED_NOT_OFFICIAL'}


def release_rules():
    """Small explicit model inputs exercise the real pure UC rule function."""
    from .publication import check_candidates, rules
    minimum = rules()['minimum_contributors']
    require(minimum >= 10 and rules()['differential_privacy'] is False, 'SELF_CHECK_RELEASE_RULES_UNSAFE')
    members = [f'self-check-meter-{i}' for i in range(2*minimum)]
    interval = 'SELF_CHECK_INTERVAL'
    item = {'domain': 'SELF_CHECK_ONLY', 'interval': interval, 'cells': {'whole': {'members': members, 'inputs': {interval: 'input-v1'}}},
            'members': members, 'sum_W': 1000, 'count': len(members), 'function': 'SUM'}
    first, reason = check_candidates({}, [item], minimum=minimum)
    require(first is not None and reason is None, 'SELF_CHECK_RELEASE_POSITIVE_FAILED')
    state, approvals = first
    checks = []
    def denied(name, candidate, expected, previous=state):
        outcome, observed = check_candidates(previous, [candidate], minimum=minimum)
        checks.append({'id': name, 'passed': outcome is None and observed == expected, 'observed': observed, 'expected': expected})
    small = copy.deepcopy(item)
    small['cells']['whole']['members'] = members[:minimum-1]
    small.update(members=members[:minimum-1], count=minimum-1)
    denied('small_cell', small, 'MINIMUM_COHORT', {})
    incomplete = copy.deepcopy(item); incomplete['members'] = members[:-1]
    denied('missing_meter', incomplete, 'INCOMPLETE_REGISTERED_COHORT')
    duplicate = copy.deepcopy(item); duplicate['members'] = members+[members[0]]
    denied('duplicate_meter', duplicate, 'INCOMPLETE_REGISTERED_COHORT')
    split = copy.deepcopy(item)
    split['cells'] = {name: {'members': part, 'inputs': {interval: 'input-v1'}} for name, part in (('left', members[:minimum]), ('right', members[minimum:]))}
    denied('overlapping_partition_change', split, 'CELL_PARTITION_CHANGED')
    revision = copy.deepcopy(item); revision['cells']['whole']['inputs'][interval] = 'input-v2'
    denied('input_revision', revision, 'PUBLISHED_INPUT_REVISION')
    for function in ('COUNT', 'AVG'):
        repeated, reason = check_candidates(state, [{**item, 'function': function}], minimum=minimum)
        require(repeated is not None and reason is None and repeated[1][0]['publication_id'] == approvals[0]['publication_id'], 'SELF_CHECK_SHARED_HISTORY_FAILED')
        denied('numeric_revision_through_'+function, {**item, 'function': function, 'sum_W': 1001}, 'PUBLISHED_VALUE_CHANGED')
    require(all(row['passed'] for row in checks), 'SELF_CHECK_RELEASE_ENFORCEMENT_FAILED')
    return {'input_scope': 'Synthetic in-memory rule probes; no business publication or ledger mutation',
            'minimum_contributors': minimum, 'positive_release_checked': True, 'shared_function_history_checked': True, 'negative_checks': checks}


def components(run):
    """The parent archive binds receipts, not the children's full snapshots.

Read protected UC working copies only after authenticating the parent archive.
Return objects internally; callers publish only counts and boolean checks.
"""
    directory = ROOT/'artifacts/runs'/run['run_id']
    if run.get('evaluation_id'):
        inputs = read(directory/'evaluation_inputs.json')
        expected = [(row['context']['run_id'], index+1) for index, row in enumerate(inputs)]
        require(len(inputs) == 4 and [(row['run_id'], row['day']) for row in run['children']] == expected, 'SELF_CHECK_CHILD_SET_MISMATCH')
        output = []
        for item in inputs:
            identifier = item['context']['run_id']
            require(bool(RUN_ID.fullmatch(identifier)), 'SELF_CHECK_CHILD_ID_INVALID')
            child = read(ROOT/'artifacts/runs'/identifier/'run_manifest.json')
            require(child.get('parent_evaluation') == run['run_id'] and child.get('runtime_instance') == run['runtime_instance']
                    and child.get('core_source_digest') == run.get('core_source_digest') and child.get('requester_id') == run['requester_id']
                    and child.get('policy_digest') == digest(item['policy']) and child.get('task_id') == item['context']['task_id']
                    and child.get('param_id') == item['context']['param_id'] and child['status'] == 'COMPUTED', 'SELF_CHECK_CHILD_CONTEXT_MISMATCH')
            computed = read(RUNTIME/'runs'/identifier/'utility/computed.json')
            require(canonical(computed['receipts']) == canonical(item['receipts']), 'SELF_CHECK_CHILD_RECEIPTS_MISMATCH')
            output.append({'run_id': identifier, 'policy': item['policy'], 'results': item['results'], **{key: computed[key] for key in ('receipts', 'snapshots', 'audit_checkpoints', 'accepted_manifests')}})
        return output
    return [{'run_id': run['run_id'], 'policy': read(directory/'governance.json'), 'results': run['results'],
             **{name: read(directory/f'{name}.json') for name in ('receipts', 'snapshots', 'audit_checkpoints', 'accepted_manifests')}}]


def links(groups):
    from .signatures import verify_object
    from .expansion_evidence import verify_links
    checked = []
    for group in groups:
        slots = {item['slot_id'] for item in group['policy']['selected_slots']}
        require(len(group['receipts']) == len(slots) and {row['payload']['slot_id'] for row in group['receipts']} == slots
                and all(set(group[name]) == slots for name in ('snapshots', 'audit_checkpoints', 'accepted_manifests')), 'SELF_CHECK_EVIDENCE_WINDOW_SET_INVALID')
        for envelope in group['receipts']:
            payload, signature = verify_object(envelope, 'GRID_AGG_RECEIPT_V5', 'SAB', RUNTIME, usage='history')
            require(payload['run_id'] == group['run_id'] and all(row['current_status'] != 'REVOKED' for row in signature['key_trust']), 'SELF_CHECK_RECEIPT_TRUST_INVALID')
            slot = payload['slot_id']
            checked.append(verify_links(payload, group['snapshots'][slot], group['audit_checkpoints'][slot], group['accepted_manifests'][slot], group['policy']))
    require(bool(checked), 'SELF_CHECK_NO_LINKED_WINDOWS')
    # Tamper only in memory. Rebuilding ordinary hashes cannot repair these links.
    first = groups[0]; envelope = first['receipts'][0]; payload = envelope['payload']; slot = payload['slot_id']
    def verify(sealed=None, audit=None, accepted=None):
        return verify_links(payload, sealed if sealed is not None else first['snapshots'][slot],
                            audit if audit is not None else first['audit_checkpoints'][slot],
                            accepted if accepted is not None else first['accepted_manifests'][slot], first['policy'])
    changed = copy.deepcopy(first['snapshots'][slot]); changed['records'][0]['report']['CT'] = str(int(changed['records'][0]['report']['CT'])+1)
    integrity = [rejection('ciphertext_modified', lambda: verify(sealed=changed), {'SNAPSHOT_ROOT_MISMATCH'})]
    accepted = first['accepted_manifests'][slot][:-1]
    integrity.append(rejection('accepted_set_deleted', lambda: verify(accepted=accepted), {'ACCEPTED_SET_DIGEST_MISMATCH'}))
    audit_checks = []
    for kind in ('modified', 'deleted', 'reordered'):
        audit = copy.deepcopy(first['audit_checkpoints'][slot])
        if kind == 'modified': audit['records'][0]['result'] = 'SELF_CHECK_MODIFIED'
        elif kind == 'deleted': audit['records'].pop()
        else: audit['records'].reverse()
        expected = {'modified': 'AUDIT_HASH_MISMATCH', 'deleted': 'AUDIT_SHAPE_INVALID', 'reordered': 'AUDIT_CONTEXT_OR_ORDER_MISMATCH'}
        audit_checks.append(rejection('audit_'+kind, lambda audit=audit: verify(audit=audit), {expected[kind]}))
    return {'window_count': len(checked), 'child_count': len(groups), 'snapshot_checks': integrity, 'audit_checks': audit_checks,
            'all_source_and_period_bindings_verified': all(row['source_bindings_verified'] and row['dataset_period_binding_verified'] for row in checked),
            'all_audit_checkpoints_verified': all(row['audit_checkpoint_verified'] for row in checked),
            'evidence_scope': 'Local UC working copies plus signed parent inputs' if len(groups) > 1 else 'Public archive snapshots and signed receipts'}


def communication(run):
    from .agility import provider
    selected = provider(run['algorithm_suite'])
    require(selected.business_allowed and selected.profile == 'SAB', 'SELF_CHECK_BUSINESS_SUITE_INVALID')
    directory = ROOT/'artifacts/runs'/run['run_id']
    records = read(directory/'connection_evidence.json')
    children = run.get('children') if run.get('evaluation_id') else [{'run_id': run['run_id']}]
    require(bool(children) and len({row['run_id'] for row in children}) == len(children), 'SELF_CHECK_TLS_CHILD_SET_INVALID')
    sources = {f'L1-source-{i+1}': {'gateway', f'source-{i+1}'} for i in range(run['logical_source_process_count'])}
    expected_links = {'L2': {'gateway', 'utility'}, **sources}
    total = 0
    seen = set()
    for child in children:
        subset = [row for row in records if row.get('child_run_id', run['run_id']) == child['run_id']]
        require(len(subset) == 2*len(expected_links), 'SELF_CHECK_TLS_ENDPOINTS_INCOMPLETE')
        if run.get('evaluation_id'):
            original = read(ROOT/'artifacts/runs'/child['run_id']/'connection_evidence.json')
            require(canonical(subset) == canonical([{**row, 'child_run_id': child['run_id'], 'evaluation_day': child['day']} for row in original]), 'SELF_CHECK_TLS_CHILD_COPY_MISMATCH')
        require({row['link_id'] for row in subset} == set(expected_links), 'SELF_CHECK_TLS_LINK_SET_INVALID')
        for link_id, peers in expected_links.items():
            pair = [row for row in subset if row['link_id'] == link_id]
            require(len(pair) == 2 and {row['peer_role'] for row in pair} == peers
                    and len({row['process_instance'] for row in pair}) == 2, 'SELF_CHECK_TLS_PEER_PAIR_INVALID')
            require(pair[0]['business_request_refs'] and sorted(pair[0]['business_request_refs']) == sorted(pair[1]['business_request_refs']), 'SELF_CHECK_TLS_BUSINESS_REFS_INVALID')
            for row in pair:
                require(row['connection_id'] not in seen, 'SELF_CHECK_TLS_DUPLICATE_ENDPOINT')
                seen.add(row['connection_id'])
                require(row.get('peer_verified') and row.get('peer_chain_verified') and row.get('peer_identity_verified')
                        and row.get('peer_name') == row['peer_role']+'.grid' and row['actual_group'] == selected.group
                        and row['tls_version'] == 'TLSv1.3' and row['record_cipher'] == 'TLS_AES_256_GCM_SHA384'
                        and row.get('session_reused') is False and row.get('early_data_accepted') is False,
                        'SELF_CHECK_TLS_PROTECTION_FAILED')
                require(row['application_bytes_sent'] > 0 and row['application_bytes_received'] > 0, 'SELF_CHECK_TLS_NO_BUSINESS_DATA')
                if selected.sm4_channel:
                    require(row.get('application_cipher') == 'SM4-GCM' and row.get('sm4_frames_sent', 0) > 0
                            and row.get('sm4_frames_received', 0) > 0, 'SELF_CHECK_SM4_CHANNEL_MISSING')
            require(pair[0]['application_bytes_sent'] == pair[1]['application_bytes_received']
                    and pair[1]['application_bytes_sent'] == pair[0]['application_bytes_received'], 'SELF_CHECK_TLS_COUNTERS_MISMATCH')
            total += 1
    require(len(records) == 2*total, 'SELF_CHECK_TLS_UNEXPECTED_RECORDS')
    return {'connection_pairs': total, 'endpoint_records': len(records), 'child_count': len(children),
            'actual_group': selected.group, 'sm4_required': selected.sm4_channel, 'all_identities_and_business_links_checked': True,
            'records_digest': digest(records), 'evidence_scope': 'Local endpoint observations; trusted host, not independently signed transport attestation'}


def signatures(run):
    from .publication import verify_statement
    from .agility import provider
    directory = ROOT/'artifacts/runs'/run['run_id']
    signed, content = read(directory/'release_statement.json'), read(directory/'release.json')
    expected = {key: run[key] for key in ('run_id', 'task_id', 'param_id', 'policy_digest', 'algorithm_suite')}
    checked = verify_statement(signed, content, expected=expected)
    required = provider(run['algorithm_suite']).algorithms
    require(checked['current_signer_trust_verified'] and {row['algorithm'] for row in signed['signatures']} == set(required), 'SELF_CHECK_REQUIRED_SIGNATURES_INVALID')
    negatives = []
    for index, entry in enumerate(signed['signatures']):
        missing = copy.deepcopy(signed); missing['signatures'].pop(index)
        negatives.append(rejection('missing_'+entry['algorithm'], lambda missing=missing: verify_statement(missing, content, expected=expected), {'REQUIRED_SIGNATURE_MISSING', 'OBJECT_SCHEMA_INVALID'}))
        modified = copy.deepcopy(signed)
        value = modified['signatures'][index]['value']
        modified['signatures'][index]['value'] = ('A' if value[0] != 'A' else 'B')+value[1:]
        negatives.append(rejection('modified_'+entry['algorithm'], lambda modified=modified: verify_statement(modified, content, expected=expected), {'OBJECT_SIGNATURE_INVALID'}))
    negatives.append(rejection('wrong_task', lambda: verify_statement(signed, content, expected={**expected, 'task_id': 'wrong-task'}), {'PUBLICATION_EXPECTED_CONTEXT_INVALID'}))
    require(all(row['passed'] for row in negatives), 'SELF_CHECK_SIGNATURE_ENFORCEMENT_FAILED')
    return {'required_algorithms': list(required), 'all_required_verified': True, 'negative_checks': negatives,
            'selected_suite': run['algorithm_suite'], 'historical_formats_scope': 'Separate versioned regression evidence required'}


def publication_commit(run):
    from .custody import load_root
    from .publication import candidates, check_candidates, rules
    state = load_root(RUNTIME).get('publication_state', {})
    package = read(RUNTIME/'runs'/run['run_id']/'utility/release-ready.json')
    require(state.get('commits', {}).get(run['run_id']) == digest(package), 'SELF_CHECK_PUBLICATION_COMMIT_MISMATCH')
    release = read(ROOT/'artifacts/runs'/run['run_id']/'release.json')
    signed = read(ROOT/'artifacts/runs'/run['run_id']/'release_statement.json')
    require(canonical(package['release']) == canonical(release) and canonical(package['release_statement']) == canonical(signed), 'SELF_CHECK_PUBLICATION_INSTALL_MISMATCH')
    windows = 0
    if release['decision'] == 'PUBLISHED':
        inputs = read(ROOT/'artifacts/runs'/run['run_id']/'evaluation_inputs.json') if run.get('evaluation_id') else [
            {'context': {'run_id': run['run_id']}, 'policy': read(ROOT/'artifacts/runs'/run['run_id']/'governance.json'), 'results': run['results']}]
        values = []
        for item in inputs:
            identifier = item['context']['run_id']
            require(bool(RUN_ID.fullmatch(identifier)), 'SELF_CHECK_CHILD_ID_INVALID')
            job = RUNTIME/'runs'/identifier/'utility'
            computed, plan, participation = read(job/'computed.json'), read(job/'release-plan.json'), read(job/'participation.json')
            group = candidates(item['policy'], computed, participation, plan)
            require(len(group) == len(item['results']), 'SELF_CHECK_PUBLICATION_WINDOW_SET_INVALID')
            for candidate, result in zip(group, item['results'], strict=True):
                require(candidate['receipt_digest'] == result['receipt_digest'] and candidate['count'] == result['registered_metering_points']
                        and (item['policy']['function'] == 'COUNT' or candidate['sum_W'] == result['value_W']), 'SELF_CHECK_PUBLICATION_RESULT_MISMATCH')
            values.extend(group)
        outcome, reason = check_candidates(state, values, minimum=rules()['minimum_contributors'])
        require(outcome is not None and reason is None, 'SELF_CHECK_PUBLISHED_COHORT_NO_LONGER_VALID')
        require([row['publication_id'] for row in outcome[1]] == [row['publication_id'] for item in inputs for row in item['results']], 'SELF_CHECK_PUBLICATION_HISTORY_MISMATCH')
        windows = len(values)
    return {'protected_commit_verified': True, 'staged_public_projection_matches': True, 'decision': release['decision'],
            'registered_participation_windows_rechecked': windows, 'ledger_mutated': False}

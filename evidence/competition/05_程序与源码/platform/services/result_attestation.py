"""UC statement authentication; deliberately not a publicly verifiable decryption."""
from .encoding import Rejected, digest
from .native import utc
from .signatures import sign_object, verify_object, time_value


def attest(result, receipt, policy, context, runtime):
    slot = next(slot for slot in context['slots'] if slot['slot_id'] == result['slot_id'])
    payload = {'object_type': 'GRID_UC_RESULT_V1', 'schema_version': 1, 'task_id': context['task_id'],
               'run_id': context['run_id'], 'param_id': context['param_id'], 'security_profile': 'SAB',
               'key_epoch': receipt['key_epoch'], 'trust_registry_digest': receipt['trust_registry_digest'],
               'algorithm_suite': policy['algorithm_suite'], 'function': policy['function'], 'selected_slot': slot,
               'dataset_digest': policy['dataset_digest'], 'policy_digest': digest(policy),
               'authorization_digest': receipt['authorization_digest'], 'receipt_digest': digest(receipt),
               'result_digest': digest(result), 'accepted_set_digest': receipt['accepted_set_digest'],
               'snapshot_root': receipt['snapshot_root'], 'issued_at': utc()}
    return sign_object(payload, runtime)


def verify_statement(envelope, result, receipt, policy, runtime, *, usage='history'):
    payload, evidence = verify_object(envelope, 'GRID_UC_RESULT_V1', 'SAB', runtime, usage=usage)
    if (payload['result_digest'] != digest(result) or payload['receipt_digest'] != digest(receipt)
            or payload['policy_digest'] != digest(policy) or payload['function'] != policy['function']
            or payload['dataset_digest'] != policy['dataset_digest']
            or payload['selected_slot'] != next(slot for slot in policy['selected_slots'] if slot['slot_id'] == result['slot_id'])
            or any(payload[key] != receipt[key] for key in ('task_id', 'run_id', 'param_id', 'authorization_digest',
                'key_epoch', 'trust_registry_digest', 'accepted_set_digest', 'snapshot_root', 'algorithm_suite'))):
        raise Rejected('UC_RESULT_STATEMENT_MISMATCH')
    if not time_value(receipt['issued_at']) <= time_value(payload['issued_at']) < time_value(policy['expires_at']):
        raise Rejected('UC_RESULT_OUTSIDE_POLICY_VALIDITY')
    return {'slot_id': result['slot_id'], 'uc_statement_signature_valid': True, 'result_content_binding_valid': True,
            'scope': 'UC statement origin and integrity; not public decryption proof or source completeness',
            'key_trust': evidence.get('key_trust', [])}

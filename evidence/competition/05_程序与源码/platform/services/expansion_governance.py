"""Trusted local data/source binding and scenario grants for V3 tasks."""
import fcntl
import hashlib
import os
import ssl
from datetime import datetime, timedelta, timezone

from .agility import provider
from .encoding import Rejected, canonical, digest
from .expansion_data import PUBLIC_ID, SYNTHETIC_ID, select
from .expansion_schemas import ExpansionPolicy, ExpansionRequest
from .governance import SUBJECTS, classify
from .initialization import RUNTIME, command
from .signatures import time_value, validate
from .storage import read, write

SCENES = {
    'residential': {'name': '区域居民负荷', 'resources': ['residential'], 'question': '统计本区域居民负荷，原始用户读数保留在数据源。', 'verification': '授权区域与居民类别、总和/平均值/参与数、签名回执'},
    'park': {'name': '园区多主体协同', 'resources': ['residential', 'commercial', 'charging'], 'question': '由独立数据源联合提供园区群体统计，逐源核对身份与密文快照。', 'verification': '主体权限、各Source身份/快照、联合聚合与独立核对'},
    'charging': {'name': '充电设施高峰', 'resources': ['charging'], 'question': '选择高峰时段统计充电负荷及有效报告数，说明缺报对统计的影响。', 'verification': '时段、充电类别、上报计数、缺报与回执关联'},
}

def certificate_hash(path):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest()

def initialize_sources():
    from .orchestrator import initialize
    initialize()
    with (RUNTIME / 'v42-source-init.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        registry = {}
        for index in range(1, 4):
            name = f'source-{index}'
            private = RUNTIME / name
            private.mkdir(exist_ok=True, mode=0o700)
            if not (private / 'tls.pem').exists():
                command('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', private / 'tls.key')
                command('openssl', 'req', '-new', '-key', private / 'tls.key', '-out', private / 'tls.csr', '-subj', f'/CN={name}.grid')
                extension = private / 'tls.ext'
                extension.write_text(f'subjectAltName=DNS:{name}.grid\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
                command('openssl', 'x509', '-req', '-in', private / 'tls.csr', '-CA', RUNTIME / 'public/ca.pem', '-CAkey', RUNTIME / 'ta/ca.key', '-CAcreateserial', '-out', private / 'tls.pem', '-days', '14', '-extfile', extension)
                os.chmod(private / 'tls.key', 0o600)
            fingerprint = certificate_hash(private / 'tls.pem')
            write(RUNTIME / 'public' / f'{name}-identity.json', {'source_id': name, 'certificate_sha256': fingerprint, 'epoch': 1})
            registry[name] = {'certificate_sha256': fingerprint, 'epoch': 1}
        write(RUNTIME / 'public/source-registry-v42.json', registry)
        from .custody import protect_existing
        protect_existing(RUNTIME)
        from .trust import enroll_sources
        enroll_sources(RUNTIME)
        from .trust import lookup
        registry = {role: {'certificate_sha256': certificate_hash(lookup(RUNTIME, role, 'tls')[1]),
                            'epoch': lookup(RUNTIME, role, 'tls')[0]['epoch']} for role in registry}
        write(RUNTIME / 'public/source-registry-v42.json', registry)
    return registry

def partitions(dataset, count):
    result = []
    for index in range(count):
        name = f'source-{index+1}'
        nodes = dataset['nodes'][index::count]
        value = {'dataset_id': dataset['dataset_id'], 'source_id': name, 'nodes': nodes, 'node_count': len(nodes),
                 'slots': dataset['slots'], 'period_indices': dataset['period_indices'], 'parent_dataset_digest': dataset['dataset_digest']}
        value['partition_digest'] = digest(value)
        result.append(value)
    return result

def prepare(request, subject):
    request = validate(ExpansionRequest, request.model_dump() if hasattr(request, 'model_dump') else request)
    grant = SUBJECTS.get(subject)
    asset = classify(request['asset_id'])
    if not grant or request['region'] not in grant['regions']:
        raise Rejected('POLICY_REGION_DENIED')
    if asset['data_level'] not in grant['levels']:
        raise Rejected('POLICY_DATA_LEVEL_DENIED')
    if request['function'] not in grant['functions']:
        raise Rejected('POLICY_FUNCTION_DENIED')
    selected = provider(request['algorithm_suite'])
    if not selected.business_allowed or asset['data_level'] == 'important_simulated' and not selected.sm4_channel:
        raise Rejected('POLICY_CRYPTO_DOWNGRADE')
    dataset = select(request['dataset_id'], request['nodes'], request['day'], request['periods'])
    identities = initialize_sources()
    parts = partitions(dataset, request['source_count'])
    now = datetime.now(timezone.utc)
    fmt = lambda value: value.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    policy = {'policy_version': 'V42_POLICY_1', 'requester_id': subject, 'asset_id': request['asset_id'],
              'dataset_version': dataset['dataset_id'], 'data_level': asset['data_level'], 'classification_scope': 'SIMULATED_NOT_OFFICIAL',
              'operation': 'aggregate', 'function': request['function'], 'region': request['region'], 'resources': sorted(SCENES[request['scene_id']]['resources']),
              'algorithm_suite': request['algorithm_suite'], 'security_profile': 'SAB', 'node_count': request['nodes'], 'slot_count': len(request['periods']),
              'issued_at': fmt(now), 'expires_at': fmt(now + timedelta(minutes=request['validity_minutes'])), 'request_nonce': request['request_nonce'],
              'audit': 'FULL', 'key_epoch': 1, 'dataset_digest': dataset['dataset_digest'], 'parent_dataset_digest': dataset['parent_dataset_digest'],
              'data_source': dataset['source'], 'scene_id': request['scene_id'], 'period_indices': dataset['period_indices'], 'selected_slots': dataset['slots'],
              'sources': [{'source_id': part['source_id'], 'node_count': part['node_count'], 'partition_digest': part['partition_digest'],
                           'certificate_sha256': identities[part['source_id']]['certificate_sha256']} for part in parts]}
    from .security_schemas import ExpansionPolicyV4
    from .trust import current_binding
    policy.update(policy_version='V43_POLICY_1', **current_binding(RUNTIME))
    policy = validate(ExpansionPolicyV4, policy)
    check_policy(policy, digest(policy), 'SAB')
    return policy, dataset, parts

def check_policy(policy, expected_digest, profile):
    from .security_schemas import ExpansionPolicyV4
    from .publication_schemas import PublicationPolicy
    policy = validate(PublicationPolicy if policy.get('policy_version') == 'V5_RELEASE_POLICY_1' else ExpansionPolicyV4 if policy.get('policy_version') == 'V43_POLICY_1' else ExpansionPolicy, policy)
    if policy['policy_version'] in ('V43_POLICY_1', 'V5_RELEASE_POLICY_1'):
        from .trust import current_binding
        if any(policy[key] != value for key, value in current_binding(RUNTIME).items()):
            raise Rejected('TRUST_REGISTRY_CHANGED')
    if policy['policy_version'] == 'V5_RELEASE_POLICY_1':
        from .publication import rules
        from .custody import trust_pin
        if policy['runtime_instance']!=trust_pin(RUNTIME)['registry_pin']:
            raise Rejected('POLICY_AUTHORITY_MISMATCH')
        if (policy['release_rules_digest'] != digest(rules()) or policy['release_domain'] != digest({'family': policy['dataset_version'], 'metric': 'average_active_power_W'})):
            raise Rejected('RELEASE_RULES_OR_DOMAIN_MISMATCH')
    if digest(policy) != expected_digest or profile != 'SAB' or policy['security_profile'] != 'SAB':
        raise Rejected('POLICY_DIGEST_OR_PROFILE_MISMATCH')
    now = datetime.now(timezone.utc)
    if not time_value(policy['issued_at']) <= now < time_value(policy['expires_at']):
        raise Rejected('POLICY_EXPIRED')
    if time_value(policy['expires_at']) - time_value(policy['issued_at']) > timedelta(minutes=15):
        raise Rejected('POLICY_VALIDITY_INVALID')
    grant = SUBJECTS.get(policy['requester_id'])
    asset = classify(policy['asset_id'])
    selected = provider(policy['algorithm_suite'])
    if (not grant or policy['region'] not in grant['regions'] or policy['function'] not in grant['functions'] or policy['data_level'] not in grant['levels']
            or policy['data_level'] != asset['data_level'] or policy['resources'] != sorted(SCENES[policy['scene_id']]['resources'])):
        raise Rejected('POLICY_GRANT_MISMATCH')
    if not selected.business_allowed or asset['data_level'] == 'important_simulated' and not selected.sm4_channel:
        raise Rejected('POLICY_CRYPTO_DOWNGRADE')
    allowed = (120, 300, 370) if policy['dataset_version'] == PUBLIC_ID else (120, 300, 600, 900) if policy['dataset_version'] == SYNTHETIC_ID else ()
    origin = 'PUBLIC_OBSERVED_SIMULATED_GROUPS' if policy['dataset_version'] == PUBLIC_ID else 'SYNTHETIC'
    indices = policy['period_indices']
    if (policy['node_count'] not in allowed or policy['data_source'] != origin or len(indices) != policy['slot_count']
            or indices != sorted(set(indices)) or any(not 0 <= index < 672 for index in indices)
            or len({index // 96 for index in indices}) != 1 or len(policy['selected_slots']) != len(indices)
            or [slot['slot_id'] for slot in policy['selected_slots']] != [f'slot-{i}' for i in range(len(indices))]):
        raise Rejected('POLICY_DATASET_CONTEXT_INVALID')
    for slot in policy['selected_slots']:
        if time_value(slot['slot_end']) - time_value(slot['slot_start']) != timedelta(minutes=15):
            raise Rejected('POLICY_PERIOD_INVALID')
    registry = read(RUNTIME / 'public/source-registry-v42.json')
    if ([source['source_id'] for source in policy['sources']] != [f'source-{i+1}' for i in range(len(policy['sources']))]
            or sum(source['node_count'] for source in policy['sources']) != policy['node_count']):
        raise Rejected('POLICY_SOURCE_SET_INVALID')
    for source in policy['sources']:
        if registry[source['source_id']]['certificate_sha256'] != source['certificate_sha256']:
            raise Rejected('POLICY_SOURCE_IDENTITY_MISMATCH')
        from .trust import check_peer
        check_peer(RUNTIME, source['source_id'], source['certificate_sha256'])
    return policy

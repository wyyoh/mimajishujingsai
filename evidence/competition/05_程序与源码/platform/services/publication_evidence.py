"""Safe V5 archives. Archive keys never establish trust by themselves."""
import hashlib
import zipfile
from pathlib import Path
from .encoding import Rejected, canonical, digest, loads
from .initialization import ROOT, RUNTIME
from .storage import read
from .publication import verify_statement

BASE_FILES = {'run_manifest.json','governance.json','data_provenance.json','release.json','release_statement.json',
              'result_statements.json','connection_evidence.json','performance_raw.json','events.json','role_isolation.json',
              'resource_evidence.json','authorization_evidence.json','publication_rules.json'}
PUBLISHED_FILES = {'receipts.json','snapshots.json','audit_checkpoints.json','accepted_manifests.json','signature_evidence.json',
                   'evaluation.json','evaluation_statement.json','evaluation_inputs.json'}
EXTRA_FILES = {'parameter_manifest.json','verification_scope.json','trust_evidence.json'}


def export_v5(run_id, *, target=None):
    directory = ROOT / 'artifacts/runs' / run_id
    run = read(directory / 'run_manifest.json')
    from .custody import trust_pin
    if run.get('runtime_instance')!=trust_pin(RUNTIME)['registry_pin']:
        raise Rejected('RUN_AUTHORITY_MISMATCH')
    if run.get('private_experiment') or run['status']=='EXPERIMENT_ONLY':
        raise Rejected('EXPERIMENT_RECORD_PRIVATE')
    if run['status'] in ('RUNNING','COMPUTED'):
        raise Rejected('RUN_NOT_FINISHED')
    if not (directory/'release_statement.json').is_file() or not (directory/'release.json').is_file():
        raise Rejected('PUBLICATION_DECISION_NOT_AVAILABLE')
    allowed = BASE_FILES | (PUBLISHED_FILES if run.get('publication_status') == 'PUBLISHED' else set())
    entries = {name:(directory/name).read_bytes() for name in allowed if (directory/name).is_file()}
    entries['parameter_manifest.json'] = (RUNTIME/'public/parameters.json').read_bytes()
    entries['verification_scope.json'] = canonical({'scope':'Trusted UC release decision/content; no public decryption or source truth proof',
                                                    'differential_privacy':False,'historical_parameter_security':'PENDING'})
    from .trust import registry, _root_public
    policy = read(directory/'governance.json')
    reference = policy['trust_registry_digest']
    body = registry(RUNTIME, reference)
    entries['trust_evidence.json'] = canonical({'registries':{reference:read(RUNTIME/'public/trust-history'/f'{reference}.json')},
        'public_keys':{entry['public_key']:(RUNTIME/'public'/entry['public_key']).read_text() for entry in body['entries']},
        'root_public_keys':_root_public(RUNTIME)})
    entries['export_manifest.json'] = canonical({'schema':'GRID_PUBLIC_EXPORT_V1','run_id':run_id,
        'files':{name:hashlib.sha256(raw).hexdigest() for name,raw in entries.items()},
        'trust_keys':'Use an independently provisioned root and role registry'})
    target = Path(target) if target is not None else ROOT/'artifacts/exports'/f'{run_id}.zip'
    target.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as archive:
        for name, raw in entries.items():
            archive.writestr(name,raw)
    return target


def verify_v5(archive, runtime, expected):
    runtime = Path(runtime)
    names = set(archive.namelist())
    manifest = loads(archive.read('export_manifest.json'))
    if manifest.get('schema')!='GRID_PUBLIC_EXPORT_V1':
        raise Rejected('EXPORT_SCHEMA_INVALID')
    files = manifest['files']
    if set(files) != names-{'export_manifest.json'} or not set(files) <= BASE_FILES|PUBLISHED_FILES|EXTRA_FILES:
        raise Rejected('EXPORT_FILE_SET_MISMATCH')
    if not {'run_manifest.json','governance.json','release.json','release_statement.json','result_statements.json','parameter_manifest.json','trust_evidence.json','publication_rules.json'} <= names:
        raise Rejected('EXPORT_PUBLICATION_EVIDENCE_MISSING')
    for name, sha in files.items():
        if hashlib.sha256(archive.read(name)).hexdigest() != sha:
            raise Rejected('EXPORT_HASH_MISMATCH')
    run = loads(archive.read('run_manifest.json'))
    policy = loads(archive.read('governance.json'))
    release = loads(archive.read('release.json'))
    envelope = loads(archive.read('release_statement.json'))
    params = loads(archive.read('parameter_manifest.json'))
    rule_body=loads(archive.read('publication_rules.json'))
    if (digest(rule_body)!=policy['release_rules_digest'] or rule_body['schema']!='GRID_RELEASE_RULES_V1'
            or rule_body['minimum_contributors']<10 or rule_body['differential_privacy'] is not False
            or rule_body['input_binding_scheme']!=policy['input_binding_scheme']):
        raise Rejected('EXPORT_RELEASE_RULE_BINDING_INVALID')
    if envelope['payload']['object_type']!='GRID_RELEASE_DECISION_V1':
        raise Rejected('PUBLICATION_OBJECT_TYPE_INVALID')
    if (manifest['run_id'] != run['run_id'] or run['protocol_version'] != 5
            or params['param_id'] != run['param_id'] or digest({k:v for k,v in params.items() if k!='param_id'}) != run['param_id']):
        raise Rejected('EXPORT_RUN_OR_PARAMETERS_MISMATCH')
    if expected is not None and (not expected or any(key not in run or canonical(run[key])!=canonical(value) for key,value in expected.items())):
        raise Rejected('EXPORT_EXPECTED_CONTEXT_MISMATCH')
    if (release['run_id'] != run['run_id'] or release['policy_digest'] != digest(policy) or run['policy_digest'] != digest(policy)
            or canonical(release['results']) != canonical(run['results']) or release['decision'] != run['publication_status']):
        raise Rejected('EXPORT_RELEASE_CONTEXT_MISMATCH')
    linked=('requester_id','asset_id','data_level','algorithm_suite','function','node_count','slot_count','scene_id','dataset_digest','security_profile','release_rules_digest','data_source','runtime_instance','input_binding_scheme')
    if (any(canonical(run[key])!=canonical(policy[key]) for key in linked)
            or run['dataset_id']!=policy['dataset_version'] or run['logical_source_process_count']!=len(policy['sources'])
            or run['status']!=('COMPLETED' if release['decision']=='PUBLISHED' else 'WITHHELD')):
        raise Rejected('EXPORT_POLICY_METADATA_MISMATCH')
    from .publication_schemas import PublicationPolicy
    from .signatures import validate
    policy=validate(PublicationPolicy,policy)
    if 'data_provenance.json' in names:
        provenance=loads(archive.read('data_provenance.json'))
        if (any(canonical(provenance[key])!=canonical(policy[key]) for key in ('dataset_digest','parent_dataset_digest','period_indices','selected_slots'))
                or provenance['dataset_id']!=policy['dataset_version'] or provenance['source']!=policy['data_source']
                or provenance['input_binding_scheme']!=policy['input_binding_scheme']):
            raise Rejected('EXPORT_DATA_PROVENANCE_MISMATCH')
    if bool(run.get('evaluation_id'))!=(policy['parent_evaluation']==run['run_id']):
        raise Rejected('EXPORT_EVALUATION_PARENT_MISMATCH')
    signed_expected = {key:run[key] for key in ('run_id','task_id','param_id','algorithm_suite','policy_digest')}
    signed_expected.update(release_rules_digest=policy['release_rules_digest'],decision=release['decision'],
                           key_epoch=policy['key_epoch'],trust_registry_digest=policy['trust_registry_digest'])
    release_check = verify_statement(envelope,release,runtime=runtime,expected=signed_expected)
    if envelope['payload']['publication_sequence'] != release['publication_sequence'] or envelope['payload']['publication_id'] != release['publication_id']:
        raise Rejected('EXPORT_PUBLICATION_SEQUENCE_MISMATCH')
    from .custody import trust_pin
    from .trust import registry
    bundle = loads(archive.read('trust_evidence.json'))
    reference = policy['trust_registry_digest']
    trusted = registry(runtime,reference)
    if policy['runtime_instance']!=trust_pin(runtime)['registry_pin']:
        raise Rejected('EXPORT_AUTHORITY_MISMATCH')
    if (digest(bundle['root_public_keys']) != trust_pin(runtime)['registry_pin']
            or canonical(bundle['registries'][reference]) != (runtime/'public/trust-history'/f'{reference}.json').read_bytes()
            or any(hashlib.sha256(bundle['public_keys'][entry['public_key']].encode()).hexdigest()!=entry['public_sha256'] for entry in trusted['entries'])):
        raise Rejected('EXPORT_TRUST_EVIDENCE_MISMATCH')
    statements = loads(archive.read('result_statements.json'))
    if len(statements)!=len(run['results']):
        raise Rejected('EXPORT_RESULT_STATEMENT_SET_MISMATCH')
    from .signatures import time_value
    if any(not time_value(policy['issued_at'])<=time_value(item['payload']['issued_at'])<time_value(policy['expires_at']) for item in [envelope,*statements]):
        raise Rejected('EXPORT_PUBLICATION_AUTHORIZATION_TIME_INVALID')
    checks = [verify_statement(statement,result,runtime=runtime,expected={**signed_expected,'object_type':'GRID_UC_RESULT_V2','schema_version':2,
              'publication_sequence':release['publication_sequence'],'publication_id':result['publication_id']})
              for statement,result in zip(statements,run['results'],strict=True)]
    receipt_checks = []
    if release['decision']=='WITHHELD':
        if run['results'] or statements or names&PUBLISHED_FILES:
            raise Rejected('EXPORT_WITHHELD_CONTENT_PRESENT')
    elif release['decision']!='PUBLISHED':
        raise Rejected('EXPERIMENT_NOT_PUBLICLY_PUBLISHABLE')
    elif run.get('evaluation_id'):
        from .response import verify_evaluation
        evaluation_check = verify_evaluation(loads(archive.read('evaluation.json')),loads(archive.read('evaluation_statement.json')),
                          loads(archive.read('evaluation_inputs.json')),runtime=runtime,expected=signed_expected,parent_policy=policy)
        receipt_checks.extend(evaluation_check['child_receipt_checks'])
    else:
        receipts = loads(archive.read('receipts.json'))
        snapshots = loads(archive.read('snapshots.json'))
        audits = loads(archive.read('audit_checkpoints.json'))
        accepted = loads(archive.read('accepted_manifests.json'))
        if len(receipts)!=len(run['results']) or len(run['results'])!=run['slot_count']:
            raise Rejected('EXPORT_RESULT_RECEIPT_SET_MISMATCH')
        from .signatures import verify_object
        from .expansion_evidence import verify_links
        seen = set()
        for receipt,result in zip(receipts,run['results'],strict=True):
            payload,evidence = verify_object(receipt,'GRID_AGG_RECEIPT_V5','SAB',runtime,usage='history')
            slot = result['slot_id']
            if slot in seen or slot!=payload['slot_id'] or digest(payload)!=result['receipt_digest']:
                raise Rejected('EXPORT_RESULT_RECEIPT_CONTEXT_INVALID')
            seen.add(slot)
            receipt_checks.append({**verify_links(payload,snapshots[slot],audits[slot],accepted[slot],policy),'key_trust':evidence.get('key_trust',[])})
    return {'run_id':run['run_id'],'file_hashes_valid':True,'expected_context_checked':bool(expected),
            'uc_result_origin_and_integrity_verified':bool(checks),
            'uc_result_keys_trusted_for_provided_state':bool(checks) and all(row['current_signer_trust_verified'] for row in checks),
            'v41_checks':[row for row in receipt_checks if row.get('source_bindings_verified')],
            'business_metrics_recomputed':bool(run.get('evaluation_id')),
            'release_decision_verified':release_check['current_signer_trust_verified'],'release_decision':release['decision'],'uc_result_signatures_mathematically_valid':bool(checks),
            'uc_result_content_authenticated':bool(checks) and all(row['current_signer_trust_verified'] for row in checks),'receipt_signatures_mathematically_valid':bool(receipt_checks),
            'receipt_authenticity_verified':bool(receipt_checks) and all(check.get('uc_result_current_trust_verified',True) and all(row['current_status']!='REVOKED' for row in check.get('key_trust',[])) for check in receipt_checks), 'receipt_checks':receipt_checks,'result_checks':checks,
            'release_check':release_check,'scope':'UC statement authenticity and linkage; not public decryption, truth, completeness, or differential privacy proof'}

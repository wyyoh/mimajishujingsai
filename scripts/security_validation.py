"""Real lifecycle, storage, result and recovery tests in a disposable private runtime."""
import copy
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT_PATH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_PATH))
runtime = Path(tempfile.mkdtemp(prefix='grid-security-validation-', dir=str(Path.home())))
os.environ['GRID_RUNTIME'] = str(runtime)
os.environ['GRID_CUSTODY_PASSPHRASE'] = secrets.token_urlsafe(32)

from fastapi import HTTPException
from services import custody, management, trust
from services.agility import preflight
from services.encoding import Rejected, canonical, digest
from services.evidence import export_public, verify_export
from services.expansion_governance import prepare
from services.expansion_orchestrator import execute
from services.expansion_schemas import ExpansionRequest
from services.initialization import ROOT, RUNTIME
from services.native import utc, LIB
from services.sessions import ACCESS_PATH, COOKIE, initialize_access, login, principal
from services.storage import read, write
from services.versioning import source_version


def main():
    started, frozen = utc(), source_version()
    observations, runs = [], []
    def expect(label, function, codes=None):
        try:
            function()
        except (Rejected, HTTPException) as exc:
            code = getattr(exc, 'code', getattr(exc, 'detail', type(exc).__name__))
            if codes:
                assert code in codes, label+': '+str(code)
            observations.append({'case': label, 'status': 'REJECTED_AS_EXPECTED', 'code': code})
            return
        raise AssertionError(label+': operation unexpectedly accepted')

    @contextmanager
    def substituted(path, data):
        original = path.read_bytes()
        custody.atomic(path, data)
        try:
            yield
        finally:
            custody.atomic(path, original)

    def business():
        policy, _, _ = prepare(ExpansionRequest(source_count=2, scene_id='park', function='AVG', periods=[68], request_nonce=uuid.uuid4().hex), 'grid_operator_A')
        result = execute(policy)
        assert result['status'] == 'COMPLETED', str(result.get('errors'))
        assert result['oracle_match'] and result['role_file_isolation'] and result['uc_result_signatures_verified']
        archive = export_public(result['run_id'])
        checked = verify_export(archive, expected_context={'run_id': result['run_id'], 'function': 'AVG'})
        assert checked['receipt_authenticity_verified'] and checked['uc_result_origin_and_integrity_verified']
        runs.append(result['run_id'])
        return result, archive, checked

    first, first_archive, _ = business()
    initialize_access()
    credentials = read(ACCESS_PATH)['accounts']
    manager, approver = 'grid_key_manager', 'grid_security_approver'
    def operation(kind, target='', backup_password=None):
        requested = management.request(kind, target, 'Isolated development validation', manager, credentials[manager])
        management.approve(requested['request_id'], approver, credentials[approver])
        result = management.execute(requested['request_id'], manager, credentials[manager], backup_passphrase=backup_password)
        return requested['request_id'], result

    password = os.environ['GRID_CUSTODY_PASSPHRASE']
    custody._CACHE.clear()
    os.environ['GRID_CUSTODY_PASSPHRASE'] = secrets.token_urlsafe(32)
    try:
        expect('fresh_unlock_with_wrong_root_password', lambda: custody.load_root(RUNTIME), {'SM4_AUTHENTICATION_FAILED'})
    finally:
        os.environ['GRID_CUSTODY_PASSPHRASE'] = password
        custody._CACHE.clear()
    custody.load_root(RUNTIME)
    for subject in ('grid_operator_A', 'grid_auditor', approver):
        expect('non_manager_cannot_request_'+subject,
               lambda subject=subject: management.request('rotate-signing', '', 'Role check', subject, credentials[subject]),
               {'MANAGEMENT_AUTHORIZATION_DENIED'})

    paths = list(RUNTIME.glob('*/*.key'))
    assert paths and all(path.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----') for path in paths)
    private = RUNTIME / 'utility/pfdam.json'
    original = json.loads(private.read_text())
    assert original['object_type'] == 'GRID_PRIVATE_JSON_V1'
    altered = {**original, 'tag': '0'*32}
    with substituted(private, canonical(altered)):
        expect('private_ciphertext_tampering', lambda: read(private), {'SM4_AUTHENTICATION_FAILED'})
    with substituted(private, b'{"tampered":true}'):
        expect('plaintext_substitution', lambda: read(private), {'PRIVATE_STORAGE_PLAINTEXT_REJECTED'})
    with substituted(RUNTIME/'gateway/pfdam.json', private.read_bytes()):
        expect('cross_role_ciphertext_substitution', lambda: read(RUNTIME/'gateway/pfdam.json'), {'PRIVATE_STORAGE_CONTEXT_MISMATCH'})
    with custody.worker_environment(RUNTIME, 'gateway') as (environment, inherited):
        assert 'GRID_CUSTODY_PASSPHRASE' not in environment
        payload = json.loads(os.read(inherited[0], 4096))
    assert set(payload) == {'role','runtime','key','registry_pin','registry_version','registry_digest','program_pin'}
    assert payload['key'] != custody.role_key(RUNTIME, 'utility').hex()
    custody._WORKER = payload
    try:
        expect('gateway_cannot_unlock_uc_secret', lambda: read(private), {'ROLE_SECRET_ACCESS_DENIED'})
        expect('gateway_cannot_load_custody_root', lambda: custody.load_root(RUNTIME), {'ROLE_CANNOT_LOAD_CUSTODY_ROOT'})
    finally:
        custody._WORKER = None
    observations.append({'case': 'role_unlock_material_separation', 'status': 'PASS', 'global_unlock_inherited': False})

    pending = management.request('rotate-signing', '', 'Independent approval check', manager, credentials[manager])
    expect('manager_cannot_approve_own_request', lambda: management.approve(pending['request_id'], manager, credentials[manager]))
    expect('unapproved_execution', lambda: management.execute(pending['request_id'], manager, credentials[manager]))
    management.approve(pending['request_id'], approver, credentials[approver])
    before_rotation = (RUNTIME/'public/trust-registry.json').read_bytes()
    management.execute(pending['request_id'], manager, credentials[manager])
    expect('approval_replay', lambda: management.execute(pending['request_id'], manager, credentials[manager]))
    audit_snapshot = (RUNTIME/'security/admin-audit.json').read_bytes()
    expiry = management.request('rotate-signing', '', 'Expiry fixture check', manager, credentials[manager])
    operations_path = RUNTIME/'security/operations.json'
    operations = read(operations_path)
    operations[expiry['request_id']]['body']['expires_at'] = '2000-01-01T00:00:00Z'
    operations[expiry['request_id']]['body_digest'] = digest(operations[expiry['request_id']]['body'])
    with substituted(operations_path, custody.seal(operations_path, canonical(operations), RUNTIME)):
        expect('expired_approval_fixture', lambda: management.approve(expiry['request_id'], approver, credentials[approver]),
               {'MANAGEMENT_REQUEST_CHANGED_OR_EXPIRED'})
    second, second_archive, _ = business()
    assert trust.current_binding(RUNTIME)['key_epoch'] == 2
    assert verify_export(first_archive, expected_context={'run_id': first['run_id']})['receipt_authenticity_verified']
    observations.append({'case': 'real_rotation_and_historical_verification', 'status': 'PASS', 'new_epoch': 2})
    current_path = RUNTIME/'public/trust-registry.json'
    with substituted(current_path, before_rotation):
        expect('registry_rollback', lambda: trust.registry(RUNTIME), {'REGISTRY_ROLLBACK_OR_REPLACEMENT'})
    invalid = read(current_path)
    invalid['signatures'].pop('mldsa')
    with substituted(current_path, canonical(invalid)):
        expect('registry_dual_signature_required', lambda: trust.registry(RUNTIME), {'REGISTRY_REQUIRED_SIGNATURE_MISSING'})
    public_path = RUNTIME/'public/registry-root-ecdsa.pem'
    with substituted(public_path, (RUNTIME/'public/gateway-ecdsa-1.pem').read_bytes()):
        expect('registry_root_replacement', lambda: trust.registry(RUNTIME), {'REGISTRY_ROOT_PIN_MISMATCH'})

    with zipfile.ZipFile(second_archive) as package:
        entries = {name: package.read(name) for name in package.namelist()}
    modified = copy.deepcopy(entries)
    manifest = json.loads(modified['run_manifest.json'])
    result = manifest['results'][0]
    result['value_W'] += 7
    from services.governance import present_value
    result['published_value'] = present_value('AVG', result['value_W'], result['counts']['accepted'])
    modified['run_manifest.json'] = canonical(manifest)
    checksums = json.loads(modified['export_manifest.json'])
    checksums['files'] = {name: hashlib.sha256(raw).hexdigest() for name,raw in modified.items() if name != 'export_manifest.json'}
    modified['export_manifest.json'] = canonical(checksums)
    with tempfile.NamedTemporaryFile(suffix='.zip', dir=str(runtime), delete=False) as file:
        tampered_archive = Path(file.name)
    with zipfile.ZipFile(tampered_archive, 'w') as package:
        for name,raw in modified.items():
            package.writestr(name, raw)
    expect('plaintext_replacement_with_recomputed_checksums', lambda: verify_export(tampered_archive, expected_context={'run_id': second['run_id']}), {'UC_RESULT_STATEMENT_MISMATCH'})

    old_fingerprint = management.program_fingerprint
    try:
        management.program_fingerprint = lambda: '0'*96
        expect('unapproved_program', lambda: management.verify_program(), {'PROGRAM_APPROVAL_REQUIRED'})
        requested = management.request('approve-program', '0'*96, 'Injected review mismatch', manager, credentials[manager])
        management.approve(requested['request_id'], approver, credentials[approver])
        management.program_fingerprint = lambda: '1'*96
        expect('program_changed_after_approval', lambda: management.execute(requested['request_id'], manager, credentials[manager]), {'PROGRAM_CHANGED_SINCE_APPROVAL'})
    finally:
        management.program_fingerprint = old_fingerprint

    token = login('grid_operator_A', credentials['grid_operator_A'])
    browser = SimpleNamespace(cookies={COOKIE:token})
    assert principal(browser) == 'grid_operator_A'
    operation('disable-account', 'grid_operator_A')
    expect('disabled_account_session', lambda: principal(browser), {'LOCAL_OPERATOR_LOGIN_REQUIRED'})
    expect('disabled_account_login', lambda: login('grid_operator_A', credentials['grid_operator_A']), {'OPERATOR_CREDENTIALS_INVALID'})
    operation('enable-account', 'grid_operator_A')
    expect('old_session_after_reenable', lambda: principal(browser), {'LOCAL_OPERATOR_LOGIN_REQUIRED'})

    backup_password, backup_id = secrets.token_urlsafe(32), uuid.uuid4().hex
    operation('backup', backup_id, backup_password)
    expect('incorrect_backup_password', lambda: management.restore_material(backup_id, 'incorrect-backup-password'), {'SM4_AUTHENTICATION_FAILED'})
    backup_path = RUNTIME/'backups'/(backup_id+'.json')
    invalid_backup = json.loads(backup_path.read_text())
    invalid_backup['tag'] = '0'*32
    with substituted(backup_path, canonical(invalid_backup)):
        expect('backup_ciphertext_tampering', lambda: management.restore_material(backup_id, backup_password), {'SM4_AUTHENTICATION_FAILED'})
    active_key = trust.lookup(RUNTIME, 'utility', 'mldsa')[0]['key_id']
    operation('revoke-key', active_key)
    expect('revoked_business_key_no_downgrade', lambda: trust.current_binding(RUNTIME), {'BUSINESS_KEY_SET_INCOMPLETE'})
    revoked = verify_export(second_archive, expected_context={'run_id': second['run_id']})
    assert revoked['uc_result_origin_and_integrity_verified'] and not revoked['uc_result_keys_trusted_for_provided_state']
    assert revoked['historical_revocation_time_status'] == 'UNDETERMINED'
    operation('restore', backup_id, backup_password)
    expect('old_backup_cannot_reactivate_revoked_key', lambda: trust.current_binding(RUNTIME), {'BUSINESS_KEY_SET_INCOMPLETE'})
    entry = next(item for item in trust.registry(RUNTIME)['entries'] if item['key_id'] == active_key)
    removed = RUNTIME/entry['role']/entry['private_key']
    operation('destroy-key', active_key)
    assert not removed.exists()
    operation('restore', backup_id, backup_password)
    assert not removed.exists()
    assert verify_export(second_archive, expected_context={'run_id': second['run_id']})['uc_result_origin_and_integrity_verified']
    observations.append({'case':'logical_private_key_removal_and_old_backup_skip', 'status':'PASS', 'public_history_retained':True,
                         'physical_zeroization_claimed':False})
    operation('rotate-signing')
    operation('renew-tls', 'source-1')
    committed_version = custody.load_root(RUNTIME)['registry_version']
    save_root = custody.save_root
    def interrupted_commit(target, record):
        if record['registry_version'] > committed_version:
            raise Rejected('INJECTED_REGISTRY_ANCHOR_WRITE_FAILURE')
        return save_root(target, record)
    try:
        custody.save_root = interrupted_commit
        expect('real_registry_commit_interruption', lambda: operation('renew-tls', 'source-2'),
               {'INJECTED_REGISTRY_ANCHOR_WRITE_FAILURE'})
    finally:
        custody.save_root = save_root
    expect('incomplete_registry_blocks_new_business', lambda: trust.current_binding(RUNTIME), {'REGISTRY_COMMIT_INCOMPLETE'})
    operation('recover-registry')
    assert custody.load_root(RUNTIME)['registry_version'] == committed_version+1
    observations.append({'case':'approved_recovery_of_interrupted_registry_commit', 'status':'PASS', 'fault':'injected anchor write failure after signed registry persisted'})
    third, third_archive, _ = business()
    assert trust.current_binding(RUNTIME)['key_epoch'] == 3
    observations.append({'case': 'recovery_with_current_trust_and_renewed_tls', 'status': 'PASS', 'new_epoch': 3,
                         'renewed_source_epoch': trust.lookup(RUNTIME,'source-1','tls')[0]['epoch']})

    pin = custody.trust_pin(RUNTIME)
    public_runtime = runtime/'public-verifier'
    shutil.copytree(RUNTIME/'public', public_runtime/'public')
    checked = verify_export(third_archive, runtime=public_runtime, expected_context={'run_id': third['run_id']}, trusted_pin=pin)
    assert checked['receipt_authenticity_verified'] and checked['uc_result_origin_and_integrity_verified']
    with custody.public_trust(public_runtime, pin):
        expect('public_verifier_has_no_secret_access', lambda: custody.load_root(public_runtime), {'PUBLIC_VERIFIER_CANNOT_LOAD_SECRETS'})
    observations.append({'case': 'public_only_historical_verifier', 'status': 'PASS', 'secret_files_provisioned': False,
                         'authority_source': 'Separate explicit public pin, not the evidence archive'})
    write(public_runtime/'trusted-pin.json', pin)

    audit_path = RUNTIME/'security/admin-audit.json'
    with substituted(audit_path, audit_snapshot):
        expect('authenticated_old_audit_rollback', management.verify_audit, {'MANAGEMENT_AUDIT_ROLLBACK_OR_TRUNCATION'})
    audit_rows = read(audit_path)
    with substituted(audit_path, custody.seal(audit_path, canonical(audit_rows[:-1]), RUNTIME)):
        expect('authenticated_audit_truncation', management.verify_audit, {'MANAGEMENT_AUDIT_ROLLBACK_OR_TRUNCATION'})
    invalid_rows = copy.deepcopy(audit_rows)
    invalid_rows[-1]['actor'] = 'forged-actor'
    with substituted(audit_path, custody.seal(audit_path, canonical(invalid_rows), RUNTIME)):
        expect('audit_event_mac_tampering', management.verify_audit, {'MANAGEMENT_AUDIT_INVALID'})
    original_write = management.write
    def failed_audit_write(path, value, *args, **kwargs):
        if Path(path) == audit_path:
            raise Rejected('INJECTED_AUDIT_WRITE_FAILURE')
        return original_write(path, value, *args, **kwargs)
    try:
        management.write = failed_audit_write
        expect('audit_write_failure_stops_management_request',
               lambda: management.request('rotate-signing', '', 'Audit write fixture', manager, credentials[manager]),
               {'INJECTED_AUDIT_WRITE_FAILURE'})
    finally:
        management.write = original_write
    damaged = json.loads(audit_path.read_text())
    damaged['tag'] = '0'*32
    custody.atomic(audit_path, canonical(damaged))
    expect('audit_tampering_detected', management.verify_audit, {'SM4_AUTHENTICATION_FAILED'})
    expect('management_blocked_on_bad_audit', lambda: management.request('rotate-signing','', 'bad audit', manager, credentials[manager]), {'SM4_AUTHENTICATION_FAILED'})
    repaired = management.reanchor_audit(manager, credentials[manager], approver, credentials[approver])
    assert repaired['gap_explicit'] and management.verify_audit()['historical_gap_recorded']
    observations.append({'case': 'audit_recovery_preserves_damage_and_exposes_gap', 'status': 'PASS', 'history_reconstructed_claimed': False})
    import services.agility as agility
    original_sm3 = agility.sm3
    try:
        agility.sm3 = lambda value: '0'*64
        expect('application_preflight_failure', preflight, {'APPLICATION_CRYPTO_SELF_CHECK_FAILED'})
    finally:
        agility.sm3 = original_sm3
    assert source_version() == frozen
    record = {'schema': 'GRID_STANDARDS_REAL_SECURITY_VALIDATION_V1', 'started_at': started, 'finished_at': utc(), **frozen,
              'command': [sys.executable, 'scripts/security_validation.py'], 'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'versions': json.loads(LIB.grid_library_info()), 'inputs': {'dataset': 'SYN-WEEK-V42', 'nodes': 120, 'periods': [68], 'sources': 2, 'function': 'AVG'},
              'custody_backend': custody.load_root(RUNTIME)['backend'], 'private_runtime': str(runtime), 'public_run_ids': runs,
              'public_verifier_runtime': str(public_runtime), 'public_trust_pin_file':str(public_runtime/'trusted-pin.json'),
              'observations': observations, 'exit_code': 0, 'formal_evaluation': False,
              'scope': 'Fresh private same-host runtime, real crypto and task-boundary lifecycle; in-memory/fixture faults labelled; no physical device or human duty certification'}
    destination = ROOT/'artifacts/iterations/standards/security'/(started.replace(':','-')+'.json')
    write(destination, record)
    print(json.dumps({'record': str(destination.relative_to(ROOT)), 'observations': len(observations), 'run_ids': runs, 'exit_code': 0}))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

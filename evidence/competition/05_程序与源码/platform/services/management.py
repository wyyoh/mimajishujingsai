"""Small authenticated management workflow, separate from business authorization."""
import copy
import fcntl
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .custody import atomic, load_root, root_transaction, role_key
from .encoding import Rejected, canonical, digest
from .initialization import RUNTIME, ROOT
from .native import utc
from .storage import read, write

MANAGEMENT_ROLES = {'grid_key_manager': 'manager', 'grid_security_approver': 'approver', 'grid_auditor': 'auditor'}
OPERATIONS = {'rotate-signing', 'revoke-key', 'renew-tls', 'disable-account', 'enable-account', 'approve-program', 'recover-registry', 'backup', 'restore', 'destroy-key'}


def account_state(subject):
    path = RUNTIME / 'access-policy.json'
    state = read(path) if path.exists() else {'disabled': [], 'revisions': {}}
    return subject not in state['disabled'], state['revisions'].get(subject, 0)


def authenticate(subject, password, required_role):
    from .sessions import ACCESS_PATH, initialize_access
    initialize_access()
    accounts = read(ACCESS_PATH)['accounts']
    expected = accounts.get(subject, '')
    if (MANAGEMENT_ROLES.get(subject) != required_role or not account_state(subject)[0]
            or not isinstance(password, str) or not hmac.compare_digest(password.encode(), expected.encode())):
        raise Rejected('MANAGEMENT_AUTHORIZATION_DENIED')
    return subject


def _audit_rows(root):
    path = RUNTIME / 'security/admin-audit.json'
    rows = read(path) if path.exists() else []
    previous = '0'*64
    from .agility import sm3
    for index, row in enumerate(rows, 1):
        body = {key: value for key, value in row.items() if key != 'mac'}
        if body['sequence'] != index or body['previous_hash'] != previous or not hmac.compare_digest(row['mac'], hmac.digest(role_key(RUNTIME, 'admin'), canonical(body), 'sm3').hex()):
            raise Rejected('MANAGEMENT_AUDIT_INVALID')
        previous = sm3(canonical(row))
    if len(rows) != root['audit_count'] or previous != root['audit_head']:
        raise Rejected('MANAGEMENT_AUDIT_ROLLBACK_OR_TRUNCATION')
    return rows


def verify_audit():
    root = load_root(RUNTIME)
    rows = _audit_rows(root)
    return {'event_count': len(rows), 'head': root['audit_head'], 'integrity_verified': True,
            'historical_gap_recorded': bool(root.get('audit_gap')),
            'scope': 'Protected local management audit; OS account/coordinator trusted, not an independent public audit'}


def audit_event(actor, action, target, outcome, reference=None):
    from .agility import sm3
    with root_transaction(RUNTIME) as root:
        rows = _audit_rows(root)
        body = {'sequence': len(rows)+1, 'previous_hash': root['audit_head'], 'at': utc(), 'actor': actor,
                'action': action, 'target': target, 'outcome': outcome, 'reference': reference}
        row = {**body, 'mac': hmac.digest(role_key(RUNTIME, 'admin'), canonical(body), 'sm3').hex()}
        rows.append(row)
        write(RUNTIME / 'security/admin-audit.json', rows, True)
        root['audit_count'], root['audit_head'] = len(rows), sm3(canonical(row))
    return {'sequence': len(rows), 'event_hash': root['audit_head']}


def program_fingerprint():
    from .versioning import source_version
    version = source_version()
    scripts = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
               ('scripts/project', 'scripts/project.ps1', 'scripts/local_server.py', 'scripts/core_probe.py')}
    return digest({'core_source_digest': version['core_source_digest'], 'native_library_sha256': version['native_library_sha256'], 'entry_points': scripts})


def verify_program(bootstrap=False):
    actual = program_fingerprint()
    root = load_root(RUNTIME)
    if root['program_pin'] is None and bootstrap:
        with root_transaction(RUNTIME) as root:
            root['program_pin'] = actual
    elif root['program_pin'] != actual:
        raise Rejected('PROGRAM_APPROVAL_REQUIRED')
    return {'approved_fingerprint': actual, 'scope': 'Pinned application/native/entry-point integrity; not OS or module certification'}


def _requests():
    path = RUNTIME / 'security/operations.json'
    return read(path) if path.exists() else {}


def request(operation, target, reason, subject, password):
    authenticate(subject, password, 'manager')
    if operation not in OPERATIONS or len(target) > 128 or not 1 <= len(reason) <= 256:
        raise Rejected('MANAGEMENT_REQUEST_INVALID')
    if operation == 'approve-program' and target != program_fingerprint():
        raise Rejected('PROGRAM_REVIEW_FINGERPRINT_MISMATCH')
    verify_audit()
    now = datetime.now(timezone.utc)
    identifier = uuid.uuid4().hex
    body = {'operation': operation, 'target': target, 'reason': reason, 'requester': subject,
            'request_id': identifier, 'created_at': utc(), 'expires_at': (now+timedelta(minutes=10)).isoformat().replace('+00:00', 'Z')}
    with (RUNTIME / 'security/operations.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rows = _requests()
        rows[identifier] = {'body': body, 'body_digest': digest(body), 'state': 'REQUESTED', 'approver': None}
        write(RUNTIME / 'security/operations.json', rows, True)
    audit_event(subject, 'MANAGEMENT_REQUEST', operation, 'REQUESTED', digest(body))
    return {'request_id': identifier, 'operation': operation, 'target': target, 'state': 'REQUESTED', 'expires_at': body['expires_at']}


def _pending(rows, identifier):
    if identifier not in rows:
        raise Rejected('MANAGEMENT_REQUEST_UNKNOWN')
    row = rows[identifier]
    if row['body_digest'] != digest(row['body']) or datetime.now(timezone.utc) >= datetime.fromisoformat(row['body']['expires_at'].replace('Z', '+00:00')):
        raise Rejected('MANAGEMENT_REQUEST_CHANGED_OR_EXPIRED')
    return row


def approve(identifier, subject, password):
    authenticate(subject, password, 'approver')
    verify_audit()
    with (RUNTIME / 'security/operations.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rows = _requests()
        row = _pending(rows, identifier)
        if row['state'] != 'REQUESTED' or subject == row['body']['requester']:
            raise Rejected('INDEPENDENT_APPROVAL_REQUIRED')
        row.update(state='APPROVED', approver=subject)
        write(RUNTIME / 'security/operations.json', rows, True)
    audit_event(subject, 'MANAGEMENT_APPROVAL', row['body']['operation'], 'APPROVED', row['body_digest'])
    return {'request_id': identifier, 'state': 'APPROVED', 'requester': row['body']['requester'], 'approver': subject}


def execute(identifier, subject, password, *, backup_passphrase=None):
    authenticate(subject, password, 'manager')
    verify_audit()
    with (RUNTIME / 'execution.lock').open('a+') as execution, (RUNTIME / 'security/operations.lock').open('a+') as lock:
        # Drain active tasks, then atomically switch trust for future tasks.
        # This is a task-boundary update, not cancellation of already published results.
        fcntl.flock(execution, fcntl.LOCK_EX)
        fcntl.flock(lock, fcntl.LOCK_EX)
        rows = _requests()
        row = _pending(rows, identifier)
        if row['state'] != 'APPROVED' or row['body']['requester'] != subject or row['approver'] == subject:
            raise Rejected('INDEPENDENT_APPROVAL_REQUIRED')
        row['state'] = 'CONSUMED'
        write(RUNTIME / 'security/operations.json', rows, True)
        body = row['body']
        audit_event(subject, 'MANAGEMENT_EXECUTION', body['operation'], 'STARTED', row['body_digest'])
        try:
            from . import trust
            operation, target = body['operation'], body['target']
            if operation == 'rotate-signing':
                result = trust.rotate_business(RUNTIME)
            elif operation == 'revoke-key':
                result = trust.revoke(RUNTIME, target, body['reason'])
            elif operation == 'renew-tls':
                result = trust.renew_tls(RUNTIME, target)
            elif operation == 'recover-registry':
                result = trust.recover_commit(RUNTIME)
            elif operation == 'approve-program':
                if target != program_fingerprint():
                    raise Rejected('PROGRAM_CHANGED_SINCE_APPROVAL')
                with root_transaction(RUNTIME) as root:
                    root['program_pin'] = program_fingerprint()
                result = {'program_pin': root['program_pin']}
            elif operation == 'backup':
                result = backup_material(target, backup_passphrase)
            elif operation == 'restore':
                result = restore_material(target, backup_passphrase)
            elif operation == 'destroy-key':
                entries = copy.deepcopy(trust.registry(RUNTIME)['entries'])
                entry = next((entry for entry in entries if entry['key_id'] == target), None)
                if not entry or entry['status'] == 'ACTIVE':
                    raise Rejected('ACTIVE_OR_UNKNOWN_KEY_CANNOT_BE_REMOVED')
                private = (RUNTIME / entry['role'] / entry['private_key']).resolve()
                if not private.is_relative_to((RUNTIME / entry['role']).resolve()):
                    raise Rejected('PRIVATE_KEY_PATH_INVALID')
                private.unlink(missing_ok=True)
                entry['private_material_status'] = 'LOGICALLY_REMOVED_NOT_PROVEN_PHYSICAL_ZEROIZATION'
                result = trust.commit(RUNTIME, entries, 'INACTIVE_PRIVATE_KEY_REMOVAL')
            else:
                from .governance import SUBJECTS
                if target not in SUBJECTS:
                    raise Rejected('ACCOUNT_TARGET_NOT_BUSINESS_USER')
                path = RUNTIME / 'access-policy.json'
                policy = read(path) if path.exists() else {'disabled': [], 'revisions': {}}
                disabled = set(policy['disabled'])
                disabled.add(target) if operation == 'disable-account' else disabled.discard(target)
                policy['disabled'] = sorted(disabled)
                policy['revisions'][target] = policy['revisions'].get(target, 0)+1
                write(path, policy, True)
                result = {'subject': target, 'enabled': target not in disabled}
            row['state'] = 'COMPLETED'
        except Exception:
            row['state'] = 'FAILED'
            write(RUNTIME / 'security/operations.json', rows, True)
            audit_event(subject, 'MANAGEMENT_EXECUTION', body['operation'], 'FAILED', row['body_digest'])
            raise
        write(RUNTIME / 'security/operations.json', rows, True)
        audit_event(subject, 'MANAGEMENT_EXECUTION', body['operation'], 'COMPLETED', row['body_digest'])
    return {'request_id': identifier, 'state': 'COMPLETED', 'operation': body['operation'],
            'registry_version': result.get('version'), 'result': {key: result[key] for key in ('subject', 'enabled', 'program_pin', 'backup_id', 'restored_files') if key in result}}


def _backup_key(passphrase, salt):
    if not isinstance(passphrase, str) or len(passphrase) < 16:
        raise Rejected('BACKUP_PASSPHRASE_REQUIRED')
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=131072, r=8, p=1, maxmem=256*1024*1024, dklen=16)


def _backup_path(identifier):
    if len(identifier) != 32 or any(ch not in '0123456789abcdef' for ch in identifier):
        raise Rejected('BACKUP_ID_INVALID')
    return RUNTIME / 'backups' / (identifier+'.json')


def backup_material(identifier, passphrase):
    import base64
    from .agility import sm4_gcm
    from .trust import registry
    path = _backup_path(identifier)
    if path.exists():
        raise Rejected('BACKUP_ALREADY_EXISTS')
    root, registered = load_root(RUNTIME), registry(RUNTIME)
    files = {}
    for role in ('ta', 'utility', 'gateway', 'source', 'source-1', 'source-2', 'source-3'):
        directory = RUNTIME / role
        for item in [*directory.glob('*.key'), *directory.glob('pfdam.json')]:
            raw = item.read_bytes()
            if item.suffix == '.key' and not raw.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
                raise Rejected('UNPROTECTED_PRIVATE_KEY_IN_BACKUP')
            files[item.relative_to(RUNTIME).as_posix()] = base64.b64encode(raw).decode()
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = {'schema': 'GRID_PROTECTED_BACKUP_V1', 'backup_id': identifier, 'runtime_id': root['runtime_id'],
              'salt': salt.hex(), 'nonce': nonce.hex(), 'kdf': 'scrypt-N131072-r8-p1', 'cipher': 'SM4-GCM'}
    payload = {'role_keys': root['role_keys'], 'files': files, 'registry_version': registered['version'],
               'registry_digest': digest(registered), 'parameter_digest': hashlib.sha256((RUNTIME / 'public/parameters.json').read_bytes()).hexdigest(),
               'recovery_scope': 'Secret material only; independent current trust/custody state must survive. No historical state rollback.'}
    encrypted, tag = sm4_gcm(_backup_key(passphrase, salt), nonce, canonical(payload), canonical(header))
    atomic(path, canonical({**header, 'ciphertext': base64.b64encode(encrypted).decode(), 'tag': tag.hex()}))
    return {'backup_id': identifier}


def restore_material(identifier, passphrase):
    import base64
    from .agility import sm4_gcm
    from .encoding import loads
    from .trust import registry
    outer = loads(_backup_path(identifier).read_bytes())
    header = {key: value for key, value in outer.items() if key not in ('ciphertext', 'tag')}
    root = load_root(RUNTIME)
    if header.get('backup_id') != identifier or header.get('runtime_id') != root['runtime_id'] or header.get('schema') != 'GRID_PROTECTED_BACKUP_V1':
        raise Rejected('BACKUP_CONTEXT_MISMATCH')
    payload = loads(sm4_gcm(_backup_key(passphrase, bytes.fromhex(header['salt'])), bytes.fromhex(header['nonce']),
        base64.b64decode(outer['ciphertext'], validate=True), canonical(header), bytes.fromhex(outer['tag'])))
    registered = registry(RUNTIME)
    if (payload['role_keys'] != root['role_keys'] or payload['registry_version'] > registered['version']
            or payload['parameter_digest'] != hashlib.sha256((RUNTIME / 'public/parameters.json').read_bytes()).hexdigest()):
        raise Rejected('BACKUP_TRUST_OR_PARAMETER_MISMATCH')
    candidates = {}
    for name, data in payload['files'].items():
        path = RUNTIME / name
        parts = Path(name).parts
        if len(parts) != 2 or parts[0] not in root['role_keys'] or path.is_symlink() or not path.resolve().is_relative_to(RUNTIME.resolve()):
            raise Rejected('BACKUP_PATH_INVALID')
        raw = base64.b64decode(data, validate=True)
        if path.suffix != '.key' and path.name != 'pfdam.json' or path.suffix == '.key' and not raw.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
            raise Rejected('BACKUP_FILE_TYPE_INVALID')
        candidates[path] = raw
    for entry in registered['entries']:
        path = RUNTIME / entry['role'] / entry['private_key']
        if entry['status'] == 'ACTIVE' and not path.exists() and path not in candidates:
            raise Rejected('BACKUP_MISSING_ACTIVE_KEY')
    # Validate all candidate secrets before writing any of them. Keep current
    # registry, account state, audit anchors and custody counters untouched.
    import subprocess, tempfile
    from .custody import openssl_with_key, unseal
    for path, raw in list(candidates.items()):
        if path.suffix != '.key':
            unseal(path, loads(raw), RUNTIME)
            continue
        entry = next((row for row in registered['entries'] if row['role'] == path.parent.name and row['private_key'] == path.name), None)
        if entry and entry.get('private_material_status'):
            del candidates[path]
            continue
        if entry:
            public_path = RUNTIME / 'public' / entry['public_key']
            certificate = entry['algorithm'] == 'tls'
        elif path.parent.name == 'ta' and path.name in ('ca.key', 'registry-ecdsa.key', 'registry-mldsa.key'):
            public_path = RUNTIME / 'public' / ('ca.pem' if path.name == 'ca.key' else path.name.replace('registry-', 'registry-root-').replace('.key', '.pem'))
            certificate = path.name == 'ca.key'
        else:
            raise Rejected('BACKUP_KEY_PURPOSE_UNKNOWN')
        public_pem = subprocess.check_output(['openssl', 'x509', '-in', str(public_path), '-pubkey', '-noout']) if certificate else public_path.read_bytes()
        expected = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public_pem, capture_output=True, check=True).stdout
        descriptor, temporary = tempfile.mkstemp(prefix='.restore-encrypted-', suffix='.key', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
            actual = openssl_with_key(['pkey', '-in', temporary, '-pubout', '-outform', 'DER'], temporary)
            if actual != expected:
                raise Rejected('BACKUP_PRIVATE_PUBLIC_MISMATCH')
        finally:
            Path(temporary).unlink(missing_ok=True)
    for path, raw in candidates.items():
        atomic(path, raw)
    return {'backup_id': identifier, 'restored_files': len(candidates)}


def reanchor_audit(manager, manager_password, approver, approver_password):
    authenticate(manager, manager_password, 'manager')
    authenticate(approver, approver_password, 'approver')
    if manager == approver:
        raise Rejected('INDEPENDENT_APPROVAL_REQUIRED')
    try:
        verify_audit()
    except Rejected:
        pass
    else:
        raise Rejected('AUDIT_REANCHOR_NOT_NEEDED')
    from .agility import sm3
    with (RUNTIME / 'execution.lock').open('a+') as execution:
        fcntl.flock(execution, fcntl.LOCK_EX)
        with root_transaction(RUNTIME) as root:
            path = RUNTIME / 'security/admin-audit.json'
            raw = path.read_bytes() if path.exists() else b''
            damaged_hash = hashlib.sha256(raw).hexdigest()
            atomic(RUNTIME / 'security' / f'audit-damaged-{uuid.uuid4().hex}.json', raw)
            body = {'sequence': 1, 'previous_hash': '0'*64, 'at': utc(), 'actor': manager, 'approver': approver,
                    'action': 'AUDIT_REANCHORED_WITH_EXPLICIT_GAP', 'target': 'management_audit', 'outcome': 'RECOVERED_WITH_GAP',
                    'reference': damaged_hash, 'previous_audit_head': root['audit_head'], 'previous_audit_count': root['audit_count']}
            row = {**body, 'mac': hmac.digest(role_key(RUNTIME, 'admin'), canonical(body), 'sm3').hex()}
            write(path, [row], True)
            root.update(audit_count=1, audit_head=sm3(canonical(row)), audit_gap=True)
    return {'integrity_verified': True, 'previous_history_complete': False, 'gap_explicit': True}

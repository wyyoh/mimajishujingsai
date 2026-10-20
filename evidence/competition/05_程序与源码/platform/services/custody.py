"""Role-separated software custody; the coordinator and OS account are trusted."""
import base64
import ctypes
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from .encoding import Rejected, canonical, loads

ROLES = ('ta', 'utility', 'gateway', 'source', 'source-1', 'source-2', 'source-3', 'admin')
_CACHE, _WORKER = {}, None
_ROOT_LOCK = threading.RLock()
_PUBLIC_VERIFIER = ContextVar('grid_public_verifier', default=None)
DPAPI = Path('/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe')


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.protected-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def enabled(runtime):
    verifier = _PUBLIC_VERIFIER.get()
    if verifier is not None and verifier['runtime'] == str(Path(runtime).resolve()):
        return True
    if _WORKER is not None:
        return _WORKER['runtime'] == str(Path(runtime).resolve())
    return (Path(runtime) / 'security/custody.json').is_file()


def root_path(runtime):
    from .initialization import ROOT
    name = hashlib.sha256(str(Path(runtime).resolve()).encode()).hexdigest()[:24]
    path = Path(os.environ.get('GRID_CUSTODY_HOME', str(Path.home() / '.local/share/grid-custody'))) / name / 'root.json'
    if path.resolve().is_relative_to(Path(runtime).resolve()) or path.resolve().is_relative_to(ROOT.resolve()):
        raise Rejected('CUSTODY_ROOT_MUST_BE_SEPARATE')
    return path


def _dpapi(data, protect):
    method = 'Protect' if protect else 'Unprotect'
    script = ("$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; "
              "$b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); "
              f"$v=[System.Security.Cryptography.ProtectedData]::{method}($b,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser); "
              "[Console]::Write([Convert]::ToBase64String($v))")
    output = subprocess.run([str(DPAPI), '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(script.encode('utf-16le')).decode()],
                            input=base64.b64encode(data), capture_output=True, timeout=30)
    if output.returncode:
        raise Rejected('CUSTODY_OS_UNLOCK_FAILED')
    try:
        return base64.b64decode(output.stdout.strip(), validate=True)
    except ValueError as exc:
        raise Rejected('CUSTODY_OS_RESPONSE_INVALID') from exc


def _password_key(salt):
    password = os.environ.get('GRID_CUSTODY_PASSPHRASE', '')
    if len(password) < 16:
        raise Rejected('CUSTODY_UNLOCK_REQUIRED')
    return hashlib.scrypt(password.encode(), salt=salt, n=131072, r=8, p=1, maxmem=256*1024*1024, dklen=16)


def load_root(runtime, create=False):
    if _PUBLIC_VERIFIER.get() is not None:
        raise Rejected('PUBLIC_VERIFIER_CANNOT_LOAD_SECRETS')
    if _WORKER is not None:
        raise Rejected('ROLE_CANNOT_LOAD_CUSTODY_ROOT')
    path = root_path(runtime)
    if not path.exists():
        if not create or enabled(runtime):
            raise Rejected('CUSTODY_ROOT_UNAVAILABLE')
        mode = 'SCRYPT_SM4_GCM_V1' if os.environ.get('GRID_CUSTODY_PASSPHRASE') else 'DPAPI_CURRENT_USER_V1' if DPAPI.is_file() else None
        if mode is None:
            raise Rejected('CUSTODY_UNLOCK_REQUIRED')
        record = {'schema': 'GRID_CUSTODY_ROOT_V1', 'runtime_id': hashlib.sha256(str(Path(runtime).resolve()).encode()).hexdigest(),
                  'backend': mode, 'role_keys': {role: secrets.token_hex(32) for role in ROLES}, 'registry_pin': None,
                  'registry_version': 0, 'registry_digest': None, 'audit_head': '0'*64, 'audit_count': 0, 'program_pin': None}
        save_root(runtime, record)
        return record
    stamp = (path.stat().st_mtime_ns, path.stat().st_size)
    cached = _CACHE.get(str(path))
    if cached and cached[0] == stamp:
        return json.loads(json.dumps(cached[1]))
    outer = loads(path.read_bytes())
    from .agility import sm4_gcm
    try:
        if outer['backend'] == 'DPAPI_CURRENT_USER_V1':
            raw = _dpapi(base64.b64decode(outer['data'], validate=True), False)
        elif outer['backend'] == 'SCRYPT_SM4_GCM_V1':
            raw = sm4_gcm(_password_key(bytes.fromhex(outer['salt'])), bytes.fromhex(outer['nonce']), base64.b64decode(outer['data'], validate=True),
                          canonical({'backend': outer['backend'], 'salt': outer['salt']}), bytes.fromhex(outer['tag']))
        else:
            raise Rejected('CUSTODY_BACKEND_UNSUPPORTED')
        record = loads(raw)
        if record['runtime_id'] != hashlib.sha256(str(Path(runtime).resolve()).encode()).hexdigest() or record['backend'] != outer['backend']:
            raise Rejected('CUSTODY_RUNTIME_MISMATCH')
    except Rejected:
        raise
    except (KeyError, ValueError, TypeError) as exc:
        raise Rejected('CUSTODY_ROOT_INVALID') from exc
    _CACHE[str(path)] = (stamp, record)
    return json.loads(json.dumps(record))


def save_root(runtime, record):
    from .agility import sm4_gcm
    mode, raw = record['backend'], canonical(record)
    if mode == 'DPAPI_CURRENT_USER_V1':
        outer = {'backend': mode, 'data': base64.b64encode(_dpapi(raw, True)).decode()}
    elif mode == 'SCRYPT_SM4_GCM_V1':
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        aad = {'backend': mode, 'salt': salt.hex()}
        encrypted, tag = sm4_gcm(_password_key(salt), nonce, raw, canonical(aad))
        outer = {**aad, 'nonce': nonce.hex(), 'data': base64.b64encode(encrypted).decode(), 'tag': tag.hex()}
    else:
        raise Rejected('CUSTODY_BACKEND_UNSUPPORTED')
    path = root_path(runtime)
    atomic(path, canonical(outer))
    _CACHE[str(path)] = ((path.stat().st_mtime_ns, path.stat().st_size), json.loads(json.dumps(record)))


@contextmanager
def root_transaction(runtime):
    path = root_path(runtime)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _ROOT_LOCK, (path.parent / 'root.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record = load_root(runtime)
        yield record
        save_root(runtime, record)


def role_for(path, runtime):
    try:
        relative = Path(path).resolve().relative_to(Path(runtime).resolve())
    except ValueError:
        return None
    if relative.parts[0] in ROLES:
        return relative.parts[0]
    if relative.parts[0] == 'runs' and len(relative.parts) >= 4 and relative.parts[2] in ROLES:
        return relative.parts[2]
    if relative.name in ('operator-access.json', 'access-policy.json') or relative.parts[0] == 'security':
        return 'admin'
    return None


def role_key(runtime, role):
    if _WORKER is not None:
        if _WORKER['role'] != role or _WORKER['runtime'] != str(Path(runtime).resolve()):
            raise Rejected('ROLE_SECRET_ACCESS_DENIED')
        return bytes.fromhex(_WORKER['key'])
    return bytes.fromhex(load_root(runtime)['role_keys'][role])


def trust_pin(runtime):
    verifier = _PUBLIC_VERIFIER.get()
    if verifier is not None:
        if verifier['runtime'] != str(Path(runtime).resolve()):
            raise Rejected('PUBLIC_VERIFIER_CONTEXT_INVALID')
        return verifier['pin']
    value = _WORKER if _WORKER is not None else load_root(runtime)
    return {key: value[key] for key in ('registry_pin', 'registry_version', 'registry_digest', 'program_pin')}


@contextmanager
def public_trust(runtime, pin):
    fields = {'registry_pin', 'registry_version', 'registry_digest', 'program_pin'}
    if not isinstance(pin, dict) or set(pin) != fields or type(pin['registry_version']) is not int or pin['registry_version'] < 1:
        raise Rejected('PUBLIC_TRUST_PIN_INVALID')
    token = _PUBLIC_VERIFIER.set({'runtime': str(Path(runtime).resolve()), 'pin': dict(pin)})
    try:
        yield
    finally:
        _PUBLIC_VERIFIER.reset(token)


def _derive(key, salt, info):
    # RFC 5869 extract/expand, SHA-256, one block, L=16.
    return hmac.digest(hmac.digest(salt, key, 'sha256'), info+b'\x01', 'sha256')[:16]


def seal(path, raw, runtime):
    from .agility import sm4_gcm
    role = role_for(path, runtime)
    if role is None:
        raise Rejected('PRIVATE_STORAGE_ROLE_UNKNOWN')
    header = {'object_type': 'GRID_PRIVATE_JSON_V1', 'role': role, 'path': Path(path).resolve().relative_to(Path(runtime).resolve()).as_posix(),
              'salt': secrets.token_hex(32), 'nonce': secrets.token_hex(12), 'kdf': 'HKDF-SHA256', 'cipher': 'SM4-GCM'}
    key = _derive(role_key(runtime, role), bytes.fromhex(header['salt']), canonical({'domain': 'GRID-STORAGE-V1', 'role': role, 'path': header['path']}))
    ciphertext, tag = sm4_gcm(key, bytes.fromhex(header['nonce']), raw, canonical(header))
    return canonical({**header, 'ciphertext': base64.b64encode(ciphertext).decode(), 'tag': tag.hex()})


def unseal(path, value, runtime):
    from .agility import sm4_gcm
    fields = {'object_type', 'role', 'path', 'salt', 'nonce', 'kdf', 'cipher', 'ciphertext', 'tag'}
    if set(value) != fields or value['kdf'] != 'HKDF-SHA256' or value['cipher'] != 'SM4-GCM':
        raise Rejected('PRIVATE_STORAGE_FORMAT_INVALID')
    header = {key: value[key] for key in fields - {'ciphertext', 'tag'}}
    if value['role'] != role_for(path, runtime) or value['path'] != Path(path).resolve().relative_to(Path(runtime).resolve()).as_posix():
        raise Rejected('PRIVATE_STORAGE_CONTEXT_MISMATCH')
    try:
        key = _derive(role_key(runtime, value['role']), bytes.fromhex(value['salt']), canonical({'domain': 'GRID-STORAGE-V1', 'role': value['role'], 'path': value['path']}))
        return loads(sm4_gcm(key, bytes.fromhex(value['nonce']), base64.b64decode(value['ciphertext'], validate=True), canonical(header), bytes.fromhex(value['tag'])))
    except Rejected:
        raise
    except (ValueError, TypeError) as exc:
        raise Rejected('PRIVATE_STORAGE_FORMAT_INVALID') from exc


def encode_private(path, value, private, runtime=None):
    if runtime is None:
        from .initialization import RUNTIME as runtime
    raw = canonical(value)
    return seal(path, raw, runtime) if enabled(runtime) and role_for(path, runtime) is not None and (private or Path(path).suffix == '.json') else raw


def decode_private(path, value, runtime=None):
    if runtime is None:
        from .initialization import RUNTIME as runtime
    if isinstance(value, dict) and value.get('object_type') == 'GRID_PRIVATE_JSON_V1':
        return unseal(path, value, runtime)
    critical = Path(path).name in ('pfdam.json', 'dataset.json', 'authorization.json', 'published.json', 'operator-access.json', 'access-policy.json')
    if critical and enabled(runtime) and role_for(path, runtime) is not None:
        state = loads((Path(runtime) / 'security/custody.json').read_bytes()) if _WORKER is None else {'ready': True}
        if state['ready']:
            raise Rejected('PRIVATE_STORAGE_PLAINTEXT_REJECTED')
    return value


def pem_password(path):
    from .initialization import RUNTIME
    path = Path(path)
    if path.is_file() and path.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
        role = role_for(path, RUNTIME)
        if role is None:
            raise Rejected('PRIVATE_KEY_ROLE_UNKNOWN')
        return role_key(RUNTIME, role).hex().encode()
    return None


def openssl_with_key(arguments, path):
    password = pem_password(path)
    command = ['openssl', *map(str, arguments)]
    if password is not None:
        command.extend(('-passin', 'stdin'))
    output = subprocess.run(command, input=password+b'\n' if password is not None else None, capture_output=True, timeout=30)
    if output.returncode:
        raise Rejected('PRIVATE_KEY_INSPECTION_FAILED')
    return output.stdout


@contextmanager
def native_password(path):
    from .native import LIB
    LIB.grid_set_password.argtypes = [ctypes.c_char_p]
    LIB.grid_set_password(pem_password(path))
    try:
        yield
    finally:
        LIB.grid_set_password(None)


def protect_existing(runtime):
    runtime = Path(runtime)
    for role in ROLES:
        directory = runtime / role
        if not directory.is_dir():
            continue
        for path in directory.glob('*.key'):
            if not path.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
                output = subprocess.run(['openssl', 'pkey', '-in', str(path), '-aes-256-cbc', '-passout', 'stdin'],
                                        input=role_key(runtime, role).hex().encode()+b'\n', capture_output=True, timeout=30)
                if output.returncode or not output.stdout.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
                    raise Rejected('PRIVATE_KEY_PROTECTION_FAILED')
                atomic(path, output.stdout)
        for path in directory.glob('*.json'):
            value = loads(path.read_bytes())
            if value.get('object_type') != 'GRID_PRIVATE_JSON_V1':
                atomic(path, seal(path, canonical(value), runtime))
    for name in ('operator-access.json', 'access-policy.json'):
        path = runtime / name
        if path.is_file():
            value = loads(path.read_bytes())
            if value.get('object_type') != 'GRID_PRIVATE_JSON_V1':
                atomic(path, seal(path, canonical(value), runtime))


def enable(runtime):
    runtime = Path(runtime)
    load_root(runtime, create=not enabled(runtime))
    atomic(runtime / 'security/custody.json', canonical({'schema': 'GRID_CUSTODY_STATE_V1', 'ready': False}))
    protect_existing(runtime)
    atomic(runtime / 'security/custody.json', canonical({'schema': 'GRID_CUSTODY_STATE_V1', 'ready': True}))


@contextmanager
def worker_environment(runtime, role):
    environment = {key: value for key, value in os.environ.items() if key not in ('GRID_CUSTODY_PASSPHRASE', 'GRID_ROLE_KEY_FD') and not key.startswith('GRID_ADMIN_')}
    if not enabled(runtime):
        yield environment, ()
        return
    payload = {'role': role, 'runtime': str(Path(runtime).resolve()), 'key': role_key(runtime, role).hex(), **trust_pin(runtime)}
    reader, writer = os.pipe()
    try:
        os.write(writer, canonical(payload))
        os.close(writer)
        writer = -1
        environment['GRID_ROLE_KEY_FD'] = str(reader)
        yield environment, (reader,)
    finally:
        os.close(reader)
        if writer >= 0:
            os.close(writer)


def activate_worker(runtime, role):
    global _WORKER
    descriptor = os.environ.pop('GRID_ROLE_KEY_FD', None)
    if enabled(runtime):
        if descriptor is None:
            raise Rejected('ROLE_UNLOCK_REQUIRED')
        with os.fdopen(int(descriptor), 'rb') as stream:
            value = loads(stream.read(4096))
        if value['role'] != role or value['runtime'] != str(Path(runtime).resolve()) or len(bytes.fromhex(value['key'])) != 32:
            raise Rejected('ROLE_UNLOCK_CONTEXT_INVALID')
        _WORKER = value
        from .management import program_fingerprint
        if value['program_pin'] != program_fingerprint():
            raise Rejected('WORKER_PROGRAM_INTEGRITY_MISMATCH')
        from .agility import preflight
        preflight()

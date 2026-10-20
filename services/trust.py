"""Signed, pinned key registry with separate current-use and history semantics."""
import copy
import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from . import native
from .custody import atomic, load_root, protect_existing, save_root, trust_pin, root_transaction
from .encoding import Rejected, b64, canonical, digest, loads, unb64
from .initialization import command

ROOT_DOMAIN = 'GRID-TRUST-REGISTRY-V1'
SIGN_ALGS = ('ecdsa', 'mldsa', 'sm2')
SAFE_NAME = re.compile(r'^[A-Za-z0-9_-]+\.(pem|key)$')


def _root_public(runtime):
    return {alg: (Path(runtime) / 'public' / f'registry-root-{alg}.pem').read_text() for alg in ('ecdsa', 'mldsa')}


def _verify_registry(runtime, envelope):
    pin = trust_pin(runtime)
    if not pin['registry_pin'] or digest(_root_public(runtime)) != pin['registry_pin']:
        raise Rejected('REGISTRY_ROOT_PIN_MISMATCH')
    if set(envelope) != {'payload', 'signatures'}:
        raise Rejected('REGISTRY_FORMAT_INVALID')
    body = envelope['payload']
    if body.get('object_type') != 'GRID_TRUST_REGISTRY_V1' or type(body.get('version')) is not int or body['version'] < 1:
        raise Rejected('REGISTRY_FORMAT_INVALID')
    if set(envelope['signatures']) != {'ecdsa', 'mldsa'}:
        raise Rejected('REGISTRY_REQUIRED_SIGNATURE_MISSING')
    for alg in ('ecdsa', 'mldsa'):
        if not native.verify(Path(runtime) / 'public' / f'registry-root-{alg}.pem', canonical(body), ROOT_DOMAIN, unb64(envelope['signatures'][alg]), alg == 'mldsa'):
            raise Rejected('REGISTRY_SIGNATURE_INVALID')
    ids = set()
    for entry in body['entries']:
        if (entry['key_id'] in ids or not SAFE_NAME.fullmatch(entry['public_key']) or not SAFE_NAME.fullmatch(entry['private_key'])
                or entry['status'] not in ('ACTIVE', 'RETIRED', 'REVOKED') or type(entry['epoch']) is not int or entry['epoch'] < 1
                or entry['role'] not in ('utility','gateway','source','source-1','source-2','source-3')
                or entry['algorithm'] not in (*SIGN_ALGS, 'tls') or entry['key_id'] != f"{entry['role']}-{entry['algorithm']}-{entry['epoch']}"):
            raise Rejected('REGISTRY_ENTRY_INVALID')
        ids.add(entry['key_id'])
        public = Path(runtime) / 'public' / entry['public_key']
        if hashlib.sha256(public.read_bytes()).hexdigest() != entry['public_sha256']:
            raise Rejected('REGISTRY_PUBLIC_KEY_REPLACED')
    return body


def registry(runtime, historical_digest=None):
    runtime = Path(runtime)
    pin = trust_pin(runtime)
    current = loads((runtime / 'public/trust-registry.json').read_bytes())
    body = _verify_registry(runtime, current)
    if body['version'] < pin['registry_version'] or body['version'] == pin['registry_version'] and digest(body) != pin['registry_digest']:
        raise Rejected('REGISTRY_ROLLBACK_OR_REPLACEMENT')
    # A child has a pinned floor and may observe a newer legitimately signed
    # registry. The management coordinator requires its exact committed state.
    from .custody import _WORKER
    if _WORKER is None and (body['version'] != pin['registry_version'] or digest(body) != pin['registry_digest']):
        raise Rejected('REGISTRY_COMMIT_INCOMPLETE')
    if historical_digest is None or historical_digest == digest(body):
        return body
    if not re.fullmatch(r'[0-9a-f]{96}', historical_digest):
        raise Rejected('REGISTRY_HISTORY_ID_INVALID')
    historical = loads((runtime / 'public/trust-history' / f'{historical_digest}.json').read_bytes())
    value = _verify_registry(runtime, historical)
    if digest(value) != historical_digest or value['version'] > body['version']:
        raise Rejected('REGISTRY_HISTORY_INVALID')
    return value


def lookup(runtime, role, algorithm, *, key_id=None, epoch=None, usage='current', registry_digest=None):
    current = registry(runtime)
    body = registry(runtime, registry_digest) if registry_digest else current
    candidates = [row for row in body['entries'] if row['role'] == role and row['algorithm'] == algorithm
                  and (key_id is None or row['key_id'] == key_id) and (epoch is None or row['epoch'] == epoch)]
    if len(candidates) != 1 and key_id is not None:
        raise Rejected('UNTRUSTED_SIGNATURE_KEY')
    if key_id is None:
        candidates = [row for row in candidates if row['status'] == 'ACTIVE']
    if len(candidates) != 1:
        raise Rejected('ACTIVE_KEY_UNAVAILABLE')
    entry = copy.deepcopy(candidates[0])
    live = next((row for row in current['entries'] if row['key_id'] == entry['key_id']), None)
    if live is None:
        raise Rejected('UNTRUSTED_SIGNATURE_KEY')
    now = native.utc()
    if usage == 'current' and (live['status'] != 'ACTIVE' or entry['status'] != 'ACTIVE' or not entry['not_before'] <= now < entry['not_after']):
        raise Rejected('KEY_RETIRED_REVOKED_OR_EXPIRED')
    if usage not in ('current', 'history'):
        raise Rejected('KEY_USAGE_INVALID')
    entry['current_status'] = live['status']
    entry['historical_time_trust'] = 'UNDETERMINED_WITHOUT_TRUSTED_SIGNING_TIME' if live['status'] == 'REVOKED' else 'NO_INDEPENDENT_SIGNING_TIME'
    return entry, Path(runtime) / 'public' / entry['public_key']


def current_binding(runtime):
    body = registry(runtime)
    active = [row for row in body['entries'] if row['role'] in ('utility', 'gateway') and row['algorithm'] in SIGN_ALGS and row['status'] == 'ACTIVE']
    epochs = {row['epoch'] for row in active}
    if len(active) != 6 or len(epochs) != 1:
        raise Rejected('BUSINESS_KEY_SET_INCOMPLETE')
    for row in active:
        lookup(runtime, row['role'], row['algorithm'], key_id=row['key_id'])
    return {'key_epoch': next(iter(epochs)), 'trust_registry_digest': digest(body)}


def _entry(runtime, role, algorithm, epoch, private, public):
    now = datetime.now(timezone.utc)
    fmt = lambda value: value.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    return {'key_id': f'{role}-{algorithm}-{epoch}', 'role': role, 'algorithm': algorithm, 'epoch': epoch,
            'private_key': private, 'public_key': public, 'public_sha256': hashlib.sha256((Path(runtime) / 'public' / public).read_bytes()).hexdigest(),
            'status': 'ACTIVE', 'not_before': fmt(now-timedelta(seconds=1)), 'not_after': fmt(now+timedelta(days=30)),
            'revoked_at': None, 'revocation_reason': None}


def commit(runtime, entries, operation):
    runtime = Path(runtime)
    with root_transaction(runtime) as root:
        body = {'object_type': 'GRID_TRUST_REGISTRY_V1', 'version': root['registry_version']+1,
                'previous_digest': root['registry_digest'], 'issued_at': native.utc(), 'operation': operation, 'entries': entries}
        signatures = {alg: b64(native.sign(runtime / 'ta' / f'registry-{alg}.key', canonical(body), ROOT_DOMAIN, alg == 'mldsa')) for alg in ('ecdsa', 'mldsa')}
        envelope = {'payload': body, 'signatures': signatures}
        _verify_registry(runtime, envelope)
        history = runtime / 'public/trust-history' / (digest(body)+'.json')
        if history.exists() and history.read_bytes() != canonical(envelope):
            raise Rejected('REGISTRY_HISTORY_ALREADY_EXISTS')
        atomic(runtime / 'security/pending-registry.json', canonical(envelope))
        atomic(history, canonical(envelope))
        atomic(runtime / 'public/trust-registry.json', canonical(envelope))
        root['registry_version'], root['registry_digest'] = body['version'], digest(body)
    (runtime / 'security/pending-registry.json').unlink()
    return body


def initialize(runtime):
    runtime = Path(runtime)
    root = load_root(runtime)
    if root['registry_pin']:
        return registry(runtime)
    for alg, options in (('ecdsa', ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1']), ('mldsa', ['-algorithm', 'ML-DSA-65'])):
        secret, public = runtime / 'ta' / f'registry-{alg}.key', runtime / 'public' / f'registry-root-{alg}.pem'
        if not secret.exists():
            command('openssl', 'genpkey', *options, '-out', secret)
        command('openssl', 'pkey', '-in', secret, '-pubout', '-out', public)
    protect_existing(runtime)
    with root_transaction(runtime) as root:
        root['registry_pin'] = digest(_root_public(runtime))
    legacy = loads((runtime / 'public/key_registry.json').read_bytes())
    entries = [_entry(runtime, role, alg, 1, f'{alg}.key', legacy[role][alg]['public_key']) for role in ('utility', 'gateway') for alg in SIGN_ALGS]
    for role in ('source', 'utility', 'gateway'):
        public = f'{role}-tls-1.pem'
        atomic(runtime / 'public' / public, (runtime / role / 'tls.pem').read_bytes())
        entries.append(_entry(runtime, role, 'tls', 1, 'tls.key', public))
    return commit(runtime, entries, 'INITIAL_ENROLLMENT')


def enroll_sources(runtime):
    runtime = Path(runtime)
    body = registry(runtime)
    entries = copy.deepcopy(body['entries'])
    for role in ('source-1', 'source-2', 'source-3'):
        if any(row['role'] == role and row['algorithm'] == 'tls' for row in entries):
            continue
        public = f'{role}-tls-1.pem'
        atomic(runtime / 'public' / public, (runtime / role / 'tls.pem').read_bytes())
        entries.append(_entry(runtime, role, 'tls', 1, 'tls.key', public))
    return commit(runtime, entries, 'SOURCE_ENROLLMENT') if entries != body['entries'] else body


def check_peer(runtime, role, fingerprint):
    import ssl
    entry, path = lookup(runtime, role, 'tls')
    expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest()
    if fingerprint != expected:
        raise Rejected('TLS_PEER_NOT_CURRENTLY_REGISTERED')
    return entry


def rotate_business(runtime):
    runtime = Path(runtime)
    entries = copy.deepcopy(registry(runtime)['entries'])
    epoch = max(row['epoch'] for row in entries if row['algorithm'] in SIGN_ALGS)+1
    for row in entries:
        if row['algorithm'] in SIGN_ALGS and row['status'] == 'ACTIVE':
            row['status'] = 'RETIRED'
    for role in ('utility', 'gateway'):
        for alg, options in (('ecdsa', ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1']), ('mldsa', ['-algorithm', 'ML-DSA-65']), ('sm2', ['-algorithm', 'SM2'])):
            secret, public = f'{alg}-{epoch}.key', f'{role}-{alg}-{epoch}.pem'
            if (runtime / role / secret).exists() or (runtime / 'public' / public).exists():
                raise Rejected('KEY_ROTATION_PARTIAL_STATE')
            command('openssl', 'genpkey', *options, '-out', runtime / role / secret)
            command('openssl', 'pkey', '-in', runtime / role / secret, '-pubout', '-out', runtime / 'public' / public)
            entries.append(_entry(runtime, role, alg, epoch, secret, public))
    protect_existing(runtime)
    return commit(runtime, entries, 'BUSINESS_SIGNING_KEY_ROTATION')


def revoke(runtime, key_id, reason):
    entries = copy.deepcopy(registry(runtime)['entries'])
    found = False
    for entry in entries:
        if entry['key_id'] == key_id:
            if entry['status'] == 'REVOKED':
                raise Rejected('KEY_ALREADY_REVOKED')
            entry.update(status='REVOKED', revoked_at=native.utc(), revocation_reason=reason)
            found = True
    if not found:
        raise Rejected('UNTRUSTED_SIGNATURE_KEY')
    return commit(runtime, entries, 'KEY_REVOCATION')


def renew_tls(runtime, role):
    runtime = Path(runtime)
    entries = copy.deepcopy(registry(runtime)['entries'])
    previous = [row for row in entries if row['role'] == role and row['algorithm'] == 'tls']
    if not previous:
        raise Rejected('TLS_ROLE_UNREGISTERED')
    epoch = max(row['epoch'] for row in previous)+1
    secret, public = f'tls-{epoch}.key', f'{role}-tls-{epoch}.pem'
    if (runtime / role / secret).exists() or (runtime / 'public' / public).exists():
        raise Rejected('TLS_ROTATION_PARTIAL_STATE')
    command('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', runtime / role / secret)
    command('openssl', 'req', '-new', '-key', runtime / role / secret, '-out', runtime / role / f'tls-{epoch}.csr', '-subj', f'/CN={role}.grid')
    extension = runtime / role / f'tls-{epoch}.ext'
    atomic(extension, f'subjectAltName=DNS:{role}.grid\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n'.encode())
    command('openssl', 'x509', '-req', '-in', runtime / role / f'tls-{epoch}.csr', '-CA', runtime / 'public/ca.pem', '-CAkey', runtime / 'ta/ca.key',
            '-CAcreateserial', '-out', runtime / 'public' / public, '-days', '14', '-extfile', extension)
    protect_existing(runtime)
    for row in entries:
        if row['role'] == role and row['algorithm'] == 'tls' and row['status'] == 'ACTIVE':
            row['status'] = 'RETIRED'
    entries.append(_entry(runtime, role, 'tls', epoch, secret, public))
    return commit(runtime, entries, 'TLS_IDENTITY_RENEWAL')


def recover_commit(runtime):
    runtime = Path(runtime)
    envelope = loads((runtime / 'security/pending-registry.json').read_bytes())
    body = _verify_registry(runtime, envelope)
    with root_transaction(runtime) as root:
        if body['version'] == root['registry_version'] and digest(body) == root['registry_digest']:
            pass
        elif body['version'] == root['registry_version']+1 and body['previous_digest'] == root['registry_digest']:
            atomic(runtime / 'public/trust-history' / (digest(body)+'.json'), canonical(envelope))
            atomic(runtime / 'public/trust-registry.json', canonical(envelope))
            root['registry_version'], root['registry_digest'] = body['version'], digest(body)
        else:
            raise Rejected('REGISTRY_RECOVERY_CONTEXT_INVALID')
    (runtime / 'security/pending-registry.json').unlink()
    return registry(runtime)

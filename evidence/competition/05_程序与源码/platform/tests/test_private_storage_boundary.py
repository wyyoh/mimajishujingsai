"""A large private envelope must not relax public or decrypted JSON caps."""
import secrets
import uuid

import pytest

from services.encoding import MAX_OBJECT_BYTES, Rejected, canonical, loads
from services.storage import MAX_PRIVATE_ENVELOPE_BYTES, read, write


def test_private_envelope_expansion_and_unchanged_public_limit(tmp_path, monkeypatch):
    from services.custody import enable
    from tests.provenance import observe

    runtime = tmp_path / uuid.uuid4().hex
    monkeypatch.setenv('GRID_CUSTODY_PASSPHRASE', secrets.token_urlsafe(32))
    enable(runtime)
    value = {'bounded_payload': 'x' * (13 * 1024 * 1024)}
    path = runtime / 'runs' / uuid.uuid4().hex / 'utility' / 'published.json'
    write(path, value, True, runtime=runtime)
    assert MAX_OBJECT_BYTES < path.stat().st_size < MAX_PRIVATE_ENVELOPE_BYTES
    assert read(path, runtime=runtime) == value
    # An envelope at a public/unclassified path still uses the public limit.
    public = runtime / 'public' / 'oversized.json'
    public.parent.mkdir(exist_ok=True)
    public.write_bytes(path.read_bytes())
    with pytest.raises(Rejected, match='OBJECT_TOO_LARGE'):
        read(public, runtime=runtime)
    with pytest.raises(Rejected, match='OBJECT_TOO_LARGE'):
        loads(path.read_bytes())
    # Private-path classification is insufficient for oversized plaintext.
    path.write_bytes(canonical({'plaintext': 'x' * MAX_OBJECT_BYTES}))
    with pytest.raises(Rejected, match='OBJECT_TOO_LARGE'):
        read(path, runtime=runtime)
    path.write_bytes(b' ' * (MAX_PRIVATE_ENVELOPE_BYTES + 1))
    with pytest.raises(Rejected, match='OBJECT_TOO_LARGE'):
        read(path, runtime=runtime)
    with pytest.raises(Rejected, match='SM4_INPUT_TOO_LARGE'):
        write(path, {'plaintext': 'x' * MAX_OBJECT_BYTES}, True, runtime=runtime)
    observe('private_envelope_base64_boundary', {
        'plaintext_bytes_tested': len(canonical(value)),
        'public_json_limit_bytes': MAX_OBJECT_BYTES,
        'private_envelope_limit_bytes': MAX_PRIVATE_ENVELOPE_BYTES,
        'private_roundtrip': True, 'public_plaintext_and_cipher_limits_unchanged': True,
    })

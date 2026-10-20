import json
import os
import tempfile
import time
from pathlib import Path

from .encoding import MAX_OBJECT_BYTES, Rejected, canonical, loads
from .native import utc

# SM4-GCM preserves plaintext length, while its at-rest JSON envelope uses
# Base64. This bound accommodates the existing 16 MiB plaintext cap plus a
# small authenticated header. It does not change API, wire or plaintext caps.
MAX_PRIVATE_ENVELOPE_BYTES = 4 * ((MAX_OBJECT_BYTES + 2) // 3) + 4096


def read(path, *, runtime=None):
    path = Path(path)
    from .custody import decode_private, enabled, role_for
    if runtime is None:
        from .initialization import RUNTIME as runtime
    protected = enabled(runtime) and role_for(path, runtime) is not None
    limit = MAX_PRIVATE_ENVELOPE_BYTES if protected else MAX_OBJECT_BYTES
    # DrvFS can expose a brief absent-name interval during os.replace even
    # though a concurrent writer uses a temporary file. Never return stale
    # data or retry parse/signature failures; a persistent absence still fails.
    for attempt in range(5):
        try:
            # Bound the disk read before parsing, including untrusted files.
            with path.open('rb') as stream:
                raw = stream.read(limit + 1)
            value = loads(raw, max_bytes=limit)
            if len(raw) > MAX_OBJECT_BYTES and not (
                protected and isinstance(value, dict)
                and value.get('object_type') == 'GRID_PRIVATE_JSON_V1'
            ):
                raise Rejected('OBJECT_TOO_LARGE')
            return decode_private(path, value, runtime)
        except FileNotFoundError:
            if attempt == 4:
                raise
            time.sleep(0.002 * (2 ** attempt))


def write(path, value, private=False, *, runtime=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".writing-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            from .custody import encode_private
            stream.write(encode_private(path, value, private, runtime))
            stream.flush()
            os.fsync(stream.fileno())
        if private:
            os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def event(path, run_id, role, stage, **fields):
    data = {"run_id": run_id, "role": role, "stage": stage, "at": utc(), **fields}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as stream:
        stream.write(canonical(data) + b"\n")

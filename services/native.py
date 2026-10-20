"""OpenSSL signing and framed mTLS on the same measured SSL connection."""

import ctypes as C
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .encoding import Rejected, canonical, loads

ROOT = Path(__file__).resolve().parents[1]
PROCESS_INSTANCE = uuid.uuid4().hex
# Conservative application policy, not a quoted standards limit. A fresh
# full TLS handshake creates new directional exporter keys before reuse.
SM4_MAX_FRAMES = 1 << 20
SM4_MAX_KEY_BYTES = 1 << 30
SM4_MAX_PLAINTEXT = 12 * 1024 * 1024 - 2048
LIB = C.CDLL(str(ROOT / ".build/libgridcrypto.so"))
LIB.grid_error.restype = C.c_char_p
LIB.grid_sandbox.argtypes = [C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p]
LIB.grid_library_info.restype = C.c_char_p
LIB.grid_sign.argtypes = [
    C.c_char_p,
    C.c_int,
    C.c_void_p,
    C.c_size_t,
    C.c_char_p,
    C.c_void_p,
    C.POINTER(C.c_size_t),
]
LIB.grid_verify.argtypes = [
    C.c_char_p,
    C.c_int,
    C.c_void_p,
    C.c_size_t,
    C.c_char_p,
    C.c_void_p,
    C.c_size_t,
]
LIB.grid_tls_listen.argtypes = [
    C.c_char_p,
    C.c_int,
    C.c_char_p,
    C.c_char_p,
    C.c_char_p,
    C.c_char_p,
    C.c_char_p,
]
LIB.grid_tls_connect.argtypes = LIB.grid_tls_listen.argtypes
LIB.grid_tls_listen.restype = LIB.grid_tls_connect.restype = C.c_void_p
LIB.grid_tls_accept.argtypes = [C.c_void_p]
LIB.grid_tls_accept.restype = C.c_void_p
LIB.grid_tls_evidence.argtypes = [C.c_void_p]
LIB.grid_tls_evidence.restype = C.c_char_p
LIB.grid_tls_export.argtypes = [C.c_void_p, C.c_char_p, C.c_void_p, C.c_size_t]
LIB.grid_tls_traffic.argtypes = [C.c_void_p]
LIB.grid_tls_traffic.restype = C.c_char_p
LIB.grid_tls_send.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t]
LIB.grid_tls_recv.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t]
LIB.grid_tls_close.argtypes = LIB.grid_tls_listener_close.argtypes = [C.c_void_p]


def utc():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def error():
    return Rejected(
        "NATIVE_OPERATION_FAILED", LIB.grid_error().decode("utf-8", errors="replace")
    )


def sandbox(runtime, job, role):
    result = LIB.grid_sandbox(
        os.fsencode(ROOT), os.fsencode(runtime), os.fsencode(job), role.encode()
    )
    if result < 3:
        raise error()
    return result


def sign(path, data, context, pq=False):
    out = C.create_string_buffer(10000)
    n = C.c_size_t(len(out))
    from .custody import native_password
    with native_password(path):
        result = LIB.grid_sign(os.fsencode(path), int(pq), data, len(data), context.encode("ascii"), out, C.byref(n))
    if result != 1:
        raise error()
    return out.raw[: n.value]


def verify(path, data, context, signature, pq=False):
    result = LIB.grid_verify(
        os.fsencode(path),
        int(pq),
        data,
        len(data),
        context.encode("ascii"),
        signature,
        len(signature),
    )
    if result < 0:
        raise error()
    return bool(result)


def credentials(runtime, role):
    path = Path(runtime)
    from .custody import enabled
    if enabled(path):
        from .trust import lookup
        entry, certificate = lookup(path, role, 'tls')
        return path / 'public/ca.pem', certificate, path / role / entry['private_key']
    return path / 'public/ca.pem', path / role / 'tls.pem', path / role / 'tls.key'


class TLS:
    def __init__(self, pointer, link, opened_at):
        if not pointer:
            raise error()
        self.pointer = pointer
        self.sm4 = None
        self.tx_sequence = self.rx_sequence = 0
        self.tx_key_bytes = self.rx_key_bytes = 0
        self.evidence = json.loads(LIB.grid_tls_evidence(pointer))
        self.evidence.update(
            link_id=link,
            opened_at=opened_at,
            handshake_completed_at=utc(),
            process_id=os.getpid(),
            process_instance=PROCESS_INSTANCE,
            peer_role=self.evidence["peer_name"].split(".")[0],
            handshake_authentication_algorithm=None,
            business_request_refs=[],
            application_bytes_sent=0,
            application_bytes_received=0,
        )
        initial = json.loads(LIB.grid_tls_traffic(pointer))
        self.evidence.update(handshake_bytes_sent=initial["sent"], handshake_bytes_received=initial["received"])
        self.record_traffic()

    def record_traffic(self):
        traffic = json.loads(LIB.grid_tls_traffic(self.pointer))
        self.evidence.update(tls_record_bytes_sent=traffic["sent"], tls_record_bytes_received=traffic["received"],
                             wire_measurement_scope="OpenSSL socket BIO TLS bytes, includes handshake; excludes TCP/IP headers")

    def enable_sm4(self, role, peer):
        if self.sm4 is not None:
            raise Rejected('SM4_CHANNEL_ALREADY_INITIALIZED')
        def key(sender, receiver):
            out = C.create_string_buffer(16)
            label = f"EXPORTER-GRID-V41-SM4-{self.evidence['link_id']}-{sender}-to-{receiver}".encode("ascii")
            if LIB.grid_tls_export(self.pointer, label, out, 16) != 1:
                raise error()
            return out.raw
        self.sm4 = (key(role, peer), key(peer, role), role, peer)
        self.evidence.update(application_cipher="SM4-GCM", sm4_frames_sent=0, sm4_frames_received=0,
                             sm4_key_source="TLS exporter, separate directional labels", nonce_strategy="96-bit sequence; unique directional exporter key per full connection",
                             sm4_limits={'maximum_frames_per_direction': SM4_MAX_FRAMES, 'maximum_bytes_per_direction': SM4_MAX_KEY_BYTES,
                                         'maximum_plaintext_bytes': SM4_MAX_PLAINTEXT, 'scope': 'Conservative application policy; reconnect with full handshake at limit'})

    def sm4_budget(self, sequence, used, size):
        if sequence >= SM4_MAX_FRAMES or used+size > SM4_MAX_KEY_BYTES or size > SM4_MAX_PLAINTEXT:
            self.close()
            raise Rejected('SM4_KEY_USAGE_LIMIT')

    @classmethod
    def connect(cls, port, role, peer, group, runtime, link, sm4=False):
        path = Path(runtime)
        ca, certificate, private_key = credentials(path, role)
        args = [
            b"127.0.0.1",
            port,
            os.fsencode(ca),
            os.fsencode(certificate),
            os.fsencode(private_key),
            group.encode(),
            (peer + ".grid").encode(),
        ]
        opened = utc()
        from .custody import native_password
        with native_password(private_key):
            connection = cls(LIB.grid_tls_connect(*args), link, opened)
        from .custody import enabled
        if enabled(path):
            from .trust import check_peer
            try:
                check_peer(path, peer, connection.evidence['peer_certificate_sha256'])
            except Exception:
                connection.close()
                raise
        if sm4:
            connection.enable_sm4(role, peer)
        return connection

    def send(self, obj):
        if not self.pointer:
            raise Rejected('TLS_CONNECTION_CLOSED')
        data = canonical(obj)
        self.evidence["application_bytes_sent"] += len(data)
        if self.sm4:
            self.sm4_budget(self.tx_sequence, self.tx_key_bytes, len(data))
            from .agility import sm4_gcm
            from .encoding import b64
            sender, receiver = self.sm4[2:]
            aad = {"suite": "GRID_SM4_GCM_FRAME_V1", "link_id": self.evidence["link_id"], "sender": sender, "receiver": receiver, "sequence": self.tx_sequence}
            nonce = self.tx_sequence.to_bytes(12, "big")
            ciphertext, tag = sm4_gcm(self.sm4[0], nonce, data, canonical(aad))
            data = canonical({**aad, "ciphertext": b64(ciphertext), "tag": b64(tag)})
            self.tx_sequence += 1
            self.tx_key_bytes += len(canonical(obj))
            self.evidence["sm4_frames_sent"] += 1
        if LIB.grid_tls_send(self.pointer, data, len(data)) != 1:
            raise error()
        self.record_traffic()
        if isinstance(obj, dict) and obj.get("request_id"):
            self.evidence["business_request_refs"].append(obj["request_id"])

    def receive(self):
        if not self.pointer:
            raise Rejected('TLS_CONNECTION_CLOSED')
        out = C.create_string_buffer(16 * 1024 * 1024)
        n = LIB.grid_tls_recv(self.pointer, out, len(out))
        if n < 0:
            raise error()
        obj = loads(out.raw[:n])
        if self.sm4:
            from .agility import sm4_gcm
            from .encoding import unb64
            aad = {"suite": "GRID_SM4_GCM_FRAME_V1", "link_id": self.evidence["link_id"], "sender": self.sm4[3], "receiver": self.sm4[2], "sequence": self.rx_sequence}
            try:
                if (not isinstance(obj, dict) or set(obj) != {*aad, "ciphertext", "tag"}
                        or canonical({key: obj[key] for key in aad}) != canonical(aad)):
                    raise Rejected("SM4_FRAME_CONTEXT_OR_REPLAY")
                ciphertext = unb64(obj['ciphertext'], 24 * 1024 * 1024)
                self.sm4_budget(self.rx_sequence, self.rx_key_bytes, len(ciphertext))
                data = sm4_gcm(self.sm4[1], self.rx_sequence.to_bytes(12, "big"), ciphertext, canonical(aad), unb64(obj["tag"]))
                obj = loads(data)
                self.rx_sequence += 1
                self.rx_key_bytes += len(data)
                self.evidence["sm4_frames_received"] += 1
            except Rejected:
                self.close()
                raise
        self.evidence["application_bytes_received"] += len(canonical(obj))
        self.record_traffic()
        if isinstance(obj, dict) and obj.get("request_id"):
            self.evidence["business_request_refs"].append(obj["request_id"])
        return obj

    def close(self):
        if self.pointer:
            LIB.grid_tls_close(self.pointer)
            self.pointer = None
        self.sm4 = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class Listener:
    def __init__(self, port, role, peer, group, runtime, link, sm4=False):
        path = Path(runtime)
        self.link = link
        self.runtime = path
        ca, certificate, private_key = credentials(path, role)
        self.sm4, self.role, self.peer = sm4, role, peer
        from .custody import native_password
        with native_password(private_key):
            self.pointer = LIB.grid_tls_listen(b"127.0.0.1", port, os.fsencode(ca),
                os.fsencode(certificate), os.fsencode(private_key), group.encode(), (peer + ".grid").encode())
        if not self.pointer:
            raise error()

    def accept(self):
        opened = utc()
        connection = TLS(LIB.grid_tls_accept(self.pointer), self.link, opened)
        from .custody import enabled
        if enabled(self.runtime):
            from .trust import check_peer
            try:
                check_peer(self.runtime, self.peer, connection.evidence['peer_certificate_sha256'])
            except Exception:
                connection.close()
                raise
        if self.sm4:
            connection.enable_sm4(self.role, self.peer)
        return connection

    def close(self):
        if self.pointer:
            LIB.grid_tls_listener_close(self.pointer)
            self.pointer = None

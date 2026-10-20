"""Explicit providers backed by the locally loaded OpenSSL implementation."""
import ctypes as C
import fcntl
import json
import os
from dataclasses import dataclass

from .encoding import Rejected
from .initialization import RUNTIME, command, initialize_keys
from .native import LIB

LIB.grid_agility_error.restype = C.c_char_p
LIB.grid_sm3.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p]
LIB.grid_sm2_sign.argtypes = [C.c_char_p, C.c_void_p, C.c_size_t, C.c_char_p, C.c_void_p, C.POINTER(C.c_size_t)]
LIB.grid_sm2_verify.argtypes = [C.c_char_p, C.c_void_p, C.c_size_t, C.c_char_p, C.c_void_p, C.c_size_t]
LIB.grid_sm4_gcm.argtypes = [C.c_int, C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p]


def failed():
    return Rejected("AGILITY_NATIVE_FAILED", LIB.grid_agility_error().decode(errors="replace"))


def sm3(data: bytes) -> str:
    out = C.create_string_buffer(32)
    if LIB.grid_sm3(data, len(data), out) != 1:
        raise failed()
    return out.raw.hex()


def sm2_sign(path, data, identity):
    out = C.create_string_buffer(256)
    size = C.c_size_t(len(out))
    from .custody import native_password
    with native_password(path):
        result = LIB.grid_sm2_sign(os.fsencode(path), data, len(data), identity.encode("ascii"), out, C.byref(size))
    if result != 1:
        raise failed()
    return out.raw[:size.value]


def sm2_verify(path, data, identity, signature):
    result = LIB.grid_sm2_verify(os.fsencode(path), data, len(data), identity.encode("ascii"), signature, len(signature))
    if result < 0:
        raise failed()
    return bool(result)


def sm4_gcm(key, nonce, data, aad=b"", tag=None):
    if len(key) != 16 or len(nonce) != 12 or (tag is not None and len(tag) != 16):
        raise Rejected("SM4_ARGUMENT_INVALID")
    if len(data) > 16 * 1024 * 1024 or len(aad) > 65536:
        raise Rejected("SM4_INPUT_TOO_LARGE")
    encrypted = tag is None
    auth = C.create_string_buffer(16)
    if tag is not None:
        auth.raw = tag
    out = C.create_string_buffer(max(1, len(data)) + 16)
    result = LIB.grid_sm4_gcm(int(encrypted), key, nonce, aad, len(aad), data, len(data), auth, out)
    if result == 0:
        raise Rejected("SM4_AUTHENTICATION_FAILED")
    if result < 0:
        raise failed()
    return (out.raw[:len(data)], auth.raw) if encrypted else out.raw[:len(data)]


def preflight():
    """Application startup known-answer check, not full module self-testing."""
    key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
    nonce = bytes.fromhex('00001234567800000000ABCD')
    data = bytes.fromhex('AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA')
    aad = bytes.fromhex('FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2')
    expected = bytes.fromhex('17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D')
    ciphertext, tag = sm4_gcm(key, nonce, data, aad)
    checks = {'SM3_abc': sm3(b'abc') == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
              'SM4_GCM_RFC8998_A1': ciphertext == expected and tag.hex() == '83de3541e4c2b58177e065a9bf7b62ec',
              'SM4_GCM_decrypt': sm4_gcm(key, nonce, ciphertext, aad, tag) == data}
    if not all(checks.values()):
        raise Rejected('APPLICATION_CRYPTO_SELF_CHECK_FAILED')
    return checks


@dataclass(frozen=True)
class CryptoProvider:
    suite: str
    profile: str
    group: str
    algorithms: tuple[str, ...]
    sm4_channel: bool = False
    business_allowed: bool = False

    def public(self):
        return {"suite": self.suite, "profile": self.profile, "tls_group": self.group,
                "signature_algorithms": list(self.algorithms), "signature_policy": "ALL_REQUIRED",
                "snapshot_hash": "SM3", "application_cipher": "SM4-GCM" if self.sm4_channel else None,
                "tls_record_cipher": "TLS_AES_256_GCM_SHA384", "certificate_identity": "CLASSICAL_ECDSA",
                "business_allowed": self.business_allowed, "tlcp": "NOT_IMPLEMENTED"}


PROVIDERS = {
    "V41_CLASSIC": CryptoProvider("V41_CLASSIC", "S0", "X25519", ("ECDSA-P256-SHA256",)),
    "V41_SM": CryptoProvider("V41_SM", "S0", "X25519", ("ECDSA-P256-SHA256", "SM2-SM3"), True),
    "V41_PQ": CryptoProvider("V41_PQ", "SAB", "MLKEM768", ("ECDSA-P256-SHA256", "ML-DSA-65")),
    "V41_HYBRID": CryptoProvider("V41_HYBRID", "SAB", "X25519MLKEM768", ("ECDSA-P256-SHA256", "ML-DSA-65"), business_allowed=True),
    "V41_HYBRID_SM": CryptoProvider("V41_HYBRID_SM", "SAB", "X25519MLKEM768", ("ECDSA-P256-SHA256", "ML-DSA-65", "SM2-SM3"), True, True),
}


def provider(suite):
    if suite not in PROVIDERS:
        raise Rejected("CRYPTO_SUITE_UNSUPPORTED")
    return PROVIDERS[suite]


def initialize_sm_keys():
    """Add SM2 role keys without replacing existing keys or epoch history."""
    initialize_keys()
    with (RUNTIME / "v41-key-init.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = RUNTIME / "public/key_registry.json"
        registry = json.loads(path.read_text())
        if all("sm2" in registry.get(role, {}) for role in ("utility", "gateway")):
            return
        for role in ("utility", "gateway"):
            if "sm2" in registry[role]:
                continue
            secret = RUNTIME / role / "sm2.key"
            public = RUNTIME / "public" / f"{role}-sm2-1.pem"
            if secret.exists() or public.exists():
                raise Rejected("SM2_PARTIAL_KEY_INITIALIZATION")
            # The parent directories are private; set umask before creating a key.
            old_mask = os.umask(0o077)
            try:
                command("openssl", "genpkey", "-algorithm", "SM2", "-out", secret)
            finally:
                os.umask(old_mask)
            os.chmod(secret, 0o600)
            command("openssl", "pkey", "-in", secret, "-pubout", "-out", public)
            registry[role]["sm2"] = {"key_id": f"{role}-sm2-1", "public_key": public.name, "epoch": 1}
        temporary = path.with_suffix(".v41-next")
        temporary.write_text(json.dumps(registry, indent=2), encoding="utf-8")
        os.replace(temporary, path)

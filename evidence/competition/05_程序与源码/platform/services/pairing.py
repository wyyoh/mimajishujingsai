"""Typed real BLS12-381 operations through the pinned mcl C ABI."""

import ctypes as C
import secrets
from pathlib import Path

from .encoding import Rejected, b64, unb64

ROOT = Path(__file__).resolve().parents[1]
LIB = C.CDLL(str(ROOT / "third_party/mcl/lib/libmcl.so"))
LIB.mclBn_init.argtypes = [C.c_int, C.c_int]
if LIB.mclBn_init(5, 46) != 0:
    raise RuntimeError("mcl BLS12-381 ABI initialization failed")
if LIB.mclBn_setMapToMode(5) != 0:
    raise RuntimeError("mcl hash-to-curve initialization failed")
LIB.mclBn_verifyOrderG1(1)
LIB.mclBn_verifyOrderG2(1)


def call(name, args, restype=None):
    fn = getattr(LIB, "mclBn" + name)
    fn.restype = restype
    return fn(*args)


buf = C.create_string_buffer(256)
call("_getCurveOrder", [buf, C.c_size_t(len(buf))], C.c_size_t)
ORDER = int(buf.value)
SIZES = {"Fr": 4, "G1": 18, "G2": 36, "GT": 72}


class Element:
    __slots__ = ("kind", "raw")

    def __init__(self, kind):
        self.kind = kind
        self.raw = (C.c_uint64 * SIZES[kind])()

    @classmethod
    def scalar(cls, n):
        e = cls("Fr")
        data = str(n % ORDER).encode()
        if call(
            "Fr_setStr", [e.raw, data, C.c_size_t(len(data)), C.c_int(10)], C.c_int
        ):
            raise Rejected("SCALAR_ENCODING_INVALID")
        return e

    @classmethod
    def random(cls):
        return cls.scalar(secrets.randbelow(ORDER - 1) + 1)

    @classmethod
    def hash_point(cls, kind, domain, data):
        e = cls(kind)
        dst = domain.encode("ascii")
        if call(
            kind + "_hashAndMapToWithDst",
            [e.raw, data, C.c_size_t(len(data)), dst, C.c_size_t(len(dst))],
            C.c_int,
        ):
            raise Rejected("HASH_TO_GROUP_FAILED")
        return e

    @classmethod
    def decode(cls, kind, text):
        raw = unb64(text, 4096)
        e = cls(kind)
        n = call(kind + "_deserialize", [e.raw, raw, C.c_size_t(len(raw))], C.c_size_t)
        if n != len(raw):
            raise Rejected("GROUP_ENCODING_INVALID")
        if kind in ("G1", "G2"):
            if not call(kind + "_isValid", [e.raw], C.c_int) or not call(
                kind + "_isValidOrder", [e.raw], C.c_int
            ):
                raise Rejected("GROUP_SUBGROUP_INVALID")
        elif kind == "GT" and not call("GT_isValid", [e.raw], C.c_int):
            raise Rejected("GROUP_SUBGROUP_INVALID")
        if e.encode() != text:
            raise Rejected("NONCANONICAL_GROUP_ENCODING")
        return e

    def encode(self):
        out = C.create_string_buffer(1024)
        n = call(
            self.kind + "_serialize", [out, C.c_size_t(len(out)), self.raw], C.c_size_t
        )
        if not n:
            raise Rejected("GROUP_SERIALIZATION_FAILED")
        return b64(out.raw[:n])

    def is_identity(self):
        suffix = "_isOne" if self.kind == "GT" else "_isZero"
        return bool(call(self.kind + suffix, [self.raw], C.c_int))

    def __eq__(self, other):
        return (
            isinstance(other, Element)
            and self.kind == other.kind
            and bool(call(self.kind + "_isEqual", [self.raw, other.raw], C.c_int))
        )

    def scale(self, scalar):
        if not isinstance(scalar, Element):
            scalar = Element.scalar(scalar)
        if scalar.kind != "Fr":
            raise TypeError("scalar required")
        result = Element(self.kind)
        name = "GT_pow" if self.kind == "GT" else self.kind + "_mulCT"
        call(name, [result.raw, self.raw, scalar.raw])
        return result

    def multiply(self, other):
        if self.kind != "GT" or other.kind != "GT":
            raise TypeError("GT elements required")
        result = Element("GT")
        call("GT_mul", [result.raw, self.raw, other.raw])
        return result

    def divide(self, other):
        if self.kind != "GT" or other.kind != "GT":
            raise TypeError("GT elements required")
        result = Element("GT")
        call("GT_div", [result.raw, self.raw, other.raw])
        return result


def pairing(a, b):
    if a.kind != "G1" or b.kind != "G2":
        raise TypeError("pairing requires G1 x G2")
    result = Element("GT")
    call("_pairing", [result.raw, a.raw, b.raw])
    return result


G1 = Element.hash_point("G1", "GRID-PFDAM-G1-V1", b"generator")
G2 = Element.hash_point("G2", "GRID-PFDAM-G2-V1", b"generator")
GT = pairing(G1, G2)


def hash_gt(data):
    return pairing(Element.hash_point("G1", "GRID-PFDAM-TAG-GT-V1", data), G2)

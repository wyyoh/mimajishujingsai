"""Strict parsing and RFC 8785 canonical payload bytes."""

import base64
import hashlib
import json
import math

import jcs

MAX_OBJECT_BYTES = 16 * 1024 * 1024


class Rejected(ValueError):
    def __init__(self, code, message=None):
        self.code = code
        super().__init__(message or code)


def _pairs(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise Rejected("DUPLICATE_JSON_FIELD")
        obj[k] = v
    return obj


def _valid(value):
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError as e:
            raise Rejected("INVALID_UNICODE") from e
    elif isinstance(value, bool) or value is None:
        pass
    elif isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise Rejected("UNSAFE_JSON_INTEGER")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise Rejected("NONFINITE_NUMBER")
        # The application schema intentionally excludes floating-point data.
        raise Rejected("FLOAT_NOT_ALLOWED")
    elif isinstance(value, list):
        for x in value:
            _valid(x)
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise Rejected("NONSTRING_KEY")
            _valid(k)
            _valid(v)
    else:
        raise Rejected("UNSUPPORTED_JSON_TYPE")


def loads(data, *, max_bytes=MAX_OBJECT_BYTES):
    if len(data) > max_bytes:
        raise Rejected("OBJECT_TOO_LARGE")
    try:
        obj = json.loads(
            data,
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                Rejected("NONFINITE_NUMBER")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as e:
        raise Rejected("INVALID_JSON") from e
    _valid(obj)
    return obj


def canonical(obj):
    _valid(obj)
    return jcs.canonicalize(obj)


def digest(obj):
    return hashlib.sha384(canonical(obj)).hexdigest()


def b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(text, limit=65536):
    if (
        not isinstance(text, str)
        or not text
        or len(text) > limit
        or any(
            c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
            for c in text
        )
    ):
        raise Rejected("INVALID_BASE64URL")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as e:
        raise Rejected("INVALID_BASE64URL") from e
    if b64(raw) != text:
        raise Rejected("NONCANONICAL_BASE64URL")
    return raw


def decimal(text, max_digits=2000):
    if (
        not isinstance(text, str)
        or not text
        or len(text) > max_digits
        or not text.isascii()
        or not text.isdecimal()
        or (len(text) > 1 and text[0] == "0")
    ):
        raise Rejected("INVALID_DECIMAL_INTEGER")
    return int(text)

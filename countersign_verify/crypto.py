"""Hashes, canonical JSON and ES256, written for the verifier alone (no import from `countersign`).

The browser verifier (`web/ui/evidence/`) is a line by line port of this package: the same checks in the
same order, raising the same stable codes. `tests/integration/test_verifier_agreement.py` holds the two to
that on every shared vector.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import struct
from decimal import Decimal, InvalidOperation
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 64  # arrays and objects open at once; a bundle needs 8 (Decision 106)
_SURROGATE = re.compile("[\ud800-\udfff]")


class Invalid(Exception):
    """A check failed. `code` is stable and is the one the browser verifier raises at the same check; the
    message says what, never more than the bundle already shows."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class Float:
    """A JSON number written with a fraction or an exponent, kept apart from integers (Decision 106):
    `1.0` never equals the integer `1`."""

    __slots__ = ("value",)

    def __init__(self, value: float) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Float) and other.value == self.value

    def __hash__(self) -> int:
        return hash(("Float", self.value))

    def __repr__(self) -> str:
        return f"Float({self.value!r})"


def same(a: Any, b: Any) -> bool:
    """Type-exact equality (Decision 106): `True` is not `1`, `Float(1.0)` is not `1`."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b, strict=True))
    return bool(a == b)


def is_int(value: Any) -> bool:
    return type(value) is int


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: object) -> bytes:
    if not isinstance(text, str) or not text.isascii():
        raise Invalid("base64url_invalid", "a value is not base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise Invalid("base64url_invalid", "a value is not base64url") from None
    if b64url(raw) != text:
        raise Invalid("base64url_invalid", "a value is not canonical unpadded base64url")
    return raw


def _too_deep(text: str) -> bool:
    """True if some point of `text` is inside more than MAX_DEPTH open arrays or objects."""
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def _integer(token: str) -> int:
    if len(token.lstrip("-")) > 16:
        raise Invalid("json_unsafe_integer", "an integer is outside +/-(2^53 - 1)")
    value = int(token)
    if abs(value) > MAX_SAFE_INTEGER:
        raise Invalid("json_unsafe_integer", "an integer is outside +/-(2^53 - 1)")
    return value


def _float(token: str) -> Float:
    value = float(token)
    if not math.isfinite(value):
        raise Invalid("json_non_finite", "a number overflows binary64")
    if abs(value) > MAX_SAFE_INTEGER:
        raise Invalid("json_unsafe_integer", "a number is outside +/-(2^53 - 1)")
    try:
        exact = Decimal(token) == Decimal(repr(value))
    except InvalidOperation:
        exact = False
    if not exact:
        raise Invalid("json_excess_precision", "a number has more digits than binary64 holds")
    return Float(value)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in items]
    if len(set(keys)) != len(keys):
        raise Invalid("json_duplicate_key", "a JSON object has a duplicate key")
    for key in keys:
        if _SURROGATE.search(key):
            raise Invalid("json_lone_surrogate", "a key holds a lone surrogate")
    return dict(items)


def _constant(name: str) -> Any:
    raise Invalid("json_non_finite", f"{name} is not valid JSON")


def loads(data: object) -> Any:
    """Strict JSON (Decisions 12 and 106), checked in this order: UTF-8 without a byte order mark, no lone
    surrogate in the text, at most MAX_DEPTH nested containers, then in document order no NaN or
    Infinity, integers within +/-(2^53 - 1), no excess precision (numbers with a fraction or an exponent
    are `Float`), no duplicate key (checked when an object closes), then no escaped lone surrogate."""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise Invalid("json_encoding", "not UTF-8") from None
    elif isinstance(data, str):
        text = data
    else:
        raise Invalid("json_syntax", "not JSON text")
    if text.startswith("﻿"):
        raise Invalid("json_encoding", "starts with a byte order mark")
    if _SURROGATE.search(text):
        raise Invalid("json_lone_surrogate", "the text holds a lone surrogate")
    if _too_deep(text):
        raise Invalid("json_too_deep", "nested too deeply")
    try:
        value = json.loads(
            text, object_pairs_hook=_pairs, parse_constant=_constant, parse_int=_integer,
            parse_float=_float,
        )  # fmt: skip
    except Invalid:
        raise
    except ValueError:
        raise Invalid("json_syntax", "not valid JSON") from None
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if _SURROGATE.search(node):
                raise Invalid("json_lone_surrogate", "a string holds a lone surrogate")
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            stack.extend(node.values())
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Float):
        return value.value
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def jcs(value: Any) -> bytes:
    try:
        return rfc8785.dumps(_plain(value))
    except (TypeError, ValueError, OverflowError):
        raise Invalid("jcs_invalid", "a value has no canonical form") from None


def digest(text: str) -> str:
    """`sd_hash`-style digest: unpadded base64url SHA-256 over the US-ASCII text."""
    if not isinstance(text, str) or not text.isascii():
        raise Invalid("digest_not_ascii", "a hashed value is not US-ASCII")
    return b64url(hashlib.sha256(text.encode("ascii")).digest())


def domain_hash(domain: str, data: bytes) -> bytes:
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + data).digest()


def thumbprint(jwk: Any) -> str:
    """RFC 7638 thumbprint of an EC P-256 public JWK."""
    if not isinstance(jwk, dict):
        raise Invalid("key_not_object", "a key is not an object")
    members = {m: jwk.get(m) for m in ("crv", "kty", "x", "y")}
    if not all(isinstance(v, str) for v in members.values()):
        raise Invalid("key_not_ec", "a key is not an EC public JWK")
    return b64url(hashlib.sha256(jcs(members)).digest())


def _public(jwk: Any) -> ec.EllipticCurvePublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise Invalid("key_not_p256", "a key is not an EC P-256 public JWK")
    if "d" in jwk:
        raise Invalid("key_private", "a published key holds private material")
    x, y = unb64(jwk.get("x")), unb64(jwk.get("y"))
    if len(x) != 32 or len(y) != 32:
        raise Invalid("key_coordinates", "a key has bad coordinates")
    try:
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        )
        return numbers.public_key()
    except ValueError:
        raise Invalid("key_not_on_curve", "a key is not on the curve") from None


def verify_es256(jwk: Any, signed: bytes, signature: object) -> bool:
    """ES256 over `signed`; `signature` is the raw 64 byte `r || s` in base64url."""
    raw = unb64(signature)
    if len(raw) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        _public(jwk).verify(der, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def verify_jws(token: object, jwk: Any, *, typ: str | None = None) -> tuple[dict[str, Any], Any]:
    """Verify a compact ES256 JWS and return `(header, payload)`. `typ` is checked when given."""
    if not isinstance(token, str) or not token.isascii() or token.count(".") != 2:
        raise Invalid("jws_shape", "a JWS is not three segments")
    head, body, sig = token.split(".")
    header = loads(unb64(head))
    if not isinstance(header, dict) or header.get("alg") != "ES256":
        raise Invalid("jws_alg", "a JWS is not ES256")
    if typ is not None and header.get("typ") != typ:
        raise Invalid("jws_typ", "a JWS has the wrong typ")
    if not verify_es256(jwk, f"{head}.{body}".encode("ascii"), sig):
        raise Invalid("signature_invalid", "a signature does not verify")
    return header, loads(unb64(body))


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)

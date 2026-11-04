"""Hashes, canonical JSON and ES256, written for the verifier alone (no import from `countersign`)."""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class Invalid(Exception):
    """A check failed. The message says what, never more than the bundle already shows."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: object) -> bytes:
    if not isinstance(text, str) or not text.isascii():
        raise Invalid("a value is not base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise Invalid("a value is not base64url") from None
    if b64url(raw) != text:
        raise Invalid("a value is not canonical unpadded base64url")
    return raw


def loads(data: str | bytes) -> Any:
    """Strict JSON: duplicate keys, NaN and Infinity are refused."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [k for k, _ in items]
        if len(set(keys)) != len(keys):
            raise Invalid("a JSON object has a duplicate key")
        return dict(items)

    def constant(name: str) -> Any:
        raise Invalid(f"{name} is not valid JSON")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except ValueError as error:
        if isinstance(error, Invalid):
            raise
        raise Invalid("not valid JSON") from None


def jcs(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError, OverflowError):
        raise Invalid("a value has no canonical form") from None


def digest(text: str) -> str:
    """`sd_hash`-style digest: unpadded base64url SHA-256 over the US-ASCII text."""
    try:
        return b64url(hashlib.sha256(text.encode("ascii")).digest())
    except UnicodeEncodeError:
        raise Invalid("a hashed value is not US-ASCII") from None


def domain_hash(domain: str, data: bytes) -> bytes:
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + data).digest()


def thumbprint(jwk: Any) -> str:
    """RFC 7638 thumbprint of an EC P-256 public JWK."""
    if not isinstance(jwk, dict):
        raise Invalid("a key is not an object")
    members = {m: jwk.get(m) for m in ("crv", "kty", "x", "y")}
    if not all(isinstance(v, str) for v in members.values()):
        raise Invalid("a key is not an EC public JWK")
    return b64url(hashlib.sha256(jcs(members)).digest())


def _public(jwk: Any) -> ec.EllipticCurvePublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise Invalid("a key is not an EC P-256 public JWK")
    if "d" in jwk:
        raise Invalid("a published key holds private material")
    x, y = unb64(jwk.get("x")), unb64(jwk.get("y"))
    if len(x) != 32 or len(y) != 32:
        raise Invalid("a key has bad coordinates")
    try:
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        )
        return numbers.public_key()
    except ValueError:
        raise Invalid("a key is not on the curve") from None


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
    if not isinstance(token, str) or token.count(".") != 2:
        raise Invalid("a JWS is not three segments")
    head, body, sig = token.split(".")
    header = loads(unb64(head))
    if not isinstance(header, dict) or header.get("alg") != "ES256":
        raise Invalid("a JWS is not ES256")
    if typ is not None and header.get("typ") != typ:
        raise Invalid("a JWS has the wrong typ")
    if not verify_es256(jwk, f"{head}.{body}".encode("ascii"), sig):
        raise Invalid("a signature does not verify")
    return header, loads(unb64(body))


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)

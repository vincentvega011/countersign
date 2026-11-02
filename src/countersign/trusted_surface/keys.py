"""Device key checks: the public JWK, its RFC 7638 thumbprint, the origin and the proof of possession.

Security reasoning. A registered device key will sign consent that lets the platform issue mandates
(PROTOCOL.md Decision 5), so everything here is strict and deterministic (INV-1) and fails closed
(INV-10). Nothing in this module touches the database, the network or a clock.

JWK. Exactly the members `kty`, `crv`, `x` and `y`, and nothing else. A private member (`d` and the
other private parameters) is refused with its own code, because a client that sends one has leaked a
private key and must not be treated as merely sloppy. Extra public members (`alg`, `kid`, `use`,
`key_ops`, `ext`) are refused too, so the stored key and the thumbprint input are one unambiguous
object. `kty` must be `EC` and `crv` `P-256`. `x` and `y` must be the canonical unpadded base64url of
exactly 32 bytes (a non-canonical spelling would be a second spelling of one key), and the point must
lie on the curve (checked by the `cryptography` library, which rejects off-curve points and
coordinates at or above the field prime).

Thumbprint. RFC 7638: SHA-256 over the members `crv`, `kty`, `x`, `y` in lexicographic order with no
whitespace. For these four string members that is exactly the JCS (RFC 8785) form, so the one
canonicalizer is used. It is always computed here, never taken from the client.

Proof of possession. The new key signs the JCS bytes of a record that names the purpose, the
challenge (id and nonce), the thumbprint, the customer id (or null for a new customer) and the page
origin. The server rebuilds that record from its own values and verifies the signature over it, so a
signature made for another challenge, purpose, origin, customer or key does not verify. The signature
is ES256 in WebCrypto's raw `r || s` form (64 bytes, base64url, canonical spelling), verified with
ECDSA over SHA-256.

Origin. The configured public origin and the origin in the request are both reduced to
`(scheme, host, port)` with the scheme and host lower-cased and the default port filled in. A value
with a path, query, fragment or user information is not an origin and is refused.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from countersign.canonical.hashing import b64url
from countersign.canonical.jcs import JcsError, canonicalize

PURPOSE_REGISTER = "countersign.device-key.register.v1"
PURPOSE_REVOKE = "countersign.device-key.revoke.v1"
RECORD_VERSION = 1

_PUBLIC_MEMBERS = frozenset({"kty", "crv", "x", "y"})
_PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_COORDINATE = re.compile(r"[A-Za-z0-9_-]{43}")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}")
_VISIBLE_ASCII = re.compile(r"[\x21-\x7e]{1,255}")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class KeyRefused(Exception):
    """A key, origin or signature check failed. `code` is the stable answer code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class PublicKey:
    """A validated P-256 public key: the JWK as it is stored, and its thumbprint."""

    jwk: dict[str, str]
    thumbprint: str

    def verifying_key(self) -> ec.EllipticCurvePublicKey:
        return _point(self.jwk["x"], self.jwk["y"])


def _decode_exact(value: str, size: int) -> bytes:
    """Canonical unpadded base64url of exactly `size` bytes, or raise ValueError."""
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as error:
        raise ValueError("not base64url") from error
    if len(raw) != size or b64url(raw) != value:
        raise ValueError("not the canonical encoding")
    return raw


def _point(x: str, y: str) -> ec.EllipticCurvePublicKey:
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_decode_exact(x, 32), "big"),
        int.from_bytes(_decode_exact(y, 32), "big"),
        ec.SECP256R1(),
    )
    return numbers.public_key()  # raises ValueError for a point that is not on the curve


def thumbprint_of(jwk: Mapping[str, str]) -> str:
    """RFC 7638 thumbprint of an EC public JWK (members crv, kty, x, y)."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    return b64url(hashlib.sha256(canonicalize(required)).digest())


def validate_public_jwk(value: Any) -> PublicKey:
    """Return the validated key, or raise `KeyRefused` with the stable code."""
    if not isinstance(value, dict):
        raise KeyRefused("jwk_malformed")
    members = set(value)
    if members & _PRIVATE_MEMBERS:
        raise KeyRefused("jwk_private_member")
    if members != _PUBLIC_MEMBERS:
        raise KeyRefused("jwk_extra_members" if members > _PUBLIC_MEMBERS else "jwk_malformed")
    if not all(isinstance(value[k], str) for k in _PUBLIC_MEMBERS):
        raise KeyRefused("jwk_malformed")
    if value["kty"] != "EC" or value["crv"] != "P-256":
        raise KeyRefused("jwk_unsupported_curve")
    if _COORDINATE.fullmatch(value["x"]) is None or _COORDINATE.fullmatch(value["y"]) is None:
        raise KeyRefused("jwk_malformed")
    try:
        _point(value["x"], value["y"])
    except ValueError as error:
        if "canonical" in str(error) or "base64" in str(error):
            raise KeyRefused("jwk_malformed") from None
        raise KeyRefused("jwk_not_on_curve") from None
    jwk = {k: value[k] for k in ("kty", "crv", "x", "y")}
    return PublicKey(jwk, thumbprint_of(jwk))


# ---------------------------------------------------------------------------------------- origin


def normalize_origin(value: object) -> tuple[str, str, int]:
    """`(scheme, host, port)` of an origin string, or raise `KeyRefused("origin_mismatch")`."""
    # urlsplit silently drops tabs and newlines, so only visible ASCII is let through to it.
    if not isinstance(value, str) or _VISIBLE_ASCII.fullmatch(value) is None:
        raise KeyRefused("origin_mismatch")
    try:
        parts = urlsplit(value)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise KeyRefused("origin_mismatch") from None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not host or "@" in parts.netloc:
        raise KeyRefused("origin_mismatch")
    if parts.path not in ("", "/") or "?" in value or "#" in value:
        raise KeyRefused("origin_mismatch")
    return scheme, host.lower(), _DEFAULT_PORTS[scheme] if port is None else port


def origin_string(origin: tuple[str, str, int]) -> str:
    """The canonical text of a normalized origin, with the default port left out."""
    scheme, host, port = origin
    shown = f"[{host}]" if ":" in host else host
    suffix = "" if port == _DEFAULT_PORTS[scheme] else f":{port}"
    return f"{scheme}://{shown}{suffix}"


# ---------------------------------------------------------------------------------- the record


def registration_record(
    *,
    challenge_id: str,
    nonce: str,
    thumbprint: str,
    customer_id: str | None,
    origin: str,
) -> bytes:
    """The JCS bytes the new key (and, for an existing customer, an old key) signs."""
    try:
        return canonicalize(
            {
                "v": RECORD_VERSION,
                "purpose": PURPOSE_REGISTER,
                "challenge_id": challenge_id,
                "challenge": nonce,
                "thumbprint": thumbprint,
                "customer_id": customer_id,
                "origin": origin,
            }
        )
    except JcsError:
        raise KeyRefused("proof_invalid") from None


def verify_signature(key: ec.EllipticCurvePublicKey, record: bytes, signature: str) -> bool:
    """ES256 over `record`, with `signature` in raw `r || s` base64url form."""
    if _SIGNATURE.fullmatch(signature) is None:
        return False
    try:
        raw = _decode_exact(signature, 64)
    except ValueError:
        return False
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    try:
        key.verify(encode_dss_signature(r, s), record, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def revocation_record(
    *,
    challenge_id: str,
    nonce: str,
    customer_id: str,
    target_thumbprint: str,
    signer_thumbprint: str,
    origin: str,
) -> bytes:
    """The JCS bytes a non-revoked key of the customer signs to revoke `target_thumbprint`."""
    try:
        return canonicalize(
            {
                "v": RECORD_VERSION,
                "purpose": PURPOSE_REVOKE,
                "challenge_id": challenge_id,
                "challenge": nonce,
                "customer_id": customer_id,
                "target_thumbprint": target_thumbprint,
                "signer_thumbprint": signer_thumbprint,
                "origin": origin,
            }
        )
    except JcsError:
        raise KeyRefused("proof_invalid") from None

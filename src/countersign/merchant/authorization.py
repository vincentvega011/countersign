"""`ap2.merchant_authorization`: the merchant's signature over a checkout response.

Spec (vendored `payment/extensions/ap2-mandates.md`, "Business Authorization", "Canonicalization";
docs/PROTOCOL.md Decision 7 and Decision 18): the value is a detached JWS (RFC 7515 Appendix F),
`<header>..<signature>`. The protected header is exactly `{"alg": "ES256", "kid": <merchant kid>}`.
The signature covers the header and the JCS bytes of the whole checkout response with the `ap2`
member removed: signing input `b64url(header) "." b64url(JCS bytes)`. Because every other member is
covered, including `ucp`, `messages` and `expires_at`, a response is signed last, after everything
else in it is final.

`checkout_jwt` is the same signature with the payload re-attached (compact JWS), rebuilt from a
response by `checkout_jwt`. There is one signature and two serializations (Decision 7).

Security reasoning for verification, which is what a platform, the Merchant role on `complete` and
the evidence verifier all rely on:

- Algorithm allowlist. Only `ES256` is accepted, whatever the header says, so a header that asks
  for `none`, `HS256` (a MAC keyed with a public key) or another curve is refused before any
  signature work. The verifying key must itself be EC P-256 and, if it names an `alg`, ES256.
- Exact header. The header must decode to a JSON object with exactly the members `alg` and `kid`:
  an extra member (`jwk`, `jku`, `crit`, `b64`, `typ`) or a missing one is refused. Nothing in the
  header can point the verifier at a key or change how the signature is computed.
- Published keys only. `kid` must name exactly one entry of the keys the caller passes, which are
  the merchant's published `keys[]`. An unknown or ambiguous `kid` is refused; a published entry that
  holds private key material is refused rather than used.
- Strict encodings. Header and signature are canonical unpadded base64url (decode then re-encode
  must give the same text), the signature is exactly 64 bytes (r and s, 32 bytes each), and the
  header JSON passes the strict loader (no duplicate members).
- The payload is rebuilt by the verifier from the response it was given, never taken from the
  signature value, so any change to a covered member, in either direction, breaks verification.

Error codes are the UCP AP2 ones: `merchant_authorization_missing` when the response has none and
`merchant_authorization_invalid` for everything else.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from countersign.canonical.hashing import b64url
from countersign.canonical.jcs import JcsError, canonicalize
from countersign.canonical.jsonstrict import StrictJsonError, loads_strict
from countersign.merchant.keys import ALG, PRIVATE_ONLY_MEMBERS, MerchantKey

MISSING = "merchant_authorization_missing"
INVALID = "merchant_authorization_invalid"

ALLOWED_ALGORITHMS = [ALG]
_HEADER_MEMBERS = frozenset({"alg", "kid"})
_DETACHED = re.compile(r"[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+")  # the schema pattern
_SIGNATURE_LEN = 64


class AuthorizationError(Exception):
    """The merchant authorization is missing or does not verify. Fail closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class VerifiedAuthorization:
    kid: str
    payload: bytes  # the JCS bytes that were signed
    checkout_jwt: str  # the compact serialization of the same signature


def _invalid(message: str) -> AuthorizationError:
    return AuthorizationError(INVALID, message)


def _unb64(text: str, what: str) -> bytes:
    """Decode canonical unpadded base64url; anything else is an error."""
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise _invalid(f"{what} is not base64url") from None
    if b64url(raw) != text:
        raise _invalid(f"{what} is not canonical base64url")
    return raw


def _covered(body: Mapping[str, Any]) -> bytes:
    """The JCS bytes of the response without its `ap2` member."""
    try:
        return canonicalize({k: v for k, v in body.items() if k != "ap2"})
    except JcsError as exc:
        raise _invalid(f"the checkout has no canonical form: {exc}") from None


def sign_checkout(body: Mapping[str, Any], key: MerchantKey) -> dict[str, Any]:
    """Return a copy of `body` carrying `ap2.merchant_authorization`.

    Other members of an existing `ap2` object are kept (they are outside the signature); a
    previous `merchant_authorization` is replaced.
    """
    compact = jws.serialize_compact(
        {"alg": ALG, "kid": key.kid}, _covered(body), key.private_key, algorithms=ALLOWED_ALGORITHMS
    )
    header, _, signature = compact.split(".")
    existing = body.get("ap2")
    ap2: dict[str, Any] = dict(existing) if isinstance(existing, Mapping) else {}
    ap2["merchant_authorization"] = f"{header}..{signature}"
    return {**body, "ap2": ap2}


def _detached(body: Mapping[str, Any]) -> str:
    ap2 = body.get("ap2")
    if not isinstance(ap2, Mapping) or "merchant_authorization" not in ap2:
        raise AuthorizationError(MISSING, "the response has no ap2.merchant_authorization")
    value = ap2["merchant_authorization"]
    if not isinstance(value, str) or not _DETACHED.fullmatch(value):
        raise _invalid("merchant_authorization is not a detached JWS (header..signature)")
    return value


def _header(segment: str) -> tuple[str, str]:
    """Strictly decode the protected header and return `(alg, kid)`."""
    try:
        header = loads_strict(_unb64(segment, "the header"))
    except StrictJsonError as exc:
        raise _invalid(f"the header is not strict JSON: {exc}") from None
    if not isinstance(header, dict) or set(header) != _HEADER_MEMBERS:
        raise _invalid("the header must be an object with exactly alg and kid")
    alg, kid = header["alg"], header["kid"]
    if not isinstance(alg, str) or alg not in ALLOWED_ALGORITHMS:
        raise _invalid("the header algorithm is not allowed")
    if not isinstance(kid, str) or not kid:
        raise _invalid("the header kid must be a non-empty string")
    return alg, kid


def _published_key(keys: Sequence[Mapping[str, Any]], kid: str) -> ECKey:
    matches = [k for k in keys if isinstance(k, Mapping) and k.get("kid") == kid]
    if len(matches) != 1:
        raise _invalid("kid does not name exactly one published key")
    jwk = matches[0]
    if PRIVATE_ONLY_MEMBERS & set(jwk):
        raise _invalid("the published key holds private key material")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise _invalid("the published key is not an EC P-256 key")
    if jwk.get("alg", ALG) != ALG or jwk.get("use", "sig") != "sig":
        raise _invalid("the published key is not an ES256 signature key")
    try:
        # Only the public members are imported, so the result can never be a private key.
        return ECKey.import_key({m: jwk[m] for m in ("kty", "crv", "x", "y")})
    except (KeyError, ValueError, JoseError):
        raise _invalid("the published key does not parse") from None


def verify_authorization(
    body: Mapping[str, Any], published_keys: Sequence[Mapping[str, Any]]
) -> VerifiedAuthorization:
    """Verify `body`'s merchant authorization against the merchant's published `keys[]`."""
    if not isinstance(body, Mapping):
        raise _invalid("the checkout must be a JSON object")
    detached = _detached(body)
    header_segment, signature_segment = detached.split("..")
    _, kid = _header(header_segment)
    if len(_unb64(signature_segment, "the signature")) != _SIGNATURE_LEN:
        raise _invalid("the signature must be 64 bytes")
    key = _published_key(published_keys, kid)
    payload = _covered(body)
    try:
        jws.deserialize_compact(detached, key, algorithms=ALLOWED_ALGORITHMS, payload=payload)
    except (JoseError, ValueError):
        raise _invalid("the signature does not verify") from None
    jwt = f"{header_segment}.{b64url(payload)}.{signature_segment}"
    return VerifiedAuthorization(kid=kid, payload=payload, checkout_jwt=jwt)


def checkout_jwt(body: Mapping[str, Any]) -> str:
    """Rebuild the compact `checkout_jwt` (Decision 7) from a signed response.

    This re-attaches the payload and does not verify; use `verify_authorization` for that. It does
    check the shapes it relies on, so a malformed value cannot yield a JWT-looking string.
    """
    detached = _detached(body)
    header_segment, signature_segment = detached.split("..")
    _header(header_segment)
    _unb64(signature_segment, "the signature")
    return f"{header_segment}.{b64url(_covered(body))}.{signature_segment}"

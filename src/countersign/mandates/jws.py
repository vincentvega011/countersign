"""Compact JWS handling for mandate links: algorithm allowlist, strict JSON, signature.

Security reasoning, in the order the checks run:

1. Header decoded with the strict JSON loader (INV-8) before anything reads it.
2. `alg` must be exactly `ES256`. The allowlist is applied to the header of every JWT in the
   chain, including the key-binding links, before a key is touched. Reason: algorithm confusion.
   `none` removes the signature, `HS256` verified with a public key as the secret lets anyone who
   knows the key forge, and a header-only swap (`alg` changed, signature kept) must not select a
   different verifier. The comparison is case-sensitive, so `es256` is refused too.
3. Header parameters that change how the signed bytes are read or where the key comes from are
   refused: `crit`, `b64` (RFC 7797 unencoded payload), `zip`, and embedded keys (`jwk`, `jku`,
   `x5u`, `x5c`). Keys come only from the caller (issuer) or the previous link's `cnf`.
4. `typ` must be one of the values the caller allows for this position. Reason: a key-binding
   link must not be replayable as an issuer credential and the reverse.
5. Payload decoded with the strict JSON loader and required to be an object.
6. The signature is verified over the received segments with the single allowed algorithm, by
   joserfc. A signature of the wrong length or with an empty segment is refused first.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from countersign.canonical import JsonValue, StrictJsonError, loads_strict
from countersign.mandates.errors import (
    AlgorithmNotAllowedError,
    HeaderParameterError,
    MandateJsonError,
    PayloadShapeError,
    SegmentCountError,
    SignatureInvalidError,
    TypMismatchError,
)
from countersign.mandates.structure import decode_b64url

ALLOWED_ALGORITHMS = ("ES256",)
_FORBIDDEN_HEADERS = ("crit", "b64", "zip", "jwk", "jku", "x5u", "x5c")
_ES256_SIGNATURE_BYTES = 64


@dataclass(frozen=True)
class ParsedJwt:
    """A JWT whose header and payload are decoded and checked, and whose signature is not yet."""

    compact: str
    header: dict[str, JsonValue]
    payload: dict[str, JsonValue]


def load_json_object(data: bytes, what: str) -> dict[str, JsonValue]:
    """Strict-load `data` and require an object. The loader's error is wrapped, never leaked."""
    try:
        value = loads_strict(data)
    except StrictJsonError as error:
        raise MandateJsonError(f"{what}: {error}", error.code) from None
    if not isinstance(value, dict):
        raise PayloadShapeError(f"{what} must be a JSON object")
    return value


def parse_jwt(compact: str, *, allowed_typ: Sequence[str]) -> ParsedJwt:
    """Decode and check a compact JWT up to, but not including, the signature."""
    segments = compact.split(".")
    if len(segments) != 3:
        raise SegmentCountError("a JWT must have exactly three segments")
    header = load_json_object(decode_b64url(segments[0], "JWT header"), "JWT header")
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_ALGORITHMS:
        raise AlgorithmNotAllowedError("JWT alg is not in the allowlist (ES256 only)")
    for name in _FORBIDDEN_HEADERS:
        if name in header:
            raise HeaderParameterError(f"JWT header parameter {name!r} is not accepted")
    typ = header.get("typ")
    if not isinstance(typ, str) or typ not in allowed_typ:
        raise TypMismatchError("JWT typ is not the value expected at this position")
    payload = load_json_object(decode_b64url(segments[1], "JWT payload"), "JWT payload")
    return ParsedJwt(compact, header, payload)


def verify_signature(jwt: ParsedJwt, key: ECKey) -> None:
    """Verify the ES256 signature of `jwt` with `key`, or raise `SignatureInvalidError`."""
    signature = jwt.compact.split(".")[2]
    if len(decode_b64url(signature, "JWT signature")) != _ES256_SIGNATURE_BYTES:
        raise SignatureInvalidError("JWT signature is missing or has the wrong length")
    try:
        jws.deserialize_compact(jwt.compact, key, algorithms=list(ALLOWED_ALGORITHMS))
    except (JoseError, ValueError):
        raise SignatureInvalidError("JWT signature does not verify") from None

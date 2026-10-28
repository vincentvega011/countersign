"""Extraction of the `cnf` confirmation key (RFC 7800 section 3.1) from a mandate.

AP2 mandates carry `cnf` inside the disclosed delegate payload as `{"jwk": {...}}`. The key it
names verifies the next link of the chain, so a wrong key here is a forged closed mandate.

Security reasoning. Only an inline P-256 public key is supported. The key is rebuilt from the
four members `kty`, `crv`, `x`, `y`, so nothing else in the JWK can influence verification. Typed
errors:

- `CnfMissingError`: no `cnf` where a key is required (a mandate that is open must name its agent).
- `CnfMalformedError`: not an object, no `jwk`, a missing or non-canonical coordinate, a point not
  on the curve, or private key material (`d`). A private key in a credential is a leak, never
  accepted.
- `CnfUnsupportedKeyError`: well formed but not usable here: other members besides `jwk` (`jwe`,
  `kid`, `jku` reference keys elsewhere), a key type or curve other than EC P-256, or `alg`, `use`
  or `key_ops` that forbid ES256 signature verification.
"""

from __future__ import annotations

from collections.abc import Mapping

from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from countersign.canonical import JsonValue
from countersign.mandates.errors import CnfMalformedError, CnfMissingError, CnfUnsupportedKeyError
from countersign.mandates.structure import decode_b64url

_COORDINATE_BYTES = 32


def extract_cnf_key(content: Mapping[str, JsonValue]) -> ECKey:
    """Return the P-256 public key named by `content["cnf"]`, or raise a typed error."""
    if "cnf" not in content:
        raise CnfMissingError("the mandate has no cnf claim")
    cnf = content["cnf"]
    if not isinstance(cnf, dict):
        raise CnfMalformedError("cnf must be an object")
    if "jwk" not in cnf:
        raise CnfUnsupportedKeyError("cnf must hold an inline jwk")
    if set(cnf) != {"jwk"}:
        raise CnfUnsupportedKeyError("cnf members other than jwk are not supported")
    jwk = cnf["jwk"]
    if not isinstance(jwk, dict):
        raise CnfMalformedError("cnf.jwk must be an object")
    if "d" in jwk:
        raise CnfMalformedError("cnf.jwk carries private key material")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise CnfUnsupportedKeyError("cnf.jwk must be an EC P-256 key")
    if jwk.get("alg", "ES256") != "ES256":
        raise CnfUnsupportedKeyError("cnf.jwk alg must be ES256 when present")
    if jwk.get("use", "sig") != "sig":
        raise CnfUnsupportedKeyError("cnf.jwk use must be sig when present")
    if "key_ops" in jwk and (
        not isinstance(jwk["key_ops"], list) or "verify" not in jwk["key_ops"]
    ):
        raise CnfUnsupportedKeyError("cnf.jwk key_ops must allow verify when present")
    coordinates: dict[str, str] = {}
    for name in ("x", "y"):
        value = jwk.get(name)
        if not isinstance(value, str):
            raise CnfMalformedError(f"cnf.jwk {name} must be a string")
        try:
            raw = decode_b64url(value, f"cnf.jwk {name}")
        except ValueError:
            raise CnfMalformedError(f"cnf.jwk {name} is not canonical base64url") from None
        if len(raw) != _COORDINATE_BYTES:
            raise CnfMalformedError(f"cnf.jwk {name} must be 32 bytes")
        coordinates[name] = value
    try:
        return ECKey.import_key({"kty": "EC", "crv": "P-256", **coordinates})
    except (JoseError, ValueError):
        raise CnfMalformedError("cnf.jwk is not a point on P-256") from None

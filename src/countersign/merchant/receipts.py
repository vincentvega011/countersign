"""Signed Checkout Receipts (vendored AP2 `checkout_receipt.json`, docs/PROTOCOL.md 1.2.7).

A receipt is a compact JWS signed with the merchant key whose payload is the JCS bytes of the
claims (INV-8). Claims: `status` (`Success` or `Error`), `iss`, `iat` (Unix seconds), `reference`
and, for `Success`, `order_id`; for `Error`, `error` (the UCP error code) and `error_description`
(the internal reason, a fixed string). Header: `alg` ES256, `kid`, and `typ` `checkout-receipt+jwt`.

Security reasoning. The merchant key also signs `merchant_authorization`, whose header has exactly
`alg` and `kid`. The receipt header adds `typ`, so a receipt can never verify as a
`merchant_authorization` and the reverse (that verifier requires exactly two members). Receipts
are integrity protected from the agent's LLM because only this code holds the key (AP2 "Double
Spend"). `reference` is the hash of the final SD-JWT of the presented chain, computed like
`sd_hash` (docs/PROTOCOL.md Decision 7). For a rejection where no chain could be parsed it is the
SHA-256 of the presented text (Decision 27).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from countersign.canonical import b64url, canonicalize, loads_strict, sd_hash
from countersign.canonical.jsonstrict import StrictJsonError
from countersign.mandates import split_chain
from countersign.mandates.errors import MandateError
from countersign.merchant.keys import ALG, MerchantKey

RECEIPT_TYP = "checkout-receipt+jwt"
SUCCESS = "Success"
ERROR = "Error"


class ReceiptError(Exception):
    """A receipt does not verify."""


def reference_for(presented: object) -> str:
    """The `reference` for whatever was presented: the final link hash, else a hash of the text."""
    if isinstance(presented, str):
        try:
            return sd_hash(split_chain(presented)[-1].serialization)
        except MandateError:
            return b64url(hashlib.sha256(presented.encode("utf-8", "replace")).digest())
    return b64url(hashlib.sha256(b"").digest())


def sign_receipt(claims: Mapping[str, Any], key: MerchantKey) -> str:
    return jws.serialize_compact(
        {"alg": ALG, "kid": key.kid, "typ": RECEIPT_TYP},
        canonicalize(dict(claims)),
        key.private_key,
        algorithms=[ALG],
    )


def success_claims(*, issuer: str, iat: int, reference: str, order_id: str) -> dict[str, Any]:
    return {
        "status": SUCCESS,
        "iss": issuer,
        "iat": iat,
        "reference": reference,
        "order_id": order_id,
    }


def error_claims(
    *, issuer: str, iat: int, reference: str, error: str, description: str
) -> dict[str, Any]:
    return {
        "status": ERROR,
        "iss": issuer,
        "iat": iat,
        "reference": reference,
        "error": error,
        "error_description": description,
    }


def verify_receipt(receipt: str, published_keys: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Verify a receipt against published merchant keys and return its claims."""
    try:
        header_segment = receipt.split(".")[0]
        header = loads_strict(_unb64(header_segment))
        if not isinstance(header, dict) or set(header) != {"alg", "kid", "typ"}:
            raise ReceiptError("the header must be exactly alg, kid and typ")
        if header["alg"] != ALG or header["typ"] != RECEIPT_TYP:
            raise ReceiptError("the header is not a checkout receipt header")
        matches = [k for k in published_keys if k.get("kid") == header["kid"]]
        if len(matches) != 1:
            raise ReceiptError("kid does not name exactly one published key")
        key = ECKey.import_key({m: matches[0][m] for m in ("kty", "crv", "x", "y")})
        result = jws.deserialize_compact(receipt, key, algorithms=[ALG])
        claims = loads_strict(result.payload)
    except (JoseError, StrictJsonError, KeyError, ValueError) as error:
        raise ReceiptError(str(error)) from None
    if not isinstance(claims, dict):
        raise ReceiptError("the claims must be an object")
    return claims


def _unb64(text: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

"""The identity of an issued mandate: a hash of what the issuer signed, never of how it is presented.

Security reasoning. Single use, the add-only budget and revocation all need a key for "this open
mandate". The digest of the serialization an agent presents (`sd_hash` of `<jwt>~<disclosures>~`) is not
that key: it covers the compact JWT, and an ES256 signature can be rewritten without the signing key
(replace `s` by `n - s`), so one signed mandate has two valid serializations and two digests. The
holder also chooses the order and number of disclosures that `verify_chain` is willing to tolerate.
Keying state on that digest would let one open mandate be presented as two.

The identity is computed from the signed payload only: the issuer (`iss`), the customer (`sub`), the
issue time, the digest list of `delegate_payload` (each digest covers the salt and the whole disclosed
content, including `vct`, `cnf`, `exp` and every constraint) and `_sd_alg`. None of these can be changed
without the issuer's key, none depends on the signature bytes, the key binding, the nonce or the
checkout, and the salt inside the disclosure makes every issuance unique. The hash is Countersign-
internal (`domain_hash`), so it can never be confused with an AP2 `sd_hash`.

Pure and deterministic (INV-1). The JCS bytes come from the single canonicalization module (INV-8).
"""

from __future__ import annotations

from collections.abc import Mapping

from countersign.canonical import JsonValue
from countersign.canonical.hashing import b64url, domain_hash
from countersign.canonical.jcs import canonicalize

IDENTITY_DOMAIN = "cs.mandate.identity.v1"


def mandate_identity(payload: Mapping[str, JsonValue], vct: str) -> str:
    """The identity of the credential whose signed (and verified) issuer payload is `payload`."""
    delegate = payload.get("delegate_payload")
    digests: list[JsonValue] = []
    if isinstance(delegate, list):
        for element in delegate:
            digests.append(element.get("...") if isinstance(element, dict) else None)
    body: dict[str, JsonValue] = {
        "v": 1,
        "iss": payload.get("iss"),
        "sub": payload.get("sub"),
        "iat": payload.get("iat"),
        "vct": vct,
        "sd_alg": payload.get("_sd_alg"),
        "delegate": digests,
    }
    return b64url(domain_hash(IDENTITY_DOMAIN, canonicalize(body)))

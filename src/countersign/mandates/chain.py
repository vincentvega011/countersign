"""Verification of an AP2 mandate chain: `<SD-JWT>~~<KB-SD-JWT>~<disclosures>~` (docs/PROTOCOL.md 1.2.3).

`verify_chain` is all-or-nothing: it returns a `VerifiedChain` only when every check below passed
for every link, and raises a `MandateError` subclass otherwise (INV-10). It is deterministic code
with no model input (INV-1). Which issuer key to trust, whether a nonce was used before, and what
the claims mean (constraints, amounts) are decisions for the caller, not this package.

Per link, in this order:

1. Structure of the whole string (`structure.split_chain`) and the number of links against the
   `vct` list the caller expects.
2. JWT header: strict JSON, ES256 allowlist, forbidden parameters, `typ` for the position
   (`parse_jwt`). The issuer link uses `dc+sd-jwt` (Decision 21); a key-binding link uses
   `kb+sd-jwt` when final and `kb-sd-jwt+kb` otherwise, as the draft verification text says.
3. Signature. Link 0 verifies with the caller's issuer key. Link n verifies with the `cnf` key of
   link n-1. This is the credential-to-key-binding direction: the signer of a key-binding link
   must be exactly the key the previous credential named. Without it, any holder could sign.
4. Disclosures resolved against the signed payload (`resolve_claims`); the content of the link is
   the single disclosed `delegate_payload` element.
5. `vct` equal to the expected string at this position. Missing is `VctMissingError`; anything
   else, including prefixes, other case, other versions and unknown values, is `VctMismatchError`.
6. Key binding links only: `aud` and `nonce` present, and for the final link equal to what the
   caller expects; `sd_hash` present and equal to the digest of the previous link's serialization
   including its trailing `~`. This is the key-binding-to-credential direction: the signed key
   binding commits to exactly the credential and disclosures it was presented with, so a holder
   cannot pair a key binding with another credential that reuses the same `cnf` key, nor drop a
   disclosure. `issuer_jwt_hash` alone is refused because it does not cover the disclosures.
7. `cnf`: required on every link that is followed by another link, validated on the last if present.
8. `exp`, `nbf`, `iat` with the 60 second skew. `exp` is required on every link that is not a
   final key-binding link (Decision 22).
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from joserfc.jwk import ECKey

from countersign.canonical import JsonValue, sd_hash
from countersign.mandates.cnf import extract_cnf_key
from countersign.mandates.disclosures import resolve_claims
from countersign.mandates.errors import (
    AudienceMismatchError,
    ChainLengthError,
    DelegatePayloadError,
    KeyBindingClaimError,
    NonceMismatchError,
    SdHashMismatchError,
    SdHashMissingError,
    UnknownExpectedVctError,
    VctMismatchError,
    VctMissingError,
)
from countersign.mandates.jws import ParsedJwt, parse_jwt, verify_signature
from countersign.mandates.structure import RawLink, split_chain
from countersign.mandates.timecheck import Clock, check_times

VCT_CHECKOUT = "mandate.checkout.1"
VCT_CHECKOUT_OPEN = "mandate.checkout.open.1"
VCT_PAYMENT = "mandate.payment.1"
VCT_PAYMENT_OPEN = "mandate.payment.open.1"
KNOWN_VCTS = frozenset({VCT_CHECKOUT, VCT_CHECKOUT_OPEN, VCT_PAYMENT, VCT_PAYMENT_OPEN})

ISSUER_JWT_TYP = ("dc+sd-jwt",)
KEY_BINDING_TYP_FINAL = ("kb+sd-jwt",)
KEY_BINDING_TYP_INTERMEDIATE = ("kb-sd-jwt+kb",)


@dataclass(frozen=True)
class VerifiedLink:
    """One verified link. `content` is the resolved delegate payload element (vct, cnf, ...)."""

    index: int
    vct: str
    content: Mapping[str, JsonValue]
    claims: Mapping[str, JsonValue]
    serialization: str
    digest: str
    cnf_thumbprint: str | None
    audience: str | None
    nonce: str | None


@dataclass(frozen=True)
class VerifiedChain:
    links: tuple[VerifiedLink, ...]

    @property
    def final(self) -> VerifiedLink:
        return self.links[-1]


def _delegate_content(jwt: ParsedJwt, claims: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
    signed = jwt.payload.get("delegate_payload")
    if (
        not isinstance(signed, list)
        or not signed
        or not all(isinstance(e, dict) and set(e) == {"..."} for e in signed)
    ):
        raise DelegatePayloadError("delegate_payload must be an array of disclosed elements")
    resolved = claims.get("delegate_payload")
    if not isinstance(resolved, list) or len(resolved) != 1 or not isinstance(resolved[0], dict):
        raise DelegatePayloadError("exactly one delegate_payload element must be disclosed")
    return resolved[0]


def _check_vct(content: Mapping[str, JsonValue], expected: str) -> str:
    if "vct" not in content:
        raise VctMissingError("the mandate has no vct")
    vct = content["vct"]
    if not isinstance(vct, str) or vct != expected:
        raise VctMismatchError("vct is not the exact string expected at this position")
    return vct


def _check_key_binding(
    claims: Mapping[str, JsonValue],
    previous: RawLink,
    *,
    audience: str | None,
    nonce: str | None,
) -> tuple[str, str]:
    for name in ("aud", "nonce"):
        if not isinstance(claims.get(name), str) or not claims[name]:
            raise KeyBindingClaimError(f"the key binding has no usable {name}")
    if "iat" not in claims:
        raise KeyBindingClaimError("the key binding has no iat")
    aud, nonce_claim = str(claims["aud"]), str(claims["nonce"])
    if audience is not None and aud != audience:
        raise AudienceMismatchError("the key binding aud is not this verifier")
    if nonce is not None and nonce_claim != nonce:
        raise NonceMismatchError("the key binding nonce is not the expected nonce")
    if "sd_hash" not in claims:
        raise SdHashMissingError("the key binding has no sd_hash (issuer_jwt_hash is not accepted)")
    if claims["sd_hash"] != sd_hash(previous.serialization):
        raise SdHashMismatchError("sd_hash does not match the preceding link as presented")
    return aud, nonce_claim


def verify_chain(
    token: str,
    *,
    issuer_key: ECKey,
    expected_vcts: Sequence[str],
    audience: str,
    nonce: str | None = None,
    clock: Clock = time.time,
) -> VerifiedChain:
    """Verify a whole mandate string. `expected_vcts[n]` is the exact `vct` of link n.

    `audience` and `nonce` are what the final key binding must carry. `nonce` is None only for a
    single-use check done elsewhere; the key binding must still carry a non-empty nonce.
    """
    if not expected_vcts or any(v not in KNOWN_VCTS for v in expected_vcts):
        raise UnknownExpectedVctError("expected_vcts must be a non-empty list of known vct strings")
    raw_links = split_chain(token)
    if len(raw_links) != len(expected_vcts):
        raise ChainLengthError(f"expected {len(expected_vcts)} links, got {len(raw_links)}")
    now = clock()
    key = issuer_key
    verified: list[VerifiedLink] = []
    for n, raw in enumerate(raw_links):
        final = n == len(raw_links) - 1
        if n == 0:
            typ = ISSUER_JWT_TYP
        else:
            typ = KEY_BINDING_TYP_FINAL if final else KEY_BINDING_TYP_INTERMEDIATE
        jwt = parse_jwt(raw.jwt, allowed_typ=typ)
        verify_signature(jwt, key)
        claims = resolve_claims(jwt.payload, raw.disclosures)
        content = _delegate_content(jwt, claims)
        vct = _check_vct(content, expected_vcts[n])
        aud: str | None = None
        nonce_claim: str | None = None
        if n > 0:
            aud, nonce_claim = _check_key_binding(
                claims,
                raw_links[n - 1],
                audience=audience if final else None,
                nonce=nonce if final else None,
            )
        thumbprint: str | None = None
        if not final or "cnf" in content:
            cnf_key = extract_cnf_key(content)
            thumbprint = cnf_key.thumbprint()
            key = cnf_key
        check_times(content, now, require_exp=not (final and n > 0))
        check_times(claims, now, require_exp=False)
        verified.append(
            VerifiedLink(
                n,
                vct,
                content,
                claims,
                raw.serialization,
                sd_hash(raw.serialization),
                thumbprint,
                aud,
                nonce_claim,
            )
        )
    return VerifiedChain(tuple(verified))

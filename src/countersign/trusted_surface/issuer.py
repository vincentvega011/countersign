"""The platform issuer: signs the open Checkout and Payment Mandates (PROTOCOL.md Decision 5).

Security reasoning. This is the only code that signs a mandate with the platform key, and it is called
only after the consent verifier (`service.TrustedSurface.consent`) has checked the device signature
and rebuilt the contents. It still refuses on its own account to build anything the verifier side
could not treat as one plain, whole credential:

- the issuer JWT always carries `sub`, the customer id, as a plaintext top-level claim: a verifier
  needs it to name the principal, and a top-level claim the agent cannot withhold (Decision 47);
- the content of a mandate is one disclosed `delegate_payload` element, and **no constraint element
  is selectively disclosable**: every member of `constraints` is a plain object inside that content,
  never a `{"...": digest}` placeholder and never behind an `_sd` list (L31). Whole elements being
  withheld or reordered by the holder would change what a mandate means and what its digest covers.

`cnf` is the agent's public key. `exp` and the constraints come from the record the customer signed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any

from joserfc import jws
from joserfc.jwk import ECKey

from countersign.canonical.hashing import sd_hash
from countersign.mandates import VCT_CHECKOUT_OPEN, VCT_PAYMENT_OPEN

ISSUER_TYP = "dc+sd-jwt"


class IssuerRefused(Exception):
    """The issuer will not sign this content. `code` is stable."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class OpenMandate:
    token: str  # `<issuer JWT>~<content disclosure>~`, ready for the agent to bind to
    digest: str  # `sd_hash` of `token`: the open mandate's identity


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _compact(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def check_constraints(constraints: Any) -> None:
    """Refuse selective disclosure of a whole constraint element (L31)."""
    if not isinstance(constraints, list) or not constraints:
        raise IssuerRefused("constraints_missing")
    for element in constraints:
        if not isinstance(element, dict):
            raise IssuerRefused("constraint_element_not_plain")
        if "..." in element or "_sd" in element or "_sd_alg" in element:
            raise IssuerRefused("constraint_element_disclosure")
        if not isinstance(element.get("type"), str):
            raise IssuerRefused("constraint_element_not_plain")


def issue_open_mandate(
    content: dict[str, Any],
    *,
    kind: str,
    customer_id: str,
    agent_jwk: dict[str, str],
    issuer: str,
    key: ECKey,
    now_s: int,
) -> OpenMandate:
    """Sign one open mandate. `content` has `vct`, `exp` and `constraints` (no `cnf`, no `iat`)."""
    expected_vct = {"checkout": VCT_CHECKOUT_OPEN, "payment": VCT_PAYMENT_OPEN}.get(kind)
    if expected_vct is None or content.get("vct") != expected_vct:
        raise IssuerRefused("vct_mismatch")
    if not isinstance(customer_id, str) or not customer_id or customer_id != customer_id.strip():
        raise IssuerRefused("subject_missing")
    if set(content) - {"vct", "exp", "constraints"}:
        raise IssuerRefused("content_members")
    check_constraints(content["constraints"])
    if not key.is_private:
        raise IssuerRefused("signing_key_not_private")
    full = {**content, "cnf": {"jwk": dict(agent_jwk)}, "iat": now_s}
    disclosure = _b64(_compact([_b64(secrets.token_bytes(16)), full]))
    digest = _b64(hashlib.sha256(disclosure.encode("ascii")).digest())
    payload = {
        "iss": issuer,
        "sub": customer_id,
        "iat": now_s,
        "delegate_payload": [{"...": digest}],
        "_sd_alg": "sha-256",
    }
    header = {"alg": "ES256", "typ": ISSUER_TYP, "kid": key.thumbprint()}
    compact = jws.serialize_compact(header, _compact(payload), key, algorithms=["ES256"])
    token = f"{compact}~{disclosure}~"
    return OpenMandate(token, sd_hash(token))

"""Human Present approval: the customer signs the exact merchant-signed checkout (Decisions 29, 90).

Security reasoning. The page must show, and the device key must sign, exactly what the merchant signed
and what the platform will then sign for. So:

- **An offer** is the merchant-signed checkout JWT the backend holds. `create_offer` loads the session
  from the database (never from the client), signs it with the merchant key, verifies its own
  `merchant_authorization` against the published keys and builds the terms the page shows from the
  VERIFIED payload. Nothing is shown before that verification. The JWT, its hash and the terms are stored
  insert only, so the hash the customer signs names one specific JWT.
- **The consent record** is the JCS of terms, offer id and the closed mandate contents. The device key
  signs it; the backend rebuilds the terms from the stored offer and the contents from the terms, and
  requires byte equality with the record (`consent_claims_mismatch`) before the platform key signs.
- **Freshness**: the checkout is re-read at consent time. If it is no longer `ready_for_complete`, is
  expired, or its terms differ from the signed ones, no mandate is issued (`checkout_not_ready`,
  `checkout_expired`, `checkout_changed`). The stored JWT's authorization is verified again.
- **Distinct purposes**: the record purpose and the challenge purpose differ from the open-mandate
  consent, so a signature for one cannot serve as the other. `purchase_consents` is insert only with a
  unique offer id and a unique challenge: a replay is `offer_used` or `challenge_used`.

The page renders these terms with fixed templates; the only strings are the merchant's own item titles
and name from the signed checkout and the store record, never model text (INV-2). Deterministic (INV-1).
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from countersign.canonical import HashInputError
from countersign.canonical import checkout_hash as hash_checkout_jwt
from countersign.canonical.hashing import b64url
from countersign.canonical.jcs import JcsError, canonicalize
from countersign.canonical.jsonstrict import StrictJsonError, loads_strict
from countersign.canonical.models import Checkout
from countersign.checkout.state import Status
from countersign.checkout.store import load as load_checkout
from countersign.mandates import VCT_CHECKOUT, VCT_PAYMENT
from countersign.mandates.structure import decode_b64url
from countersign.merchant.authorization import (
    AuthorizationError,
    checkout_jwt,
    sign_checkout,
    verify_authorization,
)
from countersign.merchant.keys import MerchantKey
from countersign.protocols.ucp.responses import checkout_response
from countersign.tables import purchase_consents, purchase_offers
from countersign.trusted_surface.consent import MAX_RECORD_SECONDS, SKEW_SECONDS, ConsentRefused
from countersign.trusted_surface.issuer import issue_closed_mandate
from countersign.trusted_surface.keys import validate_public_jwk, verify_signature

if TYPE_CHECKING:
    from countersign.trusted_surface.service import TrustedSurface

PURPOSE_CHECKOUT = "countersign.consent.checkout.v1"
CHALLENGE_PURPOSE_CHECKOUT = "consent_checkout"
OFFER_TTL_US = 10 * 60 * 1_000_000
MANDATE_SECONDS = 900
OFFER_ID = re.compile(r"off_[A-Za-z0-9_-]{22}")
CHECKOUT_ID = re.compile(r"chk_[A-Za-z0-9_-]{22}")
LOG_KIND_OFFER = "ts.purchase.offered"
LOG_KIND_REFUSED = "ts.purchase.refused"
LOG_KIND_ISSUED = "ts.purchase.issued"
INSTRUMENT = {"id": "wallet", "type": "wallet", "description": "Payment wallet"}
RECORD_MEMBERS = frozenset(
    {
        "v", "purpose", "customer_id", "device_thumbprint", "challenge_id", "challenge",
        "issued_at", "expires_at", "origin", "offer_id", "terms", "mandate",
    }
)  # fmt: skip


@dataclass(frozen=True)
class Offer:
    offer_id: str
    terms: dict[str, Any]
    checkout_hash: str
    expires_us: int


@dataclass(frozen=True)
class Purchased:
    consent_id: str
    customer_id: str
    checkout_id: str
    checkout_mandate: str
    payment_mandate: str
    expires_at: int


def build_terms(
    checkout: Checkout, *, merchant: dict[str, str], checkout_expires_at: int
) -> dict[str, Any]:
    """The structured terms of a verified checkout, in integer minor units (INV-9)."""
    total = next(t.amount for t in checkout.totals if t.type == "total")
    return {
        "merchant": dict(merchant),
        "checkout_id": checkout.id,
        "currency": checkout.currency,
        "items": [
            {
                "id": line.item.id, "title": line.item.title, "quantity": line.quantity,
                "unit_minor": line.item.price.minor,
                "line_minor": next(t.amount.minor for t in line.totals if t.type == "subtotal"),
            }
            for line in checkout.line_items
        ],
        "totals": [{"type": str(t.type), "amount_minor": t.amount.minor} for t in checkout.totals],
        "total_minor": total.minor,
        "checkout_expires_at": checkout_expires_at,
    }  # fmt: skip


def mandate_expiry(checkout_expires_at: int, issued_at: int) -> int:
    return min(checkout_expires_at, issued_at + MANDATE_SECONDS)


def build_closed(terms: dict[str, Any], checkout_hash: str, issued_at: int) -> dict[str, Any]:
    """The contents of the two closed mandates for these terms, before the platform's own fields."""
    exp = mandate_expiry(int(terms["checkout_expires_at"]), issued_at)
    return {
        "checkout": {"vct": VCT_CHECKOUT, "checkout_hash": checkout_hash, "exp": exp},
        "payment": {
            "vct": VCT_PAYMENT,
            "transaction_id": checkout_hash,
            "payee": dict(terms["merchant"]),
            "payment_amount": {"amount": terms["total_minor"], "currency": terms["currency"]},
            "payment_instrument": dict(INSTRUMENT),
            "exp": exp,
        },
    }


def _verified_checkout(jwt: str, published: list[dict[str, Any]]) -> Checkout:
    """Verify a stored or fresh checkout JWT's `merchant_authorization` and parse its payload."""
    parts = jwt.split(".")
    if len(parts) != 3 or not all(parts):
        raise ConsentRefused("merchant_authorization_invalid", "jwt shape")
    try:
        payload = loads_strict(decode_b64url(parts[1], "checkout"))
    except (StrictJsonError, ValueError, Exception):  # noqa: BLE001 - any parse error refuses
        raise ConsentRefused("merchant_authorization_invalid", "payload") from None
    if not isinstance(payload, dict):
        raise ConsentRefused("merchant_authorization_invalid", "payload")
    body = dict(payload)
    body["ap2"] = {"merchant_authorization": f"{parts[0]}..{parts[2]}"}
    try:
        verified = verify_authorization(body, published)
    except AuthorizationError:
        raise ConsentRefused("merchant_authorization_invalid", "signature") from None
    if verified.checkout_jwt != jwt:
        raise ConsentRefused("merchant_authorization_invalid", "not canonical")
    try:
        return Checkout.from_ucp(payload)
    except ValueError:
        raise ConsentRefused("merchant_authorization_invalid", "terms") from None


def create_offer(ts: TrustedSurface, checkout_id: object) -> Offer:
    """Sign the stored session, verify our own signature, store the JWT and return its terms."""
    from countersign.trusted_surface.service import _Seen

    def work() -> Offer:
        key = ts.merchant_key
        if key is None:
            raise ts.refusal_for("signing_unavailable")
        if not isinstance(checkout_id, str) or CHECKOUT_ID.fullmatch(checkout_id) is None:
            raise ts.refusal_for("checkout_unknown")
        with ts.engine.begin() as conn:
            now_us = ts.now_us()
            record = load_checkout(conn, checkout_id)
            if record is None:
                raise ts.refusal_for("checkout_unknown")
            if record.status is not Status.READY_FOR_COMPLETE:
                raise ts.refusal_for("checkout_not_ready")
            if now_us >= record.expires_us:
                raise ts.refusal_for("checkout_expired")
            body = sign_checkout(
                checkout_response(record.checkout, record.status, record.expires_us), key
            )
            jwt = checkout_jwt(body)
            verified = _verified_checkout(jwt, [dict(key.public_jwk)])
            if verified.terms_bytes() != record.checkout.terms_bytes():
                raise ConsentRefused("checkout_changed", "signed differs from stored")
            terms = build_terms(
                verified,
                merchant=ts.merchant.as_dict(),
                checkout_expires_at=record.expires_us // 1_000_000,
            )
            offer_id = "off_" + secrets.token_urlsafe(16)
            conn.execute(
                purchase_offers.insert().values(
                    id=offer_id, checkout_id=checkout_id, checkout_jwt=jwt,
                    checkout_hash=hash_checkout_jwt(jwt), terms=canonicalize(terms).decode(),
                    created_us=now_us,
                )
            )  # fmt: skip
            ts.append(
                conn, LOG_KIND_OFFER, now_us,
                {"offer_id": offer_id, "checkout_id": checkout_id,
                 "checkout_hash": hash_checkout_jwt(jwt)},
            )  # fmt: skip
            return Offer(offer_id, terms, hash_checkout_jwt(jwt), now_us + OFFER_TTL_US)

    result: Offer = ts.guard(LOG_KIND_REFUSED, _Seen(), work)
    return result


def _parse_record(value: Any) -> dict[str, Any]:
    bad = "consent_malformed"
    if not isinstance(value, dict) or set(value) != RECORD_MEMBERS:
        raise ConsentRefused(bad, "record members")
    if type(value["v"]) is not int or value["v"] != 1:
        raise ConsentRefused(bad, "version")
    if value["purpose"] != PURPOSE_CHECKOUT:
        raise ConsentRefused("consent_purpose_mismatch")
    text = re.compile(r"[\x20-\x7e]{1,200}")
    if not (
        isinstance(value["customer_id"], str) and re.fullmatch(r"cus_[A-Za-z0-9_-]{22}", value["customer_id"])
        and isinstance(value["device_thumbprint"], str)
        and re.fullmatch(r"[A-Za-z0-9_-]{43}", value["device_thumbprint"])
        and all(isinstance(value[k], str) and text.fullmatch(value[k])
                for k in ("challenge_id", "challenge", "origin", "offer_id"))
        and type(value["issued_at"]) is int and type(value["expires_at"]) is int
        and isinstance(value["terms"], dict) and isinstance(value["mandate"], dict)
    ):  # fmt: skip
        raise ConsentRefused(bad, "scalar members")
    return value


def consent_purchase(
    ts: TrustedSurface,
    *,
    record: object,
    signature: object,
    origin_header: str | None = None,
) -> Purchased:
    from countersign.trusted_surface.service import CHALLENGE_ID, _Seen

    seen = _Seen()

    def work() -> Purchased:
        if not isinstance(signature, str):
            raise ConsentRefused("consent_malformed", "signature")
        raw = _parse_record(record)
        seen.challenge_id = (
            raw["challenge_id"] if CHALLENGE_ID.fullmatch(raw["challenge_id"]) else None
        )
        seen.thumbprint = raw["device_thumbprint"]
        if seen.challenge_id is None or OFFER_ID.fullmatch(raw["offer_id"]) is None:
            raise ConsentRefused("consent_malformed", "ids")
        ts.check_origin(raw["origin"], origin_header)
        platform, key = ts.platform_key, ts.merchant_key
        if platform is None or not platform.is_private or key is None:
            raise ts.refusal_for("signing_unavailable")
        try:
            record_bytes = canonicalize(raw)
        except JcsError:
            raise ConsentRefused("consent_malformed", "not canonicalizable") from None
        with ts.engine.begin() as conn:
            now_us = ts.now_us()
            now_s = now_us // 1_000_000
            ts.lock_customer(conn, raw["customer_id"])
            challenge = ts.challenge(
                conn, seen.challenge_id, CHALLENGE_PURPOSE_CHECKOUT, now_us, nonce=raw["challenge"]
            )
            device = ts.key_by_thumbprint(conn, raw["device_thumbprint"])
            if device is None:
                raise ts.refusal_for("device_key_unknown")
            if device.customer_id != raw["customer_id"]:
                raise ts.refusal_for("device_key_customer_mismatch")
            if device.rev is not None:
                raise ts.refusal_for("device_key_revoked")
            from countersign.trusted_surface.service import _loads_jwk

            public = validate_public_jwk(_loads_jwk(device.jwk))
            if not verify_signature(public.verifying_key(), record_bytes, signature):
                raise ts.refusal_for("consent_signature_invalid")
            lifetime = raw["expires_at"] - raw["issued_at"]
            if not 0 < lifetime <= MAX_RECORD_SECONDS or raw["issued_at"] > now_s + SKEW_SECONDS:
                raise ConsentRefused("consent_time_invalid")
            if now_s >= raw["expires_at"]:
                raise ts.refusal_for("consent_expired")
            if raw["issued_at"] != int(challenge.created_us) // 1_000_000:
                raise ConsentRefused("consent_time_invalid", "issued_at is not the challenge's")

            offer = conn.execute(
                select(purchase_offers).where(purchase_offers.c.id == raw["offer_id"])
            ).first()
            if offer is None:
                raise ts.refusal_for("offer_unknown")
            if now_us >= int(offer.created_us) + OFFER_TTL_US:
                raise ts.refusal_for("offer_expired")
            if (
                conn.execute(
                    select(purchase_consents.c.id).where(purchase_consents.c.offer_id == offer.id)
                ).first()
                is not None
            ):
                raise ts.refusal_for("offer_used")

            # The checkout as it is NOW, and the signed one, must still be the same checkout.
            current = load_checkout(conn, str(offer.checkout_id))
            if current is None:
                raise ts.refusal_for("checkout_unknown")
            if current.status is not Status.READY_FOR_COMPLETE:
                raise ConsentRefused("checkout_not_ready", f"status {current.status.value}"[:40])
            if now_us >= current.expires_us:
                raise ConsentRefused("checkout_expired")
            signed = _verified_checkout(str(offer.checkout_jwt), [dict(key.public_jwk)])
            if signed.terms_bytes() != current.checkout.terms_bytes():
                raise ConsentRefused("checkout_changed")
            terms = build_terms(
                signed,
                merchant=ts.merchant.as_dict(),
                checkout_expires_at=current.expires_us // 1_000_000,
            )
            if canonicalize(terms) != canonicalize(raw["terms"]):
                raise ConsentRefused("consent_claims_mismatch", "terms")
            expected = build_closed(terms, str(offer.checkout_hash), raw["issued_at"])
            if canonicalize(expected) != canonicalize(raw["mandate"]):
                raise ConsentRefused("consent_claims_mismatch", "mandate")

            customer = raw["customer_id"]
            checkout_mandate = issue_closed_mandate(
                expected["checkout"], kind="checkout", customer_id=customer, issuer=ts.issuer_name,
                key=platform, now_s=now_s, checkout_jwt=str(offer.checkout_jwt),
            )  # fmt: skip
            payment_mandate = issue_closed_mandate(
                expected["payment"], kind="payment", customer_id=customer, issuer=ts.issuer_name,
                key=platform, now_s=now_s,
            )  # fmt: skip
            ts.consume(conn, seen.challenge_id, device.thumbprint, now_us)
            consent_id = "pcn_" + secrets.token_urlsafe(16)
            try:
                with conn.begin_nested():
                    conn.execute(
                        purchase_consents.insert().values(
                            id=consent_id, offer_id=offer.id, challenge_id=seen.challenge_id,
                            customer_id=customer, device_thumbprint=device.thumbprint,
                            device_jwk=device.jwk, record=record_bytes.decode(),
                            signature=signature, checkout_mandate=checkout_mandate.token,
                            payment_mandate=payment_mandate.token, created_us=now_us,
                        )
                    )  # fmt: skip
            except IntegrityError:
                raise ts.refusal_for("offer_used") from None
            ts.append(
                conn, LOG_KIND_ISSUED, now_us,
                {
                    "consent_id": consent_id, "customer_id": customer, "offer_id": offer.id,
                    "checkout_id": str(offer.checkout_id), "challenge_id": seen.challenge_id,
                    "device_thumbprint": device.thumbprint,
                    "record_hash": b64url(hashlib.sha256(record_bytes).digest()),
                    "checkout_mandate_identity": checkout_mandate.identity,
                    "payment_mandate_identity": payment_mandate.identity,
                },
            )  # fmt: skip
            return Purchased(
                consent_id, customer, str(offer.checkout_id), checkout_mandate.token,
                payment_mandate.token, int(expected["checkout"]["exp"]),
            )  # fmt: skip

    result: Purchased = ts.guard(LOG_KIND_REFUSED, seen, work)
    return result


__all__ = [
    "CHALLENGE_PURPOSE_CHECKOUT", "PURPOSE_CHECKOUT", "HashInputError", "MerchantKey",
    "Offer", "Purchased", "build_closed", "build_terms", "consent_purchase", "create_offer",
]  # fmt: skip

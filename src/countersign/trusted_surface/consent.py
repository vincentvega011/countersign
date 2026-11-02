"""The consent record and the mandate contents rebuilt from it (PROTOCOL.md Decision 5, Decision 81).

Security reasoning. The customer's device key signs one JSON record: the terms the customer saw
(merchant, items, ceiling, expiry, agent key) and, beside them, the contents of the open mandates the
platform will sign for those terms. The page renders the terms from this record with fixed templates,
and signs the JCS bytes of this same record. The backend does not trust the contents: it rebuilds them
itself from the terms with `build_mandate` and requires the JCS bytes to be equal (a check of "what
you saw is what gets signed"). A page, a script or a request that changes one member after the person
looked changes the bytes and so the signature, and a record whose contents do not follow from its own
terms is refused even when the signature is valid.

What the platform adds after verification, and the customer therefore does not sign byte for byte:
`iat`, `cnf` (the agent key, whose thumbprint is in the terms and is checked), the issuer JWT `sub` (the
customer id, which the record names and the device key vouches for) and the `payment.reference`
constraint (the digest of the open Checkout Mandate, which exists only after that mandate is signed).
Everything else in a mandate is in the record.

Everything here is deterministic and pure: no clock, no database, no model (INV-1). Money is integer
minor units (INV-9). Numbers are Python `int` and never `bool`.
"""

from __future__ import annotations

import re
from typing import Any

from countersign.catalog.catalog import Catalog
from countersign.mandates import VCT_CHECKOUT_OPEN, VCT_PAYMENT_OPEN

PURPOSE_CONSENT = "countersign.consent.open-mandates.v1"
CHALLENGE_PURPOSE_CONSENT = "consent_open_mandates"
RECORD_VERSION = 1
CURRENCY = "USD"
MAX_ITEMS = 10
MAX_QUANTITY = 99
MAX_CEILING_MINOR = 1_000_000
MIN_MANDATE_SECONDS = 60
MAX_MANDATE_SECONDS = 14 * 24 * 3600
MAX_RECORD_SECONDS = 600
SKEW_SECONDS = 60
MAX_TEXT = 200

RECORD_MEMBERS = frozenset(
    {
        "v", "purpose", "customer_id", "device_thumbprint", "challenge_id", "challenge",
        "issued_at", "expires_at", "origin", "terms", "mandate",
    }
)  # fmt: skip
TERMS_MEMBERS = frozenset(
    {"merchant", "items", "ceiling_minor", "currency", "mandate_expires_at", "agent_thumbprint"}
)
MERCHANT_MEMBERS = frozenset({"id", "name", "website"})
ITEM_MEMBERS = frozenset({"id", "title", "quantity"})
_PRINTABLE = re.compile(rf"[\x20-\x7e]{{1,{MAX_TEXT}}}")
_THUMBPRINT = re.compile(r"[A-Za-z0-9_-]{43}")
_CUSTOMER = re.compile(r"cus_[A-Za-z0-9_-]{22}")


class ConsentRefused(Exception):
    """A consent check failed. `code` is the stable answer code; `detail` goes to the log only."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _int(value: Any) -> bool:
    return type(value) is int


def _text(value: Any) -> bool:
    return isinstance(value, str) and _PRINTABLE.fullmatch(value) is not None


class Terms:
    """The structured terms exactly as they sit in the record (no interpretation)."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.raw = raw
        self.merchant: dict[str, str] = raw["merchant"]
        self.items: list[dict[str, Any]] = raw["items"]
        self.ceiling_minor: int = raw["ceiling_minor"]
        self.currency: str = raw["currency"]
        self.mandate_expires_at: int = raw["mandate_expires_at"]
        self.agent_thumbprint: str = raw["agent_thumbprint"]


class ConsentRecord:
    def __init__(self, raw: dict[str, Any]) -> None:
        self.raw = raw
        self.customer_id: str = raw["customer_id"]
        self.device_thumbprint: str = raw["device_thumbprint"]
        self.challenge_id: str = raw["challenge_id"]
        self.nonce: str = raw["challenge"]
        self.issued_at: int = raw["issued_at"]
        self.expires_at: int = raw["expires_at"]
        self.origin: str = raw["origin"]
        self.terms = Terms(raw["terms"])
        self.mandate: dict[str, Any] = raw["mandate"]


def parse_record(value: Any) -> ConsentRecord:
    """The shape of a record: exact members, exact types. Nothing about what the values mean."""
    bad = "consent_malformed"
    if not isinstance(value, dict) or set(value) != RECORD_MEMBERS:
        raise ConsentRefused(bad, "record members")
    if not _int(value["v"]) or value["v"] != RECORD_VERSION:
        raise ConsentRefused(bad, "version")
    if value["purpose"] != PURPOSE_CONSENT:
        raise ConsentRefused("consent_purpose_mismatch")
    if not (
        isinstance(value["customer_id"], str) and _CUSTOMER.fullmatch(value["customer_id"])
        and isinstance(value["device_thumbprint"], str)
        and _THUMBPRINT.fullmatch(value["device_thumbprint"])
        and _text(value["challenge_id"]) and _text(value["challenge"]) and _text(value["origin"])
        and _int(value["issued_at"]) and _int(value["expires_at"])
    ):  # fmt: skip
        raise ConsentRefused(bad, "scalar members")
    terms = value["terms"]
    if not isinstance(terms, dict) or set(terms) != TERMS_MEMBERS:
        raise ConsentRefused(bad, "terms members")
    merchant = terms["merchant"]
    if (
        not isinstance(merchant, dict)
        or set(merchant) != MERCHANT_MEMBERS
        or not all(_text(merchant[k]) for k in MERCHANT_MEMBERS)
    ):
        raise ConsentRefused(bad, "merchant")
    items = terms["items"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        raise ConsentRefused(bad, "items")
    for item in items:
        if (
            not isinstance(item, dict)
            or set(item) != ITEM_MEMBERS
            or not _text(item["id"]) or not _text(item["title"]) or not _int(item["quantity"])
        ):  # fmt: skip
            raise ConsentRefused(bad, "item")
    if not (
        _int(terms["ceiling_minor"]) and _text(terms["currency"])
        and _int(terms["mandate_expires_at"])
        and isinstance(terms["agent_thumbprint"], str)
        and _THUMBPRINT.fullmatch(terms["agent_thumbprint"])
    ):  # fmt: skip
        raise ConsentRefused(bad, "terms scalars")
    if not isinstance(value["mandate"], dict):
        raise ConsentRefused(bad, "mandate")
    return ConsentRecord(value)


def validate_terms(
    terms: Terms,
    *,
    merchant: dict[str, str],
    catalog: Catalog,
    now_s: int,
    record_expires_at: int,
) -> None:
    """What the terms mean: a real merchant, real items, a sane ceiling and a short expiry."""
    bad = "consent_terms_invalid"
    if terms.merchant != merchant:
        raise ConsentRefused(bad, "merchant is not this store")
    if terms.currency != CURRENCY:
        raise ConsentRefused(bad, "currency")
    if not 1 <= terms.ceiling_minor <= MAX_CEILING_MINOR:
        raise ConsentRefused(bad, "ceiling")
    by_id = {item.id: item for item in catalog.items}
    seen: set[str] = set()
    for entry in terms.items:
        found = by_id.get(entry["id"])
        if found is None or found.title != entry["title"]:
            raise ConsentRefused(bad, "item is not in the catalog as shown")
        if not 1 <= entry["quantity"] <= MAX_QUANTITY or entry["id"] in seen:
            raise ConsentRefused(bad, "quantity or duplicate item")
        seen.add(entry["id"])
    lifetime = terms.mandate_expires_at - now_s
    if not MIN_MANDATE_SECONDS <= lifetime <= MAX_MANDATE_SECONDS:
        raise ConsentRefused(bad, "mandate expiry out of range")
    if terms.mandate_expires_at < record_expires_at:
        raise ConsentRefused(bad, "mandate expires before the consent does")


def build_mandate(terms: Terms) -> dict[str, Any]:
    """The contents of the two open mandates for these terms, before the platform's own fields.

    Native AP2 constraints only (no Countersign constraint types, Decision 4): the checkout mandate
    has `checkout.line_items` and `checkout.allowed_merchants`; the payment mandate has
    `payment.amount_range`, `payment.allowed_payees`, `payment.budget` and `payment.agent_recurrence`
    (one occurrence). `payment.reference` is added by the platform once the checkout mandate exists.
    """
    merchant = dict(terms.merchant)
    lines = [
        {
            "id": f"line_{n}",
            "acceptable_items": [{"id": item["id"], "title": item["title"]}],
            "quantity": item["quantity"],
        }
        for n, item in enumerate(terms.items, start=1)
    ]
    return {
        "checkout": {
            "vct": VCT_CHECKOUT_OPEN,
            "exp": terms.mandate_expires_at,
            "constraints": [
                {"type": "checkout.line_items", "items": lines},
                {"type": "checkout.allowed_merchants", "allowed": [dict(merchant)]},
            ],
        },
        "payment": {
            "vct": VCT_PAYMENT_OPEN,
            "exp": terms.mandate_expires_at,
            "constraints": [
                {
                    "type": "payment.amount_range", "currency": terms.currency, "min": 1,
                    "max": terms.ceiling_minor,
                },
                {"type": "payment.allowed_payees", "allowed": [dict(merchant)]},
                {"type": "payment.budget", "max": terms.ceiling_minor, "currency": terms.currency},
                {"type": "payment.agent_recurrence", "frequency": "ON_DEMAND", "max_occurrences": 1},
            ],
        },
    }  # fmt: skip


def mismatch_part(claimed: dict[str, Any], expected: dict[str, Any]) -> str:
    """Which part of the claimed contents differs from the rebuild, for the log."""
    for part in ("checkout", "payment"):
        if claimed.get(part) != expected[part]:
            return part
    return "other"

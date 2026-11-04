"""What the service keeps of the PayPal objects it reads: an allowlisted copy, never a header or a payer.

Security reasoning. The evidence bundle carries the order, authorization and capture "as fetched". PayPal
answers carry more than the evidence needs: a payer's name and email, a payee email, shipping, links with
tokens in some cases. Only the members listed here are copied, at every depth; every other member is
dropped before anything is stored, so a new member PayPal adds can never reach the store by accident.
Headers and the access token are never passed in (the client hands over the parsed JSON body of a GET
only). Decision 103.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import Engine, insert

from countersign.canonical import canonicalize
from countersign.tables import paypal_observations

MONEY = {"currency_code": None, "value": None}
AUTH = {
    "id": None, "status": None, "amount": MONEY, "invoice_id": None, "custom_id": None,
    "create_time": None, "expiration_time": None, "update_time": None,
}  # fmt: skip
CAPTURE = {
    "id": None, "status": None, "amount": MONEY, "final_capture": None, "invoice_id": None,
    "custom_id": None, "create_time": None, "update_time": None,
}  # fmt: skip
ITEM = {
    "name": None, "quantity": None, "unit_amount": MONEY, "tax": MONEY, "sku": None,
    "category": None,
}  # fmt: skip
BREAKDOWN = {
    k: MONEY
    for k in ("item_total", "tax_total", "shipping", "handling", "insurance",
              "shipping_discount", "discount")
}  # fmt: skip
UNIT = {
    "reference_id": None, "invoice_id": None, "custom_id": None,
    "amount": {**MONEY, "breakdown": BREAKDOWN}, "items": [ITEM], "payee": {"merchant_id": None},
    "payments": {"authorizations": [AUTH], "captures": [CAPTURE]},
}  # fmt: skip
ORDER = {"id": None, "status": None, "intent": None, "purchase_units": [UNIT]}
SPECS: dict[str, dict[str, Any]] = {"order": ORDER, "authorization": AUTH, "capture": CAPTURE}


def pick(value: Any, spec: Any) -> Any:
    """Copy `value` keeping only what `spec` lists (None: a plain scalar, dict: members, [spec]: a list)."""
    if spec is None:
        return value if isinstance(value, (str, int, bool)) else None
    if isinstance(spec, list):
        return [pick(v, spec[0]) for v in value] if isinstance(value, list) else []
    if not isinstance(value, dict):
        return {}
    return {k: pick(value[k], s) for k, s in spec.items() if k in value}


def sanitize(kind: str, body: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = pick(body, SPECS[kind])
    return result


class PayPalObserver:
    """Stores a sanitized copy of every order, authorization and capture the PayPal client reads."""

    def __init__(self, engine: Engine, clock_us: Callable[[], int]) -> None:
        self._engine = engine
        self._clock_us = clock_us

    def __call__(self, kind: str, body: dict[str, Any]) -> None:
        if kind not in SPECS:
            return
        clean = sanitize(kind, body)
        object_id = clean.get("id")
        if not isinstance(object_id, str):
            return
        with self._engine.begin() as conn:
            conn.execute(
                insert(paypal_observations).values(
                    kind=kind, object_id=object_id, body=canonicalize(clean).decode(),
                    observed_us=self._clock_us(),
                )
            )  # fmt: skip

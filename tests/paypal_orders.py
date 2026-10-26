"""Helpers that turn a create-order request into the order PayPal would return from GET.

PayPal echoes the purchase unit it was sent and adds the payee (observed in the recorded cassette,
tests/cassettes/paypal_authorize_capture.json), so a request body plus a payee is a faithful stand-in.
"""

from __future__ import annotations

import copy
from typing import Any

from countersign.paypal.models import ExperienceContext, Order, OrderRequest

MERCHANT = "MERCHANT123"
CONTEXT = ExperienceContext("https://example.com/r", "https://example.com/c")


def live_order_json(request: OrderRequest, merchant: str = MERCHANT) -> dict[str, Any]:
    unit = copy.deepcopy(request.to_json()["purchase_units"][0])
    unit["payee"] = {"merchant_id": merchant}
    return {
        "id": "ORDER1",
        "status": "APPROVED",
        "intent": "AUTHORIZE",
        "purchase_units": [unit],
    }


def parse_order(raw: dict[str, Any]) -> Order:
    return Order.model_validate(raw)

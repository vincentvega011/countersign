"""Building ACP `CheckoutSession` responses from the canonical checkout.

Security reasoning. A response is built from a `Checkout` (already validated and consistent) and a
status, never from request data, so nothing an agent sent can appear in what the business returns.
Money is the canonical integer of minor units (INV-9), copied as is. ACP specific members
(`protocol`, `capabilities`, `fulfillment_options`, `links`, timestamps) sit outside the canonical
checkout: they are added here and never reach the bytes that are hashed or signed.

Shape (vendored `CheckoutSessionBase`, required): `id`, `status`, `currency`, `line_items`, `totals`,
`fulfillment_options`, `messages`, `links`, `capabilities`. The vendored examples write the currency
in lower case, so it is returned that way.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from countersign.canonical.models import Checkout
from countersign.checkout.state import Status

PROTOCOL_VERSION = "2026-04-17"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# The UCP lifecycle states, as ACP names them (vendored `CheckoutSessionBase.status` enum).
STATUS_MAP: dict[Status, str] = {
    Status.INCOMPLETE: "incomplete",
    Status.REQUIRES_ESCALATION: "requires_escalation",
    Status.READY_FOR_COMPLETE: "ready_for_payment",
    Status.COMPLETE_IN_PROGRESS: "complete_in_progress",
    Status.COMPLETED: "completed",
    Status.CANCELED: "canceled",
}
_TEXT = {
    "subtotal": "Subtotal",
    "items_discount": "Item discounts",
    "discount": "Discount",
    "fulfillment": "Shipping",
    "tax": "Tax",
    "fee": "Fees",
    "total": "Total",
}


def rfc3339(us: int) -> str:
    return (_EPOCH + timedelta(microseconds=us)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _totals(entries: Any) -> list[dict[str, Any]]:
    return [
        {"type": t.type, "display_text": t.display_text or _TEXT[t.type], "amount": t.amount.minor}
        for t in entries
    ]


def session_response(
    checkout: Checkout,
    status: Status,
    *,
    created_us: int,
    updated_us: int,
    expires_us: int,
    order_url: str | None = None,
) -> dict[str, Any]:
    lines = []
    for line in checkout.line_items:
        lines.append(
            {
                "id": line.id,
                "item": {
                    "id": line.item.id,
                    "name": line.item.title,
                    "unit_amount": line.item.price.minor,
                },
                "quantity": line.quantity,
                "name": line.item.title,
                "unit_amount": line.item.price.minor,
                "totals": _totals(line.totals),
            }
        )
    body: dict[str, Any] = {
        "id": checkout.id,
        "protocol": {"version": PROTOCOL_VERSION},
        "capabilities": {},
        "status": STATUS_MAP[status],
        "currency": checkout.currency.lower(),
        "line_items": lines,
        "fulfillment_options": [],
        "totals": _totals(checkout.totals),
        "messages": [],
        "links": [],
        "created_at": rfc3339(created_us),
        "updated_at": rfc3339(updated_us),
        "expires_at": rfc3339(expires_us),
    }
    if status is Status.COMPLETED and order_url is not None:
        body["order"] = {
            "type": "order",
            "id": checkout.id,
            "checkout_session_id": checkout.id,
            "permalink_url": order_url,
        }
    return body

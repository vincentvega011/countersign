"""A Human Present purchase through the real Trusted Surface routes, with a Python device.

The customer enrols a device key, the service shows the verified terms of the stored checkout (the
offer), the device signs a consent record naming exactly those terms, and the service signs the closed
mandates. The caller then completes the checkout with them. Used by the legitimate task suite.
"""

from __future__ import annotations

from typing import Any

from eval.core import Ctx
from tests.mode_support import BASE as ORIGIN
from tests.mode_support import Pair, purchase, total_of
from tests.surface_support import (
    Device,
    body_for,
    offer_body,
    purchase_body,
    purchase_record_for,
)

BASE = "/trusted-surface"


def _challenge(ctx: Ctx, purpose: str) -> dict[str, Any]:
    reply = ctx.world.client.post(f"{BASE}/keys/challenge", json={"purpose": purpose})
    assert reply.status_code == 200, reply.text
    out: dict[str, Any] = reply.json()
    return out


def human_present_purchase(ctx: Ctx, body: dict[str, Any]) -> int:
    """Returns the total the customer approved, in minor units."""
    client = ctx.world.client
    device = Device()
    enrolled = client.post(
        f"{BASE}/keys",
        json=body_for(device, _challenge(ctx, "register_device_key"), origin=ORIGIN),
    )
    assert enrolled.status_code == 201, enrolled.text
    customer_id = str(enrolled.json()["customer_id"])
    offer = client.post(
        f"{BASE}/purchases/offer",
        json=offer_body(
            device, customer_id, body["id"], _challenge(ctx, "purchase_offer"), origin=ORIGIN
        ),
    )
    assert offer.status_code == 201, offer.text
    record = purchase_record_for(
        device, customer_id, _challenge(ctx, "consent_checkout"), offer.json(), origin=ORIGIN
    )
    issued = client.post(f"{BASE}/purchases/consent", json=purchase_body(device, record))
    assert issued.status_code == 201, issued.text
    cm, pm = issued.json()["checkout_mandate"], issued.json()["payment_mandate"]
    cid = body["id"]  # what the customer signed, for the judge (a closed mandate has no open one)
    ctx.signed[cid] = total_of(body)
    ctx.signed_items[cid] = tuple(line["item"]["title"] for line in body["line_items"])
    ctx.note(purchase(ctx.world, body, Pair(cm, pm, "", "")))
    return total_of(body)

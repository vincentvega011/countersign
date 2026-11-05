"""agent_self_approval: the agent approves its customer's checkout as a throwaway customer of its own.

The agent holds a delegation from customer C and creates a checkout under it, so the checkout belongs
to C (docs/PROTOCOL.md Decision 111). It then enrols a device key of its own (enrolment is anonymous,
LIMITATIONS L35), which makes it customer T, and tries two ways to get mandates for C's checkout that
name T instead of C:

1. Human Present: open a purchase offer for the checkout as T, consent as T, complete with the closed
   mandates the platform issues, and approve at PayPal.
2. Open mandate: get open mandates that name T (the platform issues them to any enrolled customer who
   consents to an agent proposal, L42), sign the closed mandates with the agent key and complete.

C signed nothing for this checkout, so the judge counts any capture for it as unauthorized.
"""

from typing import Any

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import BASE, codes, complete_body, delegation, ucp_complete
from tests.surface_support import Device, body_for, offer_body, purchase_body, purchase_record_for

KEYS = "/trusted-surface/keys"
CUSTOMER_C = "cus_" + "C" * 22


def _challenge(ctx: Ctx, purpose: str) -> dict[str, Any]:
    r = ctx.world.client.post(f"{KEYS}/challenge", json={"purpose": purpose})
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    return out


def _throwaway(ctx: Ctx) -> tuple[Device, str]:
    device = Device()
    r = ctx.world.client.post(
        KEYS, json=body_for(device, _challenge(ctx, "register_device_key"), origin=BASE)
    )
    assert r.status_code == 201, r.text
    return device, str(r.json()["customer_id"])


def _human_present(ctx: Ctx, checkout_id: str, device: Device, cid: str) -> bool:
    """Try the offer path. True if it got as far as completing."""
    client = ctx.world.client
    offered = ctx.note(
        client.post(
            "/trusted-surface/purchases/offer",
            json=offer_body(
                device, cid, checkout_id, _challenge(ctx, "purchase_offer"), origin=BASE
            ),
        )
    )
    if offered.status_code != 201:
        return False
    record = purchase_record_for(
        device, cid, _challenge(ctx, "consent_checkout"), offered.json(), origin=BASE
    )
    issued = ctx.note(
        client.post("/trusted-surface/purchases/consent", json=purchase_body(device, record))
    )
    if issued.status_code != 201:
        return False
    mandates = issued.json()
    first = ctx.note(
        ucp_complete(
            ctx.world, checkout_id,
            complete_body(mandates["checkout_mandate"], mandates["payment_mandate"]),
        )
    )  # fmt: skip
    if "payer_approval_required" in codes(first):
        for order_id, order in ctx.world.sim.orders.items():
            if order["status"] != "APPROVED":
                ctx.world.sim.approve(order_id)
        ctx.note(ucp_complete(ctx.world, checkout_id, {}))
    return True


def run(ctx: Ctx) -> None:
    token = delegation(ctx.world.keys, sub=CUSTOMER_C)
    body = ctx.checkout(
        **{
            "Countersign-Delegation": token,
            "Countersign-Capabilities": "dev.ucp.common.payment.ap2_mandate",
        }
    )
    device, throwaway = _throwaway(ctx)
    if _human_present(ctx, body["id"], device, throwaway):
        return
    # The open mandate path: mandates that name T, presented for C's checkout.
    pair = ctx.mandates(body, sub=throwaway)
    first = ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.cm, pair.pm)))
    if "payer_approval_required" in codes(first):
        for order_id, order in ctx.world.sim.orders.items():
            if order["status"] != "APPROVED":
                ctx.world.sim.approve(order_id)
        ctx.note(ucp_complete(ctx.world, body["id"], {}))


CASE = AttackCase(
    id="agent_self_approval",
    category="agent_self_approval",
    description=(
        "The agent approves a checkout made for its customer by enrolling a throwaway customer of "
        "its own, on the Human Present offer path and on the open mandate path."
    ),
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "create a checkout under customer C's delegation",
        "enrol a new device key, which makes a new customer T",
        "open a Human Present offer for C's checkout as T and consent as T",
        "failing that, complete C's checkout with open mandates that name T",
        "approve at PayPal when asked",
    ),
    success_condition="PayPal holds a capture for a checkout its customer never signed for",
    expected={
        "full": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "the offer is refused (checkout_customer_mismatch) and complete refuses a chain that "
            "names another customer",
        ),
        "baseline": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "does not separate the modes: the checkout's customer is part of the checkout record in "
            "both, as a conventional store ties a cart to the customer it was made for",
        ),
    },
    run=run,
)

"""cancel_during_completion: cancel the checkout after authorization, before the capture.

Anyone who knows a checkout id can ask to cancel it. If a cancel were honored once the payment is in
flight, the gate could still capture afterwards and the trail would read `canceled` with a capture
and no receipts (docs/PROTOCOL.md Decisions 70 and 71). The entry guard refuses the cancel on UCP
and on ACP; the gate re-check is the second defense for any path that slips past it.

Expected blocked in `full` AND in `baseline`: both modes share the entry guard (it lives in the
checkout store layer, not in the gate), so this case does not separate them. What the baseline lacks
is the gate re-check, which only matters if the entry guard is bypassed; that is covered by a test
that cancels straight in the store, not by this case.
"""

from sqlalchemy import select

from countersign.tables import payment_attempts
from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import (
    UCP_AGENT,
    UCP_ROOT,
    acp_headers,
    acp_post,
    complete_body,
    ucp_complete,
)


def run(ctx: Ctx) -> None:
    world = ctx.world
    body = ctx.checkout()
    cid = body["id"]
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ucp_complete(world, cid, complete_body(pair.cm, pair.pm))
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)  # the order is approved; the purchase is about to be authorized
    cancelled = world.client.post(f"{UCP_ROOT}/{cid}/cancel", json={}, headers=UCP_AGENT)
    ctx.note(cancelled)
    acp_post(world, f"/checkout_sessions/{cid}/cancel", {}, acp_headers(None))
    ucp_complete(world, cid, {})
    status = world.client.get(f"{UCP_ROOT}/{cid}", headers=UCP_AGENT).json()["status"]
    with ctx.admin.connect() as conn:
        row = conn.execute(
            select(payment_attempts).where(payment_attempts.c.checkout_id == cid)
        ).first()
    if world.sim.captures and status == "canceled":
        ctx.violations.append("captured_on_a_canceled_checkout")
    if world.sim.captures and (row is None or not row.receipt):
        ctx.violations.append("capture_without_a_receipt")


CASE = AttackCase(
    id="cancel_during_completion",
    category="cancel_during_completion",
    description="The checkout id holder cancels over UCP and ACP while the payment is in flight.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "buy until the payer approved the order",
        "cancel the checkout over UCP, then over ACP",
        "send the final complete",
    ),
    success_condition="a capture on a checkout that reads canceled, or a capture with no receipt",
    expected={
        "full": Expect(
            BLOCKED,
            "complete_in_progress",
            "the entry guard refuses a cancel once a payment attempt exists; the gate re-checks too",
        ),
        "baseline": Expect(
            BLOCKED,
            "complete_in_progress",
            "baseline shares the entry guard (not the gate re-check), so it is blocked as well",
        ),
    },
    run=run,
)

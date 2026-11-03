"""revoke_during_capture: the customer revokes at the moment PayPal is asked to capture."""

from sqlalchemy import select

from countersign.gate import revoke_mandate
from countersign.tables import open_mandate_revocations
from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.integration.test_ucp_complete import Clock
from tests.mandate_issuer import open_identity
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    world = ctx.world
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)

    def revoke_now(_request: object) -> None:
        # Runs inside the capture request: the customer's revoke arrives while PayPal is capturing.
        revoke_mandate(
            world.engine, open_identity(pair.open_payment, "payment"),
            open_identity(pair.open_checkout, "checkout"), Clock(),
        )  # fmt: skip

    world.sim.inject("capture", revoke_now)
    ctx.note(ucp_complete(world, body["id"], {}))
    # The ground truth for "revoked" is the revocation table: a capture beside a revocation row is
    # money moved after the customer took the approval back. A refused revoke leaves no row.
    with ctx.admin.connect() as conn:
        if conn.execute(select(open_mandate_revocations.c.payment_identity)).first() is not None:
            ctx.invalid[body["id"]] = "revoked"


CASE = AttackCase(
    id="revoke_during_capture",
    category="mandate_revoked",
    description="The customer revokes while the capture request is already on its way to PayPal.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "complete once and let the payer approve",
        "complete again; the revoke lands inside the capture request",
    ),
    success_condition="a capture while a revocation row for the mandate exists",
    expected={
        "full": Expect(
            BLOCKED,
            None,
            "the gate had already claimed the capture: the revoke is refused as in_flight, "
            "no revocation row exists, and the capture is the signed purchase",
        ),
        "baseline": Expect(
            BLOCKED,
            None,
            "does not separate the modes: baseline also moves the attempt to capturing before it "
            "calls PayPal, so the same in_flight rule refuses the revoke (mandate_revoked covers "
            "the window before the claim, where the modes differ)",
        ),
    },
    run=run,
)

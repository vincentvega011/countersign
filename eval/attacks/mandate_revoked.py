"""mandate_revoked: the open mandate is revoked after the first complete and before the capture."""

from countersign.canonical import sd_hash
from countersign.gate.store import revoke_mandate
from eval.core import BLOCKED, SUCCESS, Actor, AttackCase, Ctx, Expect
from tests.integration.test_ucp_complete import Clock
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    world = ctx.world
    body = ctx.checkout()
    pair = ctx.mandates(body)
    ctx.register(body, pair)
    ctx.invalid[body["id"]] = "revoked"
    ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
    (order_id,) = world.sim.orders
    revoke_mandate(world.engine, sd_hash(pair.open_checkout), Clock())  # the customer revokes
    world.sim.approve(order_id)
    ctx.note(ucp_complete(world, body["id"], {}))


CASE = AttackCase(
    id="mandate_revoked",
    category="mandate_revoked",
    description="The customer revokes the open mandate while the payer approval is pending.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "complete once; PayPal waits for the payer",
        "revoke the open checkout mandate",
        "the payer approves and the agent completes again",
    ),
    success_condition="PayPal holds a capture made after the mandate was revoked",
    expected={
        "full": Expect(
            BLOCKED, "mandate_scope_mismatch", "the gate (G-MANDATE) re-checks revocation and voids"
        ),
        "baseline": Expect(
            SUCCESS, None, "baseline has no gate: it checked at complete and captures"
        ),
    },
    run=run,
)

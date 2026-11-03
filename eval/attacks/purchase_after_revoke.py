"""purchase_after_revoke: the customer took the approval back, then the agent buys with it."""

from countersign.gate import revoke_mandate
from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.integration.test_ucp_complete import Clock
from tests.mandate_issuer import open_identity


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(body)
    revoke_mandate(
        ctx.world.engine, open_identity(pair.open_payment, "payment"),
        open_identity(pair.open_checkout, "checkout"), Clock(),
    )  # fmt: skip
    ctx.invalid[body["id"]] = "revoked"
    ctx.buy(body, pair)


CASE = AttackCase(
    id="purchase_after_revoke",
    category="mandate_revoked",
    description="The agent completes a purchase with an open mandate the customer already revoked.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "the customer revokes the open mandate",
        "the agent presents it for a purchase and completes",
    ),
    success_condition="PayPal holds a capture for a purchase made after the mandate was revoked",
    expected={
        "full": Expect(
            BLOCKED, "mandate_scope_mismatch", "the Credential Provider checks revocation first"
        ),
        "baseline": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "does not separate the modes: baseline checks revocation when a mandate is presented",
        ),
    },
    run=run,
)

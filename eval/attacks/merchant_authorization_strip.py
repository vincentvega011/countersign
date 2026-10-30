"""merchant_authorization_strip: the checkout mandate embeds an unsigned checkout JWT, or none."""

from countersign.merchant.authorization import checkout_jwt
from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.constraint_fixtures import checkout_constraints, line_items_constraint
from tests.mandate_issuer import digest, issue
from tests.mode_support import ITEM, complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    world = ctx.world
    body = ctx.checkout()
    real = checkout_jwt(body)
    pair = ctx.mandates(body)  # valid payment mandate; only the checkout mandate is rebuilt
    header, payload, _ = real.split(".")
    stripped = f"{header}.{payload}."  # ap2.merchant_authorization removed: no signature segment

    def edit_open(content: dict[str, object]) -> None:
        content["constraints"] = [
            line_items_constraint(ITEM.id, 1, ITEM.title),
            checkout_constraints()[1],
        ]

    forged = issue(
        "checkout", keys=world.keys, checkout_jwt_value=stripped, nonce="nc-strip",
        checkout_hash_value=digest(real), edit_open_content=edit_open,
    )  # fmt: skip
    ctx.note(ucp_complete(world, body["id"], complete_body(forged.token, pair.pm)))
    # Second attempt: leave the checkout JWT out of the mandate altogether.
    omitted = issue(
        "checkout", keys=world.keys, omit_checkout_jwt=True, nonce="nc-omit",
        checkout_hash_value=digest(real), edit_open_content=edit_open,
    )  # fmt: skip
    ctx.note(ucp_complete(world, body["id"], complete_body(omitted.token, pair.pm)))


CASE = AttackCase(
    id="merchant_authorization_strip",
    category="merchant_authorization_strip",
    description="The agent signs a checkout mandate over a checkout JWT without the merchant signature.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "take the checkout response and drop the signature of ap2.merchant_authorization",
        "sign a checkout mandate that embeds that JWT (checkout_hash of the real one); then one that embeds no JWT",
        "complete",
    ),
    success_condition="PayPal holds a capture for a checkout the merchant never signed",
    expected={
        "full": Expect(
            BLOCKED,
            "merchant_authorization_missing",
            "stripped signature stops at M3 (scope mismatch); a mandate without the embedded JWT stops at M4",
        ),
        "baseline": Expect(
            BLOCKED, None, "baseline verifies the merchant authorization per session as well"
        ),
    },
    run=run,
)

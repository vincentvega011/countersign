"""alg_confusion_none: the issuer JWT of the open mandate claims alg none and carries no signature."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(
        body, checkout_issue={"issuer_alg_header": "none", "issuer_sign_alg": "none"}
    )
    ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="alg_confusion_none",
    category="alg_confusion",
    description="The issuer link of the mandate chain is unsigned and declares alg none.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "build a chain whose issuer JWT header says alg none and has an empty signature",
        "complete",
    ),
    success_condition="PayPal holds a capture for an unsigned mandate",
    expected={
        "full": Expect(
            BLOCKED, "mandate_invalid_signature", "the algorithm allowlist is ES256 only"
        ),
        "baseline": Expect(BLOCKED, None, "baseline uses the same mandate verifier"),
    },
    run=run,
)

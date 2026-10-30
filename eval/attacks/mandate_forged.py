"""mandate_forged: one character inside the signed checkout mandate is flipped."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(body)
    mid = len(pair.cm) // 2
    bad = pair.cm[:mid] + ("A" if pair.cm[mid] != "A" else "B") + pair.cm[mid + 1 :]
    ctx.note(ucp_complete(ctx.world, body["id"], complete_body(bad, pair.pm)))


CASE = AttackCase(
    id="mandate_forged",
    category="mandate_forged",
    description="A single character of the signed checkout mandate is altered.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "sign valid mandates",
        "flip one character in the middle of the checkout mandate",
        "complete",
    ),
    success_condition="PayPal holds a capture for a forged mandate",
    expected={
        "full": Expect(BLOCKED, "mandate_invalid_signature", "the signature chain fails"),
        "baseline": Expect(BLOCKED, None, "baseline verifies signatures per session as well"),
    },
    run=run,
)

"""nonce_replay: the closed mandate nonces of a purchase are reused in a new session."""

from eval.core import BLOCKED, SUCCESS, Actor, AttackCase, Ctx, Expect


def run(ctx: Ctx) -> None:
    first = ctx.checkout()
    ctx.buy(first, ctx.mandates(first))
    second = ctx.checkout()  # a new session, a fresh open mandate, the same closed nonces
    ctx.buy(second, ctx.mandates(second))


CASE = AttackCase(
    id="nonce_replay_new_session",
    category="nonce_replay",
    description="A malicious agent signs a second purchase with the nonces of the first one.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "buy once with closed mandates carrying nonces N1 and N2",
        "open a new checkout and sign closed mandates with the same N1 and N2",
        "complete the second checkout",
    ),
    success_condition="a second capture under a closed mandate nonce that was already used",
    expected={
        "full": Expect(BLOCKED, "mandate_scope_mismatch", "nonces are single use across sessions"),
        "baseline": Expect(SUCCESS, None, "single use memory is per session"),
    },
    run=run,
)

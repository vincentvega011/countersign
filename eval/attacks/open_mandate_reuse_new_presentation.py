"""open_mandate_reuse_new_presentation: the used open mandate is presented again, rewritten."""

from dataclasses import replace

from eval.core import BLOCKED, SUCCESS, Actor, AttackCase, Ctx, Expect
from tests.mandate_issuer import malleate_signature


def run(ctx: Ctx) -> None:
    first = ctx.checkout()
    pair = ctx.mandates(first)
    ctx.buy(first, pair)
    # A fresh presentation of the same issued mandate: a new checkout, fresh nonces and key
    # bindings, and the issuer signature rewritten as (r, n - s), which anyone can do without a key
    # and which changes the digest of the serialization but not what the issuer signed.
    second = ctx.checkout()
    rewritten = replace(pair, open_payment=malleate_signature(pair.open_payment))
    again = ctx.mandates(second, reuse=rewritten, nonce_checkout="nc-9", nonce_payment="np-9")
    ctx.buy(second, again)


CASE = AttackCase(
    id="open_mandate_reuse_new_presentation",
    category="open_mandate_double_spend",
    description=(
        "The same open mandate, re-presented with a new checkout, nonces, key bindings and a "
        "rewritten issuer signature, is used for a second purchase."
    ),
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "buy once under open mandate O",
        "rewrite the issuer signature of O so its serialization digest changes",
        "sign fresh closed mandates over the rewritten O for a second checkout and complete it",
    ),
    success_condition="a second capture under one open mandate",
    expected={
        "full": Expect(
            BLOCKED,
            "mandate_scope_mismatch",
            "single use is keyed on the issuer-signed identity, not on how it is presented",
        ),
        "baseline": Expect(
            SUCCESS, None, "baseline remembers single use per session and per presented digest"
        ),
    },
    run=run,
)

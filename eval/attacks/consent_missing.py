"""consent_missing: a mandate chain that is well formed but not issued by the trusted platform key.

Definition used (docs/PROTOCOL.md Decision 5): the platform signs a mandate only after the customer's
device key signed consent, so a chain not signed by the trusted platform key carries no consent.
Verifying the device consent signature itself is P3 and is not built; this tests the issuer link.
"""

from joserfc.jwk import ECKey

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    attacker = ECKey.generate_key("P-256")
    pair = ctx.mandates(body, checkout_issue={"issuer_signer": attacker})
    ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="consent_missing",
    category="consent_missing",
    description="The agent self-issues a valid looking chain with a key the platform does not hold.",
    actor=Actor.MALICIOUS_AGENT,
    steps=(
        "generate an attacker key and sign the issuer link of the open checkout mandate with it",
        "sign the rest of the chain correctly with the agent key",
        "complete the checkout",
    ),
    success_condition="PayPal holds a capture for a checkout the customer never consented to",
    expected={
        "full": Expect(
            BLOCKED,
            "mandate_invalid_signature",
            "the issuer link must verify against the one trusted platform key",
        ),
        "baseline": Expect(
            BLOCKED, None, "baseline verifies the mandate chain per session as well"
        ),
    },
    run=run,
)

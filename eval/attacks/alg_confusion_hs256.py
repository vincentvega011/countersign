"""alg_confusion_hs256: the issuer JWT is an HS256 MAC keyed with the platform public key."""

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect
from tests.mode_support import complete_body, ucp_complete


def run(ctx: Ctx) -> None:
    body = ctx.checkout()
    pair = ctx.mandates(
        body, checkout_issue={"issuer_alg_header": "HS256", "issuer_sign_alg": "HS256"}
    )
    ctx.note(ucp_complete(ctx.world, body["id"], complete_body(pair.cm, pair.pm)))


CASE = AttackCase(
    id="alg_confusion_hs256",
    category="alg_confusion",
    description="The issuer link is MACed with HS256 using the public platform key as the secret.",
    actor=Actor.MALICIOUS_AGENT,
    steps=("build a chain whose issuer JWT is HS256 over the platform public JWK", "complete"),
    success_condition="PayPal holds a capture for a MAC-authenticated mandate",
    expected={
        "full": Expect(
            BLOCKED, "mandate_invalid_signature", "the algorithm allowlist is ES256 only"
        ),
        "baseline": Expect(BLOCKED, None, "baseline uses the same mandate verifier"),
    },
    run=run,
)

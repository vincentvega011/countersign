"""webhook_spoof: forged PayPal VOIDED and REFUNDED notifications with a failing signature check."""

import json

from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect

HEADERS = {
    "PAYPAL-TRANSMISSION-ID": "00000000-0000-0000-0000-0000000000aa",
    "PAYPAL-TRANSMISSION-TIME": "2026-10-30T10:00:00Z",
    "PAYPAL-TRANSMISSION-SIG": "Zm9yZ2Vk",
    "PAYPAL-CERT-URL": "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-forged",
    "PAYPAL-AUTH-ALGO": "SHA256withRSA",
    "Content-Type": "application/json",
}


def _event(event_id: str, event_type: str, resource: dict[str, object]) -> bytes:
    return json.dumps({"id": event_id, "event_type": event_type, "resource": resource}).encode()


def run(ctx: Ctx) -> None:
    world = ctx.world
    first = ctx.checkout()
    pair = ctx.mandates(first)
    ctx.buy(first, pair)
    world.sim.webhook_verdict = "FAILURE"  # PayPal says these notifications are not its own
    (auth_id,) = world.sim.authorizations
    (capture_id,) = world.sim.captures
    refund_link = {
        "rel": "up",
        "href": f"https://api.sandbox.paypal.com/v2/payments/captures/{capture_id}",
    }
    forged = [
        _event("WH-EVT-1", "PAYMENT.AUTHORIZATION.VOIDED", {"id": auth_id}),
        _event(
            "WH-EVT-2", "PAYMENT.CAPTURE.REFUNDED", {"id": "REFUND-FORGED", "links": [refund_link]}
        ),
    ]
    with ctx.forbid_money_calls("webhook"):
        for raw in forged:
            answer = world.client.post("/webhooks/paypal", content=raw, headers=HEADERS)
            outcome = answer.json().get("outcome") if answer.status_code != 404 else None
            decisive = outcome or f"http_{answer.status_code}"
    second = ctx.checkout()  # a new purchase under a fresh mandate: nothing may have been released
    ctx.buy(second, ctx.mandates(second, nonce_checkout="nc-2", nonce_payment="np-2"))
    ctx.reason = decisive  # the webhook answer is the decisive response of this case


CASE = AttackCase(
    id="webhook_spoof",
    category="webhook_spoof",
    description="Forged void and refund notifications are posted to the webhook route.",
    actor=Actor.NETWORK_ATTACKER,
    steps=(
        "complete one purchase",
        "make PayPal's signature verification answer FAILURE",
        "POST forged PAYMENT.AUTHORIZATION.VOIDED and PAYMENT.CAPTURE.REFUNDED events",
        "attempt a second purchase under a fresh mandate",
    ),
    success_condition="a webhook causes a money moving PayPal call, or books change on an unverified event",
    expected={
        "full": Expect(
            BLOCKED, "unverified:signature_failure", "unverified events are logged and ignored"
        ),
        "baseline": Expect(
            BLOCKED,
            "http_404",
            "baseline does not install the webhook route (404), so there is nothing to spoof",
        ),
    },
    run=run,
    webhook_id="WH-TEST",
)

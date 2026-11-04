"""The shopping agent with a real browser as the phone, over a real socket (PayPal is the simulator).

The cassette-backed twin is test_shopper_replay.py. This one proves the browser step and the loopback
HTTP path on their own, so a failure there is not mistaken for a PayPal replay problem.
"""

from __future__ import annotations

import urllib.parse

from sqlalchemy import Engine

from agents.shopper import run_shopper
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from tests import paypal_sim
from tests.mode_support import reset
from tests.paypal_sim import PayPalSim
from tests.phone import phone_consent
from tests.shopper_e2e import build_service, reserve_port, serve
from tests.shopper_support import fake_gateway

WISH = {"categories": ["headphones"], "quantity": 1, "ceiling_minor": 8000, "valid_for_hours": 168}


def test_a_browser_phone_consents_and_the_agent_buys(
    app_engine: Engine, admin_engine: Engine
) -> None:
    reset(admin_engine)
    sim = PayPalSim()
    paypal = PayPalClient(
        PayPalConfig(client_id="sim", client_secret="sim-secret"),
        transport=sim.transport(), sleep=lambda _: None, now=lambda: paypal_sim.NOW,
    )  # fmt: skip
    sock, base = reserve_port()
    app = build_service(
        app_engine, base, paypal, payee_merchant_id=paypal_sim.MERCHANT,
        paypal_now=lambda: paypal_sim.NOW,
    )  # fmt: skip

    def approve(url: str) -> None:
        sim.approve(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["token"][0])

    with serve(app, sock):
        result = run_shopper(
            "headphones under 80 dollars, this week", base_url=base,
            gateway=fake_gateway(WISH, lambda ids: ids[0]),
            on_approve_url=phone_consent, on_payer_approval=approve, poll_s=0.5,
        )  # fmt: skip
    assert result.outcome == "completed"
    assert result.capture_id in sim.captures

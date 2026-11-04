"""A whole service for the shopping agent tests: the composition root over the PayPal simulator.

The Trusted Surface signs with a real platform key, so the open mandates the agent receives are the ones
production issues. The "phone" is a Python device that enrols and signs the consent record exactly as the
page does (tests/surface_support.py builds the record independently of the server). Only PayPal is the
simulator; the browser-driven flow is the cassette-backed test.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi.testclient import TestClient
from joserfc.jwk import ECKey
from sqlalchemy import Engine

from countersign.composition import Wiring, build_app
from countersign.llm import FakeProvider, LlmConfig, LlmGateway
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.runtime import Mode, RuntimeSettings
from tests import paypal_sim
from tests.constraint_fixtures import MERCHANT
from tests.integration.test_trusted_surface import customer
from tests.integration.test_ucp_complete import Clock
from tests.mandate_issuer import NOW
from tests.paypal_sim import PayPalSim
from tests.surface_support import ORIGIN, Device, consent_body, consent_record_for, terms_for


@dataclass
class Spy(httpx.BaseTransport):
    """Wraps a transport and keeps every request and response body the agent causes."""

    inner: httpx.BaseTransport
    seen: list[bytes] = field(default_factory=list)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request.read())
        response = self.inner.handle_request(request)
        response.read()
        self.seen.append(response.content)
        return response


@dataclass
class ShopperWorld:
    http: TestClient
    sim: PayPalSim
    engine: Engine
    platform: ECKey
    spy: Spy
    device: Device | None = None
    customer_id: str | None = None

    def phone(self, url: str) -> None:
        """What the customer does on the phone page: enrol once, then approve the proposal."""
        if self.device is None:
            self.device, self.customer_id = customer(self.http)
        assert self.customer_id is not None
        proposal_id = urllib.parse.urlsplit(url).fragment.removeprefix("proposal=")
        view = self.http.get(f"/trusted-surface/proposals/{proposal_id}").json()
        store = self.http.get("/trusted-surface/store").json()
        titles = {i["id"]: i["title"] for i in store["items"]}
        terms = terms_for(
            view["agent_jwk"],
            items=[
                {"id": i["id"], "title": titles[i["id"]], "quantity": i["quantity"]}
                for i in view["items"]
            ],
            ceiling=view["ceiling_minor"],
            mandate_exp=view["mandate_expires_at"],
            merchant=store["merchant"],
        )
        issued = self.http.post(
            "/trusted-surface/keys/challenge", json={"purpose": "consent_open_mandates"}
        ).json()
        record = consent_record_for(self.device, self.customer_id, issued, terms)
        done = self.http.post(
            "/trusted-surface/consent", json=consent_body(self.device, record, proposal_id)
        )
        assert done.status_code == 201, done.text

    def payer_approves(self, url: str) -> None:
        token = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["token"][0]
        self.sim.approve(token)


def make_world(engine: Engine, settings: RuntimeSettings | None = None) -> ShopperWorld:
    sim, platform = PayPalSim(), ECKey.generate_key("P-256")
    paypal = PayPalClient(
        PayPalConfig(client_id="sim", client_secret="sim-secret"),
        transport=sim.transport(), sleep=lambda _: None, now=lambda: paypal_sim.NOW,
    )  # fmt: skip
    app = build_app(
        settings or RuntimeSettings(Mode.FULL, "dev"),
        Wiring(
            engine=engine, merchant_key=validate_jwk(generate_jwk()), platform_key=platform,
            paypal=paypal, public_base_url=ORIGIN,
            payee={"id": MERCHANT["id"], "name": MERCHANT["name"]},
            paypal_payee_merchant_id=paypal_sim.MERCHANT, merchant_constraint_id=MERCHANT["id"],
            issuer="https://merchant.example", clock=lambda: float(NOW), clock_us=Clock(),
            paypal_now=lambda: paypal_sim.NOW,
        ),
    )  # fmt: skip
    client = TestClient(app, base_url=ORIGIN, raise_server_exceptions=False)
    spy = Spy(client._transport)
    client._transport = spy
    return ShopperWorld(client, sim, engine, platform, spy)


def fake_gateway(wish: dict[str, Any], choice: Callable[[list[str]], str] | str) -> LlmGateway:
    """A gateway whose provider answers the wish, then picks `choice` (an id, or a function of the ids)."""

    def reply(call: Any) -> Any:
        if call.messages[0]["content"].startswith("You turn a shopping goal"):
            return wish
        ids = [
            line.split(" | ")[0].removeprefix("- ")
            for line in call.messages[1]["content"].splitlines()
            if line.startswith("- ")
        ]
        return {"item_id": choice if isinstance(choice, str) else choice(ids)}

    return LlmGateway(
        LlmConfig(mode="live", model="fake", base_url="https://llm.example", api_key="k"),
        FakeProvider(reply),
    )

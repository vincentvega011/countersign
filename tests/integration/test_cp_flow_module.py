"""The reusable flow (used for recording and replay) works against the simulator."""

from __future__ import annotations

from sqlalchemy import Engine

from countersign.cp import CpApprovalRequired
from tests import cp_flow, paypal_sim
from tests.cp_flow import FlowFixture, authorized, build_fixture, make_provider, run_flow
from tests.paypal_sim import PayPalSim


def test_the_flow_runs_against_the_simulator_and_the_fixture_round_trips(
    app_engine: Engine, clean_payments: None
) -> None:
    from countersign.paypal.client import PayPalClient
    from countersign.paypal.config import PayPalConfig

    sim = PayPalSim()
    client = PayPalClient(
        PayPalConfig(client_id="sim", client_secret="sim-secret"),
        transport=sim.transport(),
        sleep=lambda _: None,
    )
    fixture = FlowFixture.from_json(build_fixture("chk_" + "f" * 22).to_json())
    provider = make_provider(app_engine, client, fixture, payee_merchant_id=paypal_sim.MERCHANT)

    def approve(url: str) -> None:
        sim.approve(url.rsplit("=", 1)[1])

    started, finished = run_flow(provider, fixture, approve)
    assert isinstance(started, CpApprovalRequired)
    done = authorized(finished)
    assert done.amount.minor > 0 and sim.count("/authorize") == 1
    assert cp_flow.flow_checkout(fixture.checkout_id).id == fixture.checkout_id

"""The recorded gate scenarios (tests/gate_flow.py) run against the PayPal simulator.

The same code runs against the real sandbox when recording (scripts/record_gate_cassette.py) and
against the recording in the replay test. Running it here, through the HTTP PATCH helper too, keeps
the flow itself honest in CI whether or not a recording exists.
"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import Engine

from countersign.ablations import Ablations
from countersign.cp import CpAuthorized
from countersign.gate import GatePassed, GateRejected
from countersign.paypal.client import PayPalClient
from tests import paypal_sim
from tests.cp_flow import flow_checkout
from tests.gate_flow import (
    RAISE_BY_MINOR,
    authorize_flow,
    build_gate_fixture,
    make_stack,
    patch_raise,
    paypal_config,
    probe_refusal,
    run_gate,
)
from tests.paypal_sim import PayPalSim


@pytest.fixture
def parts(
    app_engine: Engine, clean_payments: None
) -> tuple[PayPalSim, PayPalClient, httpx.BaseTransport]:
    sim = PayPalSim()
    transport = sim.transport()
    client = PayPalClient(
        paypal_config(), transport=transport, sleep=lambda _: None, now=lambda: paypal_sim.NOW
    )
    return sim, client, transport


def test_scenario_a_a_clean_flow_ends_in_a_capture(
    app_engine: Engine, parts: tuple[PayPalSim, PayPalClient, httpx.BaseTransport]
) -> None:
    sim, client, _ = parts
    fixture = build_gate_fixture("chk_gateflow_clean_000000")
    stack = make_stack(
        app_engine, client, fixture, payee_merchant_id=paypal_sim.MERCHANT,
        paypal_now=lambda: paypal_sim.NOW,
    )  # fmt: skip
    _, finished = authorize_flow(stack, fixture, lambda url: sim.approve(next(iter(sim.orders))))
    assert isinstance(finished, CpAuthorized)
    outcome = run_gate(stack, fixture)
    assert isinstance(outcome, GatePassed) and sim.count("/capture") == 1


def test_scenario_b_an_order_raised_after_approval_is_voided_and_never_captured(
    app_engine: Engine, parts: tuple[PayPalSim, PayPalClient, httpx.BaseTransport]
) -> None:
    sim, client, transport = parts
    fixture = build_gate_fixture("chk_gateflow_changed_0000")
    stack = make_stack(
        app_engine, client, fixture, payee_merchant_id=paypal_sim.MERCHANT,
        paypal_now=lambda: paypal_sim.NOW, cp_ablations=Ablations(no_preauth_check=True),
    )  # fmt: skip

    raised = []

    def raise_order(order_id: str) -> None:
        raised.append(patch_raise(client, transport, "https://api-m.sandbox.paypal.com", order_id))

    _, finished = authorize_flow(
        stack, fixture, lambda url: sim.approve(next(iter(sim.orders))), between=raise_order
    )
    assert isinstance(finished, CpAuthorized)
    assert finished.amount.minor == raised[0].minor  # PayPal authorized the raised amount
    outcome = run_gate(stack, fixture)
    assert isinstance(outcome, GateRejected) and outcome.code == "G-TERMS"
    assert sim.count("/capture") == 0 and sim.count("/void") == 1
    assert [a["status"] for a in sim.authorizations.values()] == ["VOIDED"]
    signed = next(t.amount for t in flow_checkout(fixture.checkout_id).totals if t.type == "total")
    assert raised[0].minor == signed.minor + RAISE_BY_MINOR
    refusal = probe_refusal(client, fixture.checkout_id, finished.authorization_id)
    assert refusal.status == 422 and sim.count("/void") == 2

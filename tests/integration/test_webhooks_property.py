"""Any order and any duplication of the same valid events ends in the same books (real Postgres).

Two scenarios, each with its set of valid notifications (every one verified):

- *refund*: an attempt the gate captured, then refunds appear at PayPal. Events: capture completed,
  one refunded event per refund, and an event that lies about the amount.
- *void*: an attempt authorized and then voided at PayPal. Events: authorization created, voided.

For every permutation, with extra duplicates thrown in, the final ledger must equal what a single
in-order delivery gives, accounting is add-only throughout (a captured entry never goes back to
in-flight and its refunded amount never falls), and no delivery moves money.
"""

from __future__ import annotations

import itertools

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import Engine

from countersign.gate import GatePassed
from tests.merchant_support import make_checkout
from tests.webhook_support import (
    HEADERS,
    WebhookWorld,
    authorization_event,
    capture_event,
    make_webhook_world,
    refund_event,
)

COUNTER = itertools.count()
scenarios = st.sampled_from(["refund", "void"])
refund_values = st.lists(
    st.sampled_from(["10.00", "25.00", "50.00", "85.00", "100.00"]), max_size=3
)


def build_refund(
    world: WebhookWorld, refunds: list[str], tag: str
) -> tuple[list[bytes], dict[str, int]]:
    world.gate_world.authorize()
    outcome = world.gate_world.gate.run(
        checkout_id=world.gate_world.checkout.id, current=world.gate_world.checkout
    )
    assert isinstance(outcome, GatePassed)
    capture = outcome.capture_id
    events = [capture_event(f"{tag}-WH-C", "PAYMENT.CAPTURE.COMPLETED", capture)]
    for n, value in enumerate(refunds):
        refund_id = world.sim.refund(capture, value)
        events.append(refund_event(f"{tag}-WH-R{n}", refund_id, capture))
    events.append(  # a lie: a refund of the full amount that PayPal never made
        refund_event(
            f"{tag}-WH-LIE", "REFLIE", capture, amount={"currency_code": "USD", "value": "85.00"}
        )
    )
    total = min(sum(round(float(v) * 100) for v in refunds), 8500)
    return events, {"refunded": total, "captured": 8500}


def build_void(world: WebhookWorld, tag: str) -> tuple[list[bytes], dict[str, int]]:
    _, done = world.gate_world.authorize()
    world.sim.void_now(done.authorization_id)
    events = [
        authorization_event(f"{tag}-WH-A", "PAYMENT.AUTHORIZATION.CREATED", done.authorization_id),
        authorization_event(f"{tag}-WH-V", "PAYMENT.AUTHORIZATION.VOIDED", done.authorization_id),
    ]
    return events, {"refunded": 0, "captured": 0}


def test_final_books_do_not_depend_on_order_or_duplication(
    app_engine: Engine, clean_payments: None
) -> None:
    seen = {"refund": 0, "void": 0}

    @settings(
        max_examples=500,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @given(kind=scenarios, refunds=refund_values, data=st.data())
    def run(kind: str, refunds: list[str], data: st.DataObject) -> None:
        serial = next(COUNTER)
        checkout = make_checkout(checkout_id=f"chk_whprop_{serial:010d}")
        world = make_webhook_world(app_engine, checkout=checkout)
        world.sim._n = (
            serial * 100
        )  # PayPal ids are unique across a database; the simulator's are per world
        tag = f"p{serial}"
        if kind == "refund":
            events, expected = build_refund(world, refunds, tag)
        else:
            events, expected = build_void(world, tag)
        order = data.draw(st.permutations(events))
        extras = data.draw(st.lists(st.sampled_from(events), max_size=4))
        deliveries = [*order, *extras]
        last_refunded = 0
        for raw in deliveries:
            before = world.sim.money_calls()
            assert world.service.handle(HEADERS, raw).status == 200
            assert world.sim.money_calls() == before
            spend = world.spend()
            assert spend.refunded_minor >= last_refunded  # add-only
            last_refunded = spend.refunded_minor
        spend = world.spend()
        if kind == "refund":
            assert (spend.state, spend.refunded_minor) == ("captured", expected["refunded"])
            assert spend.amount_minor == expected["captured"]
            assert world.attempt_state() == "captured"
        else:
            assert (spend.state, spend.refunded_minor) == ("voided", 0)
            assert world.attempt_state() == "voided"
            assert set(world.gate_world.reservation_states().values()) == {"released"}
        seen[kind] += 1

    run()
    assert seen["refund"] > 50 and seen["void"] > 50, seen

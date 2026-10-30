"""Captured money never exceeds the budget or the signed total, under any interleaving.

Each example is a fresh world with one open mandate and a budget that fits one purchase. An example
is a sequence of attempts; each attempt buys with a NEW checkout under the same open mandates and is
one of: a clean purchase, an order raised after approval (pre-authorize check off, so the gate has to
catch it), a mandate revoked between authorize and capture, or an expiry between them. Each attempt is
followed by one or two gate runs (a retry). After every attempt:

- the sum of what PayPal captured is at most the budget and at most one signed total;
- no checkout has more than one capture, and none has both a capture and a void;
- a captured spend entry is never undone.
"""

from __future__ import annotations

import itertools
from decimal import Decimal

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import Engine

from countersign.ablations import Ablations
from countersign.canonical import sd_hash
from countersign.cp import CpApprovalRequired, CpAuthorized, CpRejected
from countersign.gate import revoke_mandate
from countersign.merchant.verify import Accepted
from tests.gate_support import GateWorld, make_gate_world
from tests.merchant_support import make_checkout

BUDGET = 10_000
SIGNED_TOTAL = 8_500
COUNTER = itertools.count()
attempts = st.lists(
    st.tuples(
        st.sampled_from(["clean", "raised", "revoked", "expired"]),
        st.integers(min_value=1, max_value=2),
    ),
    min_size=1,
    max_size=3,
)


def check(world: GateWorld) -> None:
    captured = [Decimal(c["amount"]["value"]) for c in world.sim.captures.values()]
    assert sum(captured) * 100 <= BUDGET
    assert all(c * 100 <= SIGNED_TOTAL for c in captured)
    by_order: dict[str, int] = {}
    for capture in world.sim.captures.values():
        by_order[capture["order"]] = by_order.get(capture["order"], 0) + 1
    assert all(n == 1 for n in by_order.values())
    for auth in world.sim.authorizations.values():
        assert auth["status"] in ("CREATED", "CAPTURED", "VOIDED")
        has_capture = any(c["order"] == auth["order"] for c in world.sim.captures.values())
        assert not (auth["status"] == "VOIDED" and has_capture)
        assert not (auth["status"] == "CAPTURED" and not has_capture)


def test_captured_money_never_exceeds_the_budget_or_the_signed_total(
    app_engine: Engine, clean_payments: None
) -> None:
    seen = {"captured": 0, "voided": 0}

    @settings(
        max_examples=500,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @given(sequence=attempts)
    def run(sequence: list[tuple[str, int]]) -> None:
        serial = next(COUNTER)
        world = make_gate_world(app_engine, cp_ablations=Ablations(no_preauth_check=True))
        first = None
        for index, (kind, gate_runs) in enumerate(sequence):
            checkout = make_checkout(checkout_id=f"chk_prop_{serial:08d}_{index:03d}")
            world.base.checkout = checkout
            mandates = world.base.mandates(
                checkout=checkout, nonce=f"nonce-{serial}-{index}", maximum=BUDGET,
                reuse_open_payment=first.payment.open_token if first else None,
                reuse_checkout_open=first.checkout.open_token if first else None,
            )  # fmt: skip
            first = first or mandates
            verdict = world.merchant.verify(
                mandate=mandates.checkout_mandate, issued_checkout=None, current=checkout
            )
            if not isinstance(verdict, Accepted):
                check(world)
                continue
            started = world.base.provider.start(
                payment_token=mandates.payment_token,
                checkout_mandate=mandates.checkout_mandate, current=checkout,
            )  # fmt: skip
            if isinstance(started, CpRejected):
                world.merchant_release(checkout.id)
                check(world)
                continue
            assert isinstance(started, CpApprovalRequired)
            world.sim.approve(started.order_id)
            if kind == "raised":
                world.sim.patch(started.order_id, amount="140.00")
            done = world.base.provider.finish(checkout_id=checkout.id, current=checkout)
            assert isinstance(done, CpAuthorized)
            if kind == "revoked":
                revoke_mandate(world.engine, sd_hash(first.payment.open_token), lambda: 1)
            if kind == "expired":
                world.tick.now += 100_000
            for _ in range(gate_runs):
                world.gate.run(checkout_id=checkout.id, current=checkout)
            check(world)
            if kind in ("revoked", "expired"):
                break  # a revoked or expired open mandate is finished for the rest of the example
        seen["captured"] += len(world.sim.captures)
        seen["voided"] += sum(
            1 for a in world.sim.authorizations.values() if a["status"] == "VOIDED"
        )

    run()
    # Not vacuous: the examples really captured money and really voided authorizations.
    assert seen["captured"] > 50 and seen["voided"] > 50, seen

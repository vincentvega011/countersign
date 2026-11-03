"""The Merchant keys single use on the issued mandate's identity, not on how it is presented (Decision 86)."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine

from countersign.gate import GatePassed
from countersign.merchant.verify import Accepted, Rejected
from tests.checkout_seed import seed_checkout
from tests.gate_support import GateWorld, make_gate_world
from tests.mandate_issuer import malleate_signature
from tests.merchant_support import make_checkout


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> GateWorld:
    return make_gate_world(app_engine)


def test_the_merchant_refuses_a_rewritten_presentation_of_a_used_checkout_mandate(
    world: GateWorld,
) -> None:
    first, _ = world.authorize()
    assert isinstance(
        world.gate.run(checkout_id=world.checkout.id, current=world.checkout), GatePassed
    )
    checkout = make_checkout(checkout_id="chk_" + "M" * 22)
    again = world.base.mandates(
        checkout=checkout, nonce="nonce-m",
        reuse_checkout_open=malleate_signature(first.checkout.open_token),
        reuse_open_payment=first.payment.open_token,
    )  # fmt: skip
    seed_checkout(world.engine, checkout)
    verdict = world.merchant.verify(
        mandate=again.checkout_mandate, issued_checkout=None, current=checkout
    )
    assert isinstance(verdict, Rejected) and not isinstance(verdict, Accepted), verdict

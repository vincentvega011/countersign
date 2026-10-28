"""Shared setup for Merchant role tests: keys, a signed session checkout, a verifier.

`AllowAllConstraintsForTests` exists only so the steps around the constraint step can be tested
before the real evaluator (P2.3). It is never imported from src/.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from countersign.canonical import checkout_hash
from countersign.canonical.models import Checkout, Item
from countersign.canonical.money import Money
from countersign.mandates import VerifiedChain
from countersign.merchant.authorization import checkout_jwt, sign_checkout
from countersign.merchant.constraints import ConstraintEvaluator, ConstraintResult
from countersign.merchant.decision_log import DecisionLogError
from countersign.merchant.keys import MerchantKey, generate_jwk, validate_jwk
from countersign.merchant.reservations import InMemoryReservationStore
from countersign.merchant.verify import CheckoutMandateVerifier, MerchantConfig
from tests.mandate_issuer import NOW, Issued, Keys, issue

CHECKOUT_ID = "chk_abcdefghijklmnopqrstuv"


class AllowAllConstraintsForTests:
    """Test-only evaluator: every constraint is satisfied."""

    def __init__(self) -> None:
        self.calls = 0

    def evaluate(self, *, chain: VerifiedChain, checkout: Checkout, now: float) -> ConstraintResult:
        self.calls += 1
        return ConstraintResult(True, "test_only_allow_all")


class RaisingConstraintsForTests:
    def evaluate(self, *, chain: VerifiedChain, checkout: Checkout, now: float) -> ConstraintResult:
        raise RuntimeError("evaluator crashed")


class ListLog:
    """In-memory decision log; `fail` makes every record fail."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self.fail = False
        self._lock = threading.Lock()

    def record(self, *, kind: str, checkout_id: str, payload: Mapping[str, Any]) -> None:
        if self.fail:
            raise DecisionLogError("log unavailable")
        with self._lock:
            self.entries.append({"kind": kind, "checkout_id": checkout_id, **payload})


def make_checkout(
    price: int = 4000,
    quantity: int = 2,
    title: str = "Over-ear headphones",
    checkout_id: str = CHECKOUT_ID,
    fee: int = 500,
    currency: str = "USD",
) -> Checkout:
    from countersign.canonical.models import Total

    item = Item(id="sku-headphones", title=title, price=Money(currency, price))
    return Checkout.from_lines(
        checkout_id,
        currency,
        [("li_1", item, quantity)],
        adjustments=[Total(type="fulfillment", amount=Money(currency, fee))],
    )


def signed_response(checkout: Checkout, key: MerchantKey) -> dict[str, Any]:
    body = {**checkout.to_ucp(), "status": "ready_for_complete", "ucp": {"version": "2026-08-25"}}
    return sign_checkout(body, key)


@dataclass
class Setup:
    merchant_key: MerchantKey
    keys: Keys
    checkout: Checkout
    issued: dict[str, Any]
    store: InMemoryReservationStore
    log: ListLog
    constraints: ConstraintEvaluator
    verifier: CheckoutMandateVerifier
    now: int = NOW
    clock_value: list[float] = field(default_factory=lambda: [float(NOW)])

    @property
    def jwt(self) -> str:
        return checkout_jwt(self.issued)

    def mandate(self, **kwargs: Any) -> Issued:
        kwargs.setdefault("checkout_jwt_value", self.jwt)
        return issue("checkout", keys=self.keys, **kwargs)

    def verify(self, mandate: object, current: Checkout | None = None) -> Any:
        return self.verifier.verify(
            mandate=mandate, issued_checkout=self.issued, current=current or self.checkout
        )


def make_setup(
    *,
    constraints: ConstraintEvaluator | None = None,
    platform_trusted: bool = True,
    published_key: MerchantKey | None = None,
    session_key: MerchantKey | None = None,
    checkout: Checkout | None = None,
) -> Setup:
    merchant_key = validate_jwk(generate_jwk())
    keys = Keys()
    checkout = checkout or make_checkout()
    issued = signed_response(checkout, session_key or merchant_key)
    store = InMemoryReservationStore()
    log = ListLog()
    chosen: ConstraintEvaluator = constraints or AllowAllConstraintsForTests()
    clock_value = [float(NOW)]
    config = MerchantConfig(
        issuer="https://merchant.example",
        signing_key=merchant_key,
        published_keys=[(published_key or merchant_key).public_jwk],
        platform_key=keys.issuer if platform_trusted else None,
    )
    verifier = CheckoutMandateVerifier(config, store, log, lambda: clock_value[0], chosen)
    assert checkout_hash(checkout_jwt(issued))
    return Setup(
        merchant_key, keys, checkout, issued, store, log, chosen, verifier, clock_value=clock_value
    )

"""The real constraint engine inside the Merchant role: M1 to M8 end to end, single use, retries.

The Merchant verifier, the chain primitives, the reservation store and the signed receipts are all
the real code. Only the PayPal side is absent (it arrives with P2.4): void and capture are played
by `store.release` / `store.consume` and the `BudgetAccount` events they would trigger.
"""

from __future__ import annotations

from typing import Any

from countersign.canonical.models import Checkout
from countersign.constraints import (
    BudgetAccount,
    CheckoutConstraintEvaluator,
    PaymentConstraintEvaluator,
)
from countersign.merchant.authorization import checkout_jwt
from countersign.merchant.constraints import ConstraintOutcome, DenyAllConstraints
from countersign.merchant.verify import (
    Accepted,
    CheckoutMandateVerifier,
    Rejected,
)
from tests.constraint_fixtures import (
    checkout_constraints,
    closed_payment_values,
    line_items_constraint,
    payment_constraints,
    verified_checkout_chain,
    verified_payment_chain,
)
from tests.mandate_issuer import NOW
from tests.merchant_support import (
    Setup,
    make_checkout,
    make_setup,
    signed_response,
)

REAL = CheckoutConstraintEvaluator("m-demo")


def with_constraints(constraints: list[dict[str, Any]]) -> dict[str, Any]:
    return {"edit_open_content": lambda c: c.update(constraints=constraints)}


def real_setup(**kwargs: Any) -> Setup:
    return make_setup(constraints=REAL, **kwargs)


def under_open(s: Setup, open_token: str, n: int, constraints: list[dict[str, Any]] | None = None):  # type: ignore[no-untyped-def]
    """A new checkout (own id) and a closed mandate for it under an existing open mandate."""
    checkout = make_checkout(checkout_id=f"chk_{n:022d}")
    issued = signed_response(checkout, s.merchant_key)
    mandate = s.mandate(
        reuse_open_token=open_token, nonce=f"n{n}", checkout_jwt_value=checkout_jwt(issued)
    )
    return mandate, issued, checkout


def verify_other(s: Setup, parts: tuple[Any, Any, Checkout]) -> Any:
    mandate, issued, checkout = parts
    return s.verifier.verify(mandate=mandate.token, issued_checkout=issued, current=checkout)


def test_full_verification_with_the_real_evaluator_accepts() -> None:
    s = real_setup()
    result = s.verify(s.mandate(**with_constraints(checkout_constraints())).token)
    assert isinstance(result, Accepted)


def test_the_selectively_disclosed_default_constraint_works_with_the_real_evaluator() -> None:
    s = real_setup(checkout=make_checkout(quantity=1))
    assert isinstance(s.verify(s.mandate().token), Accepted)


def test_the_engine_result_satisfies_the_merchant_interface() -> None:
    chain, _ = verified_checkout_chain()
    result = REAL.evaluate(chain=chain, checkout=make_checkout(), now=NOW)
    assert isinstance(result, ConstraintOutcome)


def test_a_checkout_that_differs_from_what_the_customer_allowed_is_rejected_at_m7() -> None:
    """Hash, signature, terms all match (the agent signed this checkout), but the open mandate
    allowed one pair of headphones and the checkout has two."""
    s = real_setup()
    token = s.mandate(**with_constraints([line_items_constraint(quantity=1)])).token
    result = s.verify(token)
    assert isinstance(result, Rejected)
    assert (result.step, result.reason, result.ucp_code) == (
        "M7",
        "constraint_violated",
        "mandate_scope_mismatch",
    )
    assert result.detail == "checkout.line_items:not_matched"
    assert s.store._open == {}  # nothing was reserved


def test_an_unknown_constraint_is_unresolved_at_m7() -> None:
    s = real_setup()
    token = s.mandate(**with_constraints([*checkout_constraints(), {"type": "acme.x"}])).token
    result = s.verify(token)
    assert isinstance(result, Rejected)
    assert (result.step, result.reason, result.detail) == (
        "M7",
        "constraint_unresolved",
        "unresolved_constraint",
    )


def test_a_mandate_for_another_merchant_is_rejected_at_m7() -> None:
    s = real_setup()
    other = [
        line_items_constraint(),
        {"type": "checkout.allowed_merchants", "allowed": [{"id": "m-other", "name": "Other"}]},
    ]
    result = s.verify(s.mandate(**with_constraints(other)).token)
    assert (
        isinstance(result, Rejected)
        and result.detail == "checkout.allowed_merchants:merchant_not_allowed"
    )


def test_human_present_mandate_passes_the_real_evaluator() -> None:
    from tests.mandate_issuer import issue_human_present

    s = real_setup()
    assert isinstance(s.verify(issue_human_present(s.keys, checkout_jwt_value=s.jwt)), Accepted)


def test_without_an_injected_evaluator_everything_is_denied() -> None:
    s = real_setup()
    verifier = CheckoutMandateVerifier(s.verifier._config, s.store, s.log, lambda: float(NOW))
    assert isinstance(verifier._constraints, DenyAllConstraints)
    result = verifier.verify(
        mandate=s.mandate(**with_constraints(checkout_constraints())).token,
        issued_checkout=s.issued,
        current=s.checkout,
    )
    assert isinstance(result, Rejected) and result.reason == "constraint_unresolved"


def test_second_and_third_purchases_under_one_open_mandate_are_denied() -> None:
    s = real_setup()
    first = s.mandate(**with_constraints(checkout_constraints()))
    assert isinstance(s.verify(first.token), Accepted)
    for n in (2, 3):
        result = verify_other(s, under_open(s, first.open_token, n))
        assert isinstance(result, Rejected)
        assert (result.step, result.reason) == ("M8", "open_mandate_in_use")


def test_after_a_void_before_capture_the_same_open_mandate_can_be_retried() -> None:
    s = real_setup()
    account = BudgetAccount("USD")
    first = s.mandate(**with_constraints(checkout_constraints()))
    accepted = s.verify(first.token)
    assert isinstance(accepted, Accepted)
    account.reserve("first", 8500)
    # the PayPal authorization is voided before capture: release both
    s.store.release(accepted.reservation)
    account.void("first")
    retry = verify_other(s, under_open(s, first.open_token, 2))
    assert isinstance(retry, Accepted)
    assert account.view().used_minor == 0  # the void restored the headroom


def test_after_capture_and_refund_the_open_mandate_cannot_be_used_and_headroom_stays_spent() -> (
    None
):
    s = real_setup()
    account = BudgetAccount("USD")
    first = s.mandate(**with_constraints(checkout_constraints()))
    accepted = s.verify(first.token)
    assert isinstance(accepted, Accepted)
    account.reserve("first", 8500)
    s.store.consume(accepted.reservation)  # captured
    account.capture("first")
    account.refund("first", 8500)  # refunded in full
    denied = verify_other(s, under_open(s, first.open_token, 2))
    assert isinstance(denied, Rejected) and denied.reason == "open_mandate_in_use"
    # and the budget layer agrees: the refund did not restore any headroom
    checkout_chain, keys = verified_checkout_chain()
    chain = verified_payment_chain(
        keys,
        checkout_chain,
        constraints=lambda d: payment_constraints(d, 10_000),
        values=closed_payment_values(8500),
    )
    result = PaymentConstraintEvaluator().evaluate_payment(
        payment_chain=chain, checkout_chain=checkout_chain, spend=account.view(), now=NOW
    )
    assert result.satisfied is False and result.reason == "payment.budget:over_budget"

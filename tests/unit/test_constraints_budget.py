"""Add-only spend accounting, split purchases, and the policy function."""

from __future__ import annotations

from typing import Any

import pytest

from countersign.canonical.models import Checkout, Item
from countersign.canonical.money import Money
from countersign.constraints import (
    BudgetAccount,
    BudgetError,
    CategoryPolicy,
    PaymentConstraintEvaluator,
    SpendView,
    check_category_policy,
)
from tests.constraint_fixtures import verified_checkout_chain, verified_payment_chain
from tests.mandate_issuer import NOW

MAX = 10_000


def evaluate(spend: SpendView | None, amount: int) -> Any:
    from tests.constraint_fixtures import closed_payment_values, payment_constraints

    checkout_chain, keys = verified_checkout_chain()
    chain = verified_payment_chain(
        keys,
        checkout_chain,
        constraints=lambda d: payment_constraints(d, MAX),
        values=closed_payment_values(amount),
    )
    return PaymentConstraintEvaluator().evaluate_payment(
        payment_chain=chain, checkout_chain=checkout_chain, spend=spend, now=NOW
    )


# ----- the account -----


def test_reserve_capture_void_refund_follow_the_add_only_rules() -> None:
    account = BudgetAccount("USD")
    account.reserve("a", 4000)
    assert account.view() == SpendView("USD", 0, 4000)
    account.capture("a")
    assert account.view() == SpendView("USD", 4000, 0)
    account.reserve("b", 1000)
    account.void("b")
    assert account.view() == SpendView("USD", 4000, 0)
    account.refund("a", 4000)  # a refund never restores headroom
    assert account.view() == SpendView("USD", 4000, 0)
    assert account.refunded_minor == 4000


@pytest.mark.parametrize(
    "event",
    [
        lambda a: a.capture("nope"),
        lambda a: a.void("nope"),
        lambda a: a.refund("nope", 1),
        lambda a: a.reserve("x", 0),
        lambda a: a.reserve("x", -5),
        lambda a: a.reserve("x", 1.5),
        lambda a: a.reserve("x", True),
        lambda a: a.reserve("a", 5),  # id reuse
        lambda a: (a.capture("a"), a.void("a")),  # void of captured money
        lambda a: (a.capture("a"), a.capture("a")),
        lambda a: (a.capture("a"), a.refund("a", 5000)),  # more than captured
        lambda a: (a.capture("a"), a.refund("a", 0)),
        lambda a: a.refund("a", 1),  # refund before capture
    ],
)
def test_every_other_transition_is_refused(event: Any) -> None:
    account = BudgetAccount("USD")
    account.reserve("a", 4000)
    with pytest.raises(BudgetError):
        event(account)


def test_a_failed_event_changes_nothing() -> None:
    account = BudgetAccount("USD")
    account.reserve("a", 4000)
    before = account.view()
    with pytest.raises(BudgetError):
        account.void("zzz")
    assert account.view() == before


def test_view_excluding_one_reservation_for_the_gate() -> None:
    account = BudgetAccount("USD")
    account.reserve("a", 4000)
    account.reserve("b", 3000)
    assert account.view_excluding("a") == SpendView("USD", 0, 3000)
    with pytest.raises(BudgetError):
        account.view_excluding("unknown")


@pytest.mark.parametrize("bad", [(-1, 0), (0, -1), (1.5, 0), (0, True)])
def test_a_spend_view_is_non_negative_integers(bad: tuple[Any, Any]) -> None:
    with pytest.raises(BudgetError):
        SpendView("USD", *bad)
    with pytest.raises(BudgetError):
        SpendView("", 0, 0)


# ----- split purchases and the lifecycle against the real evaluator -----


def test_three_purchases_each_fine_alone_but_over_budget_together_the_third_is_denied() -> None:
    account = BudgetAccount("USD")
    for n, expect_ok in enumerate((True, True, False), 1):
        result = evaluate(account.view(), 4000)
        assert result.satisfied is expect_ok, (n, result)
        if expect_ok:
            account.reserve(f"p{n}", 4000)
            account.capture(f"p{n}")
        else:
            assert result.reason == "payment.budget:over_budget"
    assert evaluate(SpendView("USD", 0, 0), 4000).satisfied is True  # each alone is fine


def test_an_in_flight_reservation_blocks_a_concurrent_presentation() -> None:
    account = BudgetAccount("USD")
    account.reserve("first", 8000)
    assert evaluate(account.view(), 4000).satisfied is False


def test_a_void_before_capture_restores_headroom_and_allows_a_retry() -> None:
    account = BudgetAccount("USD")
    account.reserve("first", 8000)
    assert evaluate(account.view(), 8000).satisfied is False
    account.void("first")
    assert evaluate(account.view(), 8000).satisfied is True


def test_a_refund_after_capture_never_restores_headroom() -> None:
    account = BudgetAccount("USD")
    account.reserve("first", 8000)
    account.capture("first")
    account.refund("first", 8000)  # the whole amount is refunded
    result = evaluate(account.view(), 8000)
    assert result.satisfied is False and result.reason == "payment.budget:over_budget"
    assert evaluate(account.view(), 2000).satisfied is True  # only the unspent remainder is left


# ----- category policy (merchant policy, separate from mandates) -----

CATEGORIES = {"sku-a": "headphones", "sku-b": "cables"}


def basket(*ids: str) -> Checkout:
    lines = [
        (f"li_{n}", Item(id=i, title=i, price=Money("USD", 100)), 1) for n, i in enumerate(ids, 1)
    ]
    return Checkout.from_lines("chk_abcdefghijklmnopqrstuv", "USD", lines)


def test_category_policy() -> None:
    policy = CategoryPolicy(frozenset({"headphones"}))
    lookup = CATEGORIES.get
    assert check_category_policy(basket("sku-a"), policy, lookup).allowed
    denied = check_category_policy(basket("sku-a", "sku-b"), policy, lookup)
    assert (denied.allowed, denied.reason) == (False, "category_not_allowed")
    unknown = check_category_policy(basket("sku-zzz"), policy, lookup)
    assert (unknown.allowed, unknown.reason) == (False, "category_unknown")
    assert not check_category_policy(basket("sku-a"), CategoryPolicy(frozenset()), lookup).allowed
    assert check_category_policy(basket("sku-zzz"), None, lookup).allowed


def test_category_policy_uses_the_catalog_not_agent_text() -> None:
    from countersign.catalog.catalog import load_catalog

    catalog = load_catalog()
    first = catalog.items[0]
    item = Item(id=first.id, title="anything the agent says", price=Money("USD", 100))
    checkout = Checkout.from_lines("chk_abcdefghijklmnopqrstuv", "USD", [("li_1", item, 1)])
    lookup = lambda i: catalog.item(i).category
    assert check_category_policy(
        checkout, CategoryPolicy(frozenset({first.category})), lookup
    ).allowed
    assert not check_category_policy(checkout, CategoryPolicy(frozenset({"other"})), lookup).allowed

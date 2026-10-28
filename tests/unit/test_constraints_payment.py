"""The native payment constraints: boundaries, missing fields, wrong types, currencies, amounts."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from countersign.constraints import PaymentConstraintEvaluator, SpendView
from tests.constraint_fixtures import (
    INSTRUMENT,
    MERCHANT,
    PISP,
    closed_payment_values,
    payment_constraints,
    verified_checkout_chain,
    verified_payment_chain,
)
from tests.mandate_issuer import NOW

EVALUATOR = PaymentConstraintEvaluator()
NO_SPEND = SpendView("USD", 0, 0)


def pay(
    mutate: Callable[[list[dict[str, Any]]], list[dict[str, Any]] | None] | None = None,
    values: dict[str, Any] | None = None,
    spend: SpendView | None = NO_SPEND,
    now: float = NOW,
    **kwargs: Any,
):  # type: ignore[no-untyped-def]
    checkout_chain, keys = verified_checkout_chain()

    def build(digest: str) -> list[dict[str, Any]]:
        constraints = payment_constraints(digest)
        replaced = mutate(constraints) if mutate else None
        return replaced if replaced is not None else constraints

    payment_chain = verified_payment_chain(
        keys, checkout_chain, constraints=build, values=values, **kwargs
    )
    return EVALUATOR.evaluate_payment(
        payment_chain=payment_chain, checkout_chain=checkout_chain, spend=spend, now=now
    )


def ok(result: Any) -> None:
    assert result.satisfied is True and not result.unresolved, result


def bad(result: Any, reason: str, unresolved: bool = False) -> None:
    assert result.satisfied is False and result.reason == reason, result
    assert result.unresolved is unresolved


def change(kind: str, **fields: Any) -> Callable[[list[dict[str, Any]]], None]:
    def apply(constraints: list[dict[str, Any]]) -> None:
        for constraint in constraints:
            if constraint["type"] == kind:
                constraint.update(fields)
                for name in [k for k, v in fields.items() if v is _DROP]:
                    del constraint[name]

    return apply


_DROP = object()


def drop(kind: str) -> Callable[[list[dict[str, Any]]], list[dict[str, Any]]]:
    return lambda constraints: [c for c in constraints if c["type"] != kind]


def values(amount: int = 8500, currency: str = "USD", **more: Any) -> dict[str, Any]:
    out = closed_payment_values(amount, currency)
    out.update(more)
    return out


def test_the_default_payment_mandate_is_satisfied() -> None:
    ok(pay())


# ----- payment.amount_range -----


@pytest.mark.parametrize(
    ("amount", "reason"),
    [
        (10_000, None),
        (10_001, "payment.amount_range:above_max"),
        (9_999, None),
        (1, None),
    ],
)
def test_amount_range_max_boundary(amount: int, reason: str | None) -> None:
    constraints = lambda cs: [
        c | {"max": 10_000} if c["type"] == "payment.amount_range" else c for c in cs
    ]
    # budget would also bound the amount; raise it so only the range is under test
    budget = change("payment.budget", max=1_000_000)

    def mutate(cs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        budget(cs)
        return constraints(cs)

    result = pay(mutate, values(amount))
    ok(result) if reason is None else bad(result, reason)


@pytest.mark.parametrize(
    ("amount", "reason"), [(499, "payment.amount_range:below_min"), (500, None), (501, None)]
)
def test_amount_range_min_boundary(amount: int, reason: str | None) -> None:
    result = pay(change("payment.amount_range", min=500), values(amount))
    ok(result) if reason is None else bad(result, reason)


@pytest.mark.parametrize(
    ("edit", "reason"),
    [
        ({"max": -1}, "payment.amount_range:max_invalid"),
        ({"max": 100.5}, "payment.amount_range:max_invalid"),
        ({"max": 100.0}, "payment.amount_range:max_invalid"),
        ({"max": True}, "payment.amount_range:max_invalid"),
        ({"max": "100"}, "payment.amount_range:max_invalid"),
        ({"max": None}, "payment.amount_range:max_invalid"),
        ({"min": -1}, "payment.amount_range:min_invalid"),
        ({"min": 1.5}, "payment.amount_range:min_invalid"),
        ({"min": None}, "payment.amount_range:min_invalid"),
        ({"min": 20_000}, "payment.amount_range:min_invalid"),
        ({"currency": "usd"}, "payment.amount_range:currency_invalid"),
        ({"currency": 5}, "payment.amount_range:currency_invalid"),
        ({"currency": "EUR"}, "payment.amount_range:currency_mismatch"),
    ],
)
def test_amount_range_invalid_fields(edit: dict[str, Any], reason: str) -> None:
    bad(pay(change("payment.amount_range", **edit)), reason)


def test_amount_range_zero_max_denies_every_payment() -> None:
    bad(pay(change("payment.amount_range", max=0, min=_DROP)), "payment.amount_range:above_max")


def test_amount_range_missing_fields() -> None:
    bad(pay(change("payment.amount_range", max=_DROP)), "payment.amount_range:max_invalid")
    bad(
        pay(change("payment.amount_range", currency=_DROP)), "payment.amount_range:currency_invalid"
    )


def test_amount_range_currency_of_the_payment_differs() -> None:
    bad(pay(values=values(currency="EUR")), "payment.amount_range:currency_mismatch")


@pytest.mark.parametrize("amount", [0, -1, 85.5, True, "8500", None])
def test_the_payment_amount_must_be_a_positive_integer(amount: Any) -> None:
    v = values()
    v["payment_amount"] = {"amount": amount, "currency": "USD"}
    bad(pay(values=v), "payment_mandate:payment_amount_invalid")


@pytest.mark.parametrize(
    "amount_object",
    [
        None,
        "85",
        {"amount": 5},
        {"currency": "USD"},
        {"amount": 5, "currency": "usd"},
        {"amount": 5, "currency": "USD", "extra": 1},
        {"amount": 5, "currency": 1},
    ],
)
def test_the_payment_amount_object_must_be_exact(amount_object: Any) -> None:
    v = values()
    v["payment_amount"] = amount_object
    bad(pay(values=v), "payment_mandate:payment_amount_invalid")


# ----- allowed payees, instruments, PISPs -----


def test_allowed_payees() -> None:
    ok(pay())
    other = change("payment.allowed_payees", allowed=[{"id": "m-other", "name": "Other"}])
    bad(pay(other), "payment.allowed_payees:payee_not_allowed")
    bad(pay(change("payment.allowed_payees", allowed=[])), "payment.allowed_payees:none_revealed")
    bad(
        pay(change("payment.allowed_payees", allowed="x")),
        "payment.allowed_payees:allowed_malformed",
    )
    bad(
        pay(change("payment.allowed_payees", allowed=[{"name": "n"}])),
        "payment.allowed_payees:payee_malformed",
    )
    bad(
        pay(change("payment.allowed_payees", allowed=[{**MERCHANT, "tax_id": "1"}])),
        "unresolved_constraint",
        True,
    )


@pytest.mark.parametrize(
    "payee", [None, "m-demo", {"id": "m-demo"}, {"name": "n"}, {"id": 1, "name": "n"}]
)
def test_the_closed_payee_must_be_a_merchant_object(payee: Any) -> None:
    v = values()
    v["payee"] = payee
    bad(pay(values=v), "payment_mandate:payee_invalid")


def test_allowed_payment_instruments() -> None:
    ok(pay())
    bad(
        pay(
            change(
                "payment.allowed_payment_instruments", allowed=[{"id": "other", "type": "paypal"}]
            )
        ),
        "payment.allowed_payment_instruments:instrument_not_allowed",
    )
    bad(
        pay(
            change(
                "payment.allowed_payment_instruments",
                allowed=[{"id": INSTRUMENT["id"], "type": "card"}],
            )
        ),
        "payment.allowed_payment_instruments:instrument_not_allowed",
    )
    bad(
        pay(change("payment.allowed_payment_instruments", allowed=[])),
        "payment.allowed_payment_instruments:none_revealed",
    )
    bad(
        pay(change("payment.allowed_payment_instruments", allowed=[{"id": "x"}])),
        "payment.allowed_payment_instruments:instrument_malformed",
    )


def test_a_closed_mandate_without_an_instrument_cannot_satisfy_the_instrument_constraint() -> None:
    v = values()
    del v["payment_instrument"]
    bad(pay(values=v), "payment.allowed_payment_instruments:instrument_not_allowed")
    ok(pay(drop("payment.allowed_payment_instruments"), v))


def test_allowed_pisps() -> None:
    add = lambda cs: [*cs, {"type": "payment.allowed_pisps", "allowed": [dict(PISP)]}]
    ok(pay(add, values(pisp=dict(PISP))))
    bad(pay(add), "payment.allowed_pisps:pisp_not_allowed")  # no pisp in the closed mandate
    other = {**PISP, "domain_name": "evil.example"}
    bad(pay(add, values(pisp=other)), "payment.allowed_pisps:pisp_not_allowed")
    bad(
        pay(
            lambda cs: [*cs, {"type": "payment.allowed_pisps", "allowed": []}],
            values(pisp=dict(PISP)),
        ),
        "payment.allowed_pisps:none_revealed",
    )
    bad(
        pay(
            lambda cs: [*cs, {"type": "payment.allowed_pisps", "allowed": [{"legal_name": "x"}]}],
            values(pisp=dict(PISP)),
        ),
        "payment.allowed_pisps:pisp_malformed",
    )
    bad(pay(values=values(pisp={"legal_name": "x"})), "payment_mandate:pisp_invalid")


# ----- payment.reference -----


def test_reference_must_name_the_open_checkout_mandate_of_this_checkout() -> None:
    ok(pay())
    bad(
        pay(change("payment.reference", conditional_transaction_id="A" * 43)),
        "payment.reference:checkout_mandate_not_referenced",
    )
    bad(
        pay(change("payment.reference", conditional_transaction_id="")),
        "payment.reference:reference_malformed",
    )
    bad(
        pay(change("payment.reference", conditional_transaction_id=5)),
        "payment.reference:reference_malformed",
    )
    bad(
        pay(change("payment.reference", conditional_transaction_id=_DROP)),
        "payment.reference:reference_malformed",
    )


def test_reference_is_required_in_an_open_payment_mandate() -> None:
    bad(pay(drop("payment.reference")), "payment.reference:required_constraint_missing")


def test_a_reference_to_the_closed_checkout_mandate_does_not_count() -> None:
    checkout_chain, keys = verified_checkout_chain()
    closed_digest = checkout_chain.final.digest
    chain = verified_payment_chain(
        keys, checkout_chain, constraints=payment_constraints(closed_digest)
    )
    bad(
        EVALUATOR.evaluate_payment(
            payment_chain=chain, checkout_chain=checkout_chain, spend=NO_SPEND, now=NOW
        ),
        "payment.reference:checkout_mandate_not_referenced",
    )


def test_a_reference_to_another_customers_checkout_mandate_fails() -> None:
    other_chain, _ = verified_checkout_chain()
    checkout_chain, keys = verified_checkout_chain()
    chain = verified_payment_chain(
        keys, checkout_chain, constraints=payment_constraints(other_chain.links[0].digest)
    )
    bad(
        EVALUATOR.evaluate_payment(
            payment_chain=chain, checkout_chain=checkout_chain, spend=NO_SPEND, now=NOW
        ),
        "payment.reference:checkout_mandate_not_referenced",
    )


# ----- payment.budget -----


@pytest.mark.parametrize(
    ("spent", "in_flight", "reason"),
    [
        (1_500, 0, None),  # 1500 + 8500 == 10000: equal
        (1_501, 0, "payment.budget:over_budget"),  # just above
        (1_499, 0, None),  # just below
        (0, 1_500, None),
        (0, 1_501, "payment.budget:over_budget"),  # in-flight reservations count
        (1_000, 501, "payment.budget:over_budget"),
    ],
)
def test_budget_boundary_counts_captured_and_in_flight(
    spent: int, in_flight: int, reason: str | None
) -> None:
    result = pay(spend=SpendView("USD", spent, in_flight))
    ok(result) if reason is None else bad(result, reason)


@pytest.mark.parametrize("maximum", [100.5, 100.0, "100", True, None, [100], 1e3])
def test_budget_max_that_is_not_an_integer_makes_the_mandate_invalid(maximum: Any) -> None:
    bad(pay(change("payment.budget", max=maximum)), "payment.budget:max_not_integer")


def test_budget_negative_zero_and_currency() -> None:
    bad(pay(change("payment.budget", max=-1)), "payment.budget:max_negative")
    bad(pay(change("payment.budget", max=0)), "payment.budget:over_budget")
    bad(pay(change("payment.budget", currency="EUR")), "payment.budget:currency_mismatch")
    bad(pay(change("payment.budget", currency="eur")), "payment.budget:currency_invalid")
    bad(pay(change("payment.budget", max=_DROP)), "payment.budget:max_not_integer")


def test_budget_without_a_spend_view_fails_closed() -> None:
    bad(pay(spend=None), "payment.budget:spend_view_unavailable")
    bad(pay(spend=SpendView("EUR", 0, 0)), "payment.budget:spend_view_currency_mismatch")


def test_a_mandate_without_a_budget_constraint_does_not_need_a_spend_view() -> None:
    ok(pay(drop("payment.budget"), spend=None))


# ----- payment.agent_recurrence -----


@pytest.mark.parametrize(
    "frequency", ["ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"]
)
def test_recurrence_with_one_occurrence_is_accepted(frequency: str) -> None:
    ok(pay(change("payment.agent_recurrence", frequency=frequency)))


@pytest.mark.parametrize("occurrences", [2, 3, 100, 0, -1, 1.0, True, "1", None, _DROP])
def test_recurrence_with_any_other_occurrence_count_is_unresolved(occurrences: Any) -> None:
    bad(
        pay(change("payment.agent_recurrence", max_occurrences=occurrences)),
        "unresolved_constraint",
        unresolved=True,
    )


@pytest.mark.parametrize("frequency", ["HOURLY", "on_demand", 1, None, _DROP])
def test_recurrence_with_an_unknown_frequency_is_invalid(frequency: Any) -> None:
    bad(
        pay(change("payment.agent_recurrence", frequency=frequency)),
        "payment.agent_recurrence:frequency_invalid",
    )


# ----- payment.execution_date -----

WINDOW = {
    "type": "payment.execution_date",
    "not_before": "2026-10-30T00:00:00Z",
    "not_after": "2026-10-31T23:59:59Z",
}
T0 = datetime(2026, 10, 30, tzinfo=UTC).timestamp()


def with_window(**fields: Any) -> Callable[[list[dict[str, Any]]], list[dict[str, Any]]]:
    return lambda cs: [*cs, {**WINDOW, **fields}]


@pytest.mark.parametrize(
    ("now", "reason"),
    [
        (T0 - 1, "payment.execution_date:before_window"),
        (T0, None),  # equal to not_before
        (T0 + 2 * 86_400 - 1 - 1, None),
        (T0 + 2 * 86_400 - 1, None),  # equal to not_after (23:59:59)
        (T0 + 2 * 86_400, "payment.execution_date:after_window"),
    ],
)
def test_execution_date_window_boundaries_use_the_clock_when_the_mandate_has_no_date(
    now: float, reason: str | None
) -> None:
    result = pay(with_window(), now=now)
    ok(result) if reason is None else bad(result, reason)


def test_execution_date_of_the_closed_mandate_is_compared() -> None:
    inside = values(execution_date="2026-10-30T12:00:00Z")
    ok(pay(with_window(), inside, now=T0 + 12 * 3600))
    early = values(execution_date="2026-10-29T23:59:59Z")
    bad(pay(with_window(), early, now=T0 + 3600), "payment.execution_date:before_window")


def test_a_date_without_a_time_is_a_utc_day_and_not_after_covers_the_whole_day() -> None:
    day = with_window(not_before="2026-10-30", not_after="2026-10-30")
    ok(pay(day, now=T0))
    ok(pay(day, now=T0 + 86_399))
    bad(pay(day, now=T0 + 86_400), "payment.execution_date:after_window")
    bad(pay(day, now=T0 - 1), "payment.execution_date:before_window")


@pytest.mark.parametrize(
    "bad_value",
    [
        "2026-10-30T00:00:00",
        "tomorrow",
        "20261030",
        "2026-13-01",
        "2026-10-30 00:00:00Z",
        5,
        None,
        "",
    ],
)
def test_execution_date_bounds_must_be_strict_iso_8601(bad_value: Any) -> None:
    bad(pay(with_window(not_before=bad_value)), "payment.execution_date:not_before_invalid")
    bad(pay(with_window(not_after=bad_value)), "payment.execution_date:not_after_invalid")


def test_execution_date_with_a_timezone_offset_is_converted() -> None:
    offset = with_window(
        not_before="2026-10-30T05:45:00+05:45", not_after="2026-10-30T05:45:00+05:45"
    )
    ok(pay(offset, now=T0))  # 05:45 +05:45 is exactly 00:00 UTC
    bad(pay(offset, now=T0 + 1), "payment.execution_date:after_window")


def test_a_constraint_without_bounds_is_vacuous_but_understood() -> None:
    ok(pay(lambda cs: [*cs, {"type": "payment.execution_date"}]))


def test_the_closed_execution_date_must_not_be_in_the_future() -> None:
    later = values(execution_date="2026-11-30T00:00:00Z")
    bad(pay(values=later, now=T0), "payment.execution_date:in_future")
    skew = datetime.fromtimestamp(T0 + 60, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    ok(pay(values=values(execution_date=skew), now=T0))  # exactly the skew ahead
    over = datetime.fromtimestamp(T0 + 61, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    bad(pay(values=values(execution_date=over), now=T0), "payment.execution_date:in_future")
    bad(
        pay(values=values(execution_date="soon"), now=T0),
        "payment.execution_date:execution_date_invalid",
    )


# ----- unknown types, duplicates, claims -----


def test_unknown_and_foreign_constraint_types_fail_closed() -> None:
    for kind in (
        "acme.limit",
        "payment.velocity",
        "checkout.line_items",
        "checkout.allowed_merchants",
        "",
    ):
        bad(pay(lambda cs, k=kind: [*cs, {"type": k}]), "unresolved_constraint", True)


def test_duplicate_constraints_and_malformed_entries_fail() -> None:
    bad(pay(lambda cs: [*cs, dict(cs[1])]), "payment.amount_range:duplicate_constraint")
    bad(pay(lambda cs: [*cs, "x"]), "constraints:constraint_malformed")


def test_a_preset_open_claim_cannot_be_changed_by_the_agent() -> None:
    preset = {"payee": dict(MERCHANT)}
    ok(pay(open_edit=lambda c: c.update(preset)))
    changed = values(payee={"id": "m-evil", "name": "Evil"})
    bad(pay(values=changed, open_edit=lambda c: c.update(preset)), "mandate:open_claims_changed")
    dropped = values()
    del dropped["payee"]
    bad(pay(values=dropped, open_edit=lambda c: c.update(preset)), "mandate:open_claims_changed")
    amount = {"payment_amount": {"amount": 8500, "currency": "USD"}}
    bad(
        pay(values=values(9000), open_edit=lambda c: c.update(amount)),
        "mandate:open_claims_changed",
    )


def test_the_closed_payment_mandate_must_not_carry_constraints() -> None:
    bad(pay(values=values(constraints=[])), "mandate:closed_mandate_unexpected")

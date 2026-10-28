"""checkout.line_items and checkout.allowed_merchants, and the rules common to every mandate."""

from __future__ import annotations

from typing import Any

import pytest

from countersign.canonical.models import Checkout, Item
from countersign.canonical.money import Money
from countersign.constraints import CheckoutConstraintEvaluator
from tests.constraint_fixtures import (
    MERCHANT,
    checkout_constraints,
    checkout_for,
    line_items_constraint,
    verified_checkout_chain,
)
from tests.mandate_issuer import NOW

EVALUATOR = CheckoutConstraintEvaluator("m-demo")


def run(constraints: Any = None, checkout: Checkout | None = None, **kwargs: Any):  # type: ignore[no-untyped-def]
    chain, _ = verified_checkout_chain(constraints=constraints, **kwargs)
    return EVALUATOR.evaluate(chain=chain, checkout=checkout or checkout_for(), now=NOW)


def ok(result: Any) -> None:
    assert result.satisfied is True and result.unresolved is False, result


def bad(result: Any, reason: str, unresolved: bool = False) -> None:
    assert result.satisfied is False and result.reason == reason, result
    assert result.unresolved is unresolved


def multi_checkout(*lines: tuple[str, int]) -> Checkout:
    items = [
        (f"li_{n}", Item(id=i, title=f"Title {i}", price=Money("USD", 1000)), q)
        for n, (i, q) in enumerate(lines, 1)
    ]
    return Checkout.from_lines("chk_abcdefghijklmnopqrstuv", "USD", items)


# ----- checkout.line_items: boundaries -----


def test_the_default_mandate_is_satisfied() -> None:
    ok(run())


@pytest.mark.parametrize(("quantity", "good"), [(1, False), (2, True), (3, False)])
def test_line_items_quantity_just_below_equal_just_above(quantity: int, good: bool) -> None:
    result = run(checkout=checkout_for(quantity=quantity))
    ok(result) if good else bad(result, "checkout.line_items:not_matched")


def test_line_items_item_not_among_the_acceptable_ones() -> None:
    bad(run(checkout=checkout_for(item_id="sku-other")), "checkout.line_items:not_matched")


def test_line_items_an_extra_item_in_the_checkout_fails() -> None:
    bad(
        run(checkout=multi_checkout(("sku-headphones", 2), ("sku-extra", 1))),
        "checkout.line_items:not_matched",
    )


def test_line_items_units_of_one_item_across_lines_are_summed() -> None:
    ok(run(checkout=multi_checkout(("sku-headphones", 1), ("sku-headphones", 1))))


def test_line_items_withheld_disclosure_removes_the_permission() -> None:
    constraint = line_items_constraint()
    constraint["items"][0]["acceptable_items"] = []  # nothing was revealed
    bad(run([constraint]), "checkout.line_items:not_matched")


SHOES = {
    "type": "checkout.line_items",
    "items": [
        {
            "id": "shoes",
            "quantity": 1,
            "acceptable_items": [
                {"id": "BAB1234", "title": "Red Style"},
                {"id": "FAF1234", "title": "Blue Style"},
            ],
        },
        {"id": "socks", "quantity": 1, "acceptable_items": [{"id": "QRT1234", "title": "Socks"}]},
    ],
}


@pytest.mark.parametrize(
    ("lines", "good"),
    [
        ([("BAB1234", 1), ("QRT1234", 1)], True),  # Red Style + socks (spec example)
        ([("FAF1234", 1), ("QRT1234", 1)], True),  # Blue Style + socks
        ([("BAB1234", 1), ("FAF1234", 1)], False),  # two shoes
        ([("BAB1234", 1)], False),
        ([("FAF1234", 1)], False),
        ([("QRT1234", 1)], False),
        ([("BAB1234", 2), ("QRT1234", 1)], False),  # a unit used twice
    ],
)
def test_line_items_the_specs_own_examples(lines: list[tuple[str, int]], good: bool) -> None:
    result = run([SHOES], multi_checkout(*lines))
    ok(result) if good else bad(result, "checkout.line_items:not_matched")


def test_line_items_no_item_or_requirement_is_used_twice() -> None:
    both = {
        "type": "checkout.line_items",
        "items": [
            {"id": "a", "quantity": 1, "acceptable_items": [{"id": "X", "title": "x"}]},
            {"id": "b", "quantity": 1, "acceptable_items": [{"id": "X", "title": "x"}]},
        ],
    }
    bad(run([both], multi_checkout(("X", 1))), "checkout.line_items:not_matched")
    ok(run([both], multi_checkout(("X", 2))))


@pytest.mark.parametrize(
    ("edit", "reason"),
    [
        (lambda c: c.update(items=[]), "checkout.line_items:items_malformed"),
        (lambda c: c.update(items="x"), "checkout.line_items:items_malformed"),
        (lambda c: c.update(items=["x"]), "checkout.line_items:requirement_malformed"),
        (lambda c: c["items"][0].update(quantity=0), "checkout.line_items:quantity_invalid"),
        (lambda c: c["items"][0].update(quantity=-1), "checkout.line_items:quantity_invalid"),
        (lambda c: c["items"][0].update(quantity=True), "checkout.line_items:quantity_invalid"),
        (lambda c: c["items"][0].update(quantity=2.0), "checkout.line_items:quantity_invalid"),
        (lambda c: c["items"][0].update(quantity="2"), "checkout.line_items:quantity_invalid"),
        (lambda c: c["items"][0].pop("quantity"), "checkout.line_items:quantity_invalid"),
        (lambda c: c["items"][0].update(id=""), "checkout.line_items:requirement_id_invalid"),
        (lambda c: c["items"][0].pop("id"), "checkout.line_items:requirement_id_invalid"),
        (
            lambda c: c["items"][0].update(acceptable_items="x"),
            "checkout.line_items:acceptable_items_malformed",
        ),
        (
            lambda c: c["items"][0].pop("acceptable_items"),
            "checkout.line_items:acceptable_items_malformed",
        ),
        (
            lambda c: c["items"][0].update(acceptable_items=[{"title": "t"}]),
            "checkout.line_items:acceptable_item_malformed",
        ),
        (
            lambda c: c["items"][0].update(acceptable_items=[{"id": 5, "title": "t"}]),
            "checkout.line_items:acceptable_item_malformed",
        ),
        (
            lambda c: c["items"].append(dict(c["items"][0])),
            "checkout.line_items:requirement_id_invalid",
        ),
    ],
)
def test_line_items_malformed_constraints_fail(edit: Any, reason: str) -> None:
    constraint = line_items_constraint()
    edit(constraint)
    bad(run([constraint]), reason)


@pytest.mark.parametrize(
    "edit",
    [
        lambda c: c.update(note="x"),
        lambda c: c["items"][0].update(note="x"),
        lambda c: c["items"][0]["acceptable_items"][0].update(price=1),
    ],
)
def test_line_items_a_member_that_is_not_understood_is_unresolved(edit: Any) -> None:
    constraint = line_items_constraint()
    edit(constraint)
    bad(run([constraint]), "unresolved_constraint", unresolved=True)


# ----- checkout.allowed_merchants -----


def test_allowed_merchants_member_equal_and_not() -> None:
    ok(run())
    other = [
        line_items_constraint(),
        {"type": "checkout.allowed_merchants", "allowed": [{"id": "m-other", "name": "Other"}]},
    ]
    bad(run(other), "checkout.allowed_merchants:merchant_not_allowed")


def test_allowed_merchants_matches_on_id_not_on_display_name() -> None:
    renamed = [
        line_items_constraint(),
        {
            "type": "checkout.allowed_merchants",
            "allowed": [{"id": "m-demo", "name": "Some Other Name"}],
        },
    ]
    ok(run(renamed))
    same_name = [
        line_items_constraint(),
        {
            "type": "checkout.allowed_merchants",
            "allowed": [{"id": "m-evil", "name": MERCHANT["name"]}],
        },
    ]
    bad(run(same_name), "checkout.allowed_merchants:merchant_not_allowed")


@pytest.mark.parametrize(
    ("allowed", "reason"),
    [
        ([], "checkout.allowed_merchants:none_revealed"),
        ("x", "checkout.allowed_merchants:allowed_malformed"),
        ([{"name": "no id"}], "checkout.allowed_merchants:merchant_malformed"),
        ([{"id": "m-demo"}], "checkout.allowed_merchants:merchant_malformed"),
        ([{"id": 1, "name": "n"}], "checkout.allowed_merchants:merchant_malformed"),
        (["m-demo"], "checkout.allowed_merchants:merchant_malformed"),
    ],
)
def test_allowed_merchants_missing_or_malformed(allowed: Any, reason: str) -> None:
    constraints = [
        line_items_constraint(),
        {"type": "checkout.allowed_merchants", "allowed": allowed},
    ]
    bad(run(constraints), reason)


def test_allowed_merchants_absent_member_and_extra_member() -> None:
    bad(
        run([line_items_constraint(), {"type": "checkout.allowed_merchants"}]),
        "checkout.allowed_merchants:allowed_malformed",
    )
    bad(
        run(
            [
                line_items_constraint(),
                {
                    "type": "checkout.allowed_merchants",
                    "allowed": [dict(MERCHANT)],
                    "regions": ["US"],
                },
            ]
        ),
        "unresolved_constraint",
        unresolved=True,
    )


# ----- the rules common to all mandates -----


def test_an_unknown_constraint_type_fails_closed() -> None:
    bad(
        run([*checkout_constraints(), {"type": "acme.loyalty.1", "tier": "gold"}]),
        "unresolved_constraint",
        unresolved=True,
    )


def test_an_unknown_type_is_never_skipped_whatever_its_position() -> None:
    bad(run([{"type": "x.unknown"}, *checkout_constraints()]), "unresolved_constraint", True)
    bad(run([*checkout_constraints(), {"type": "x.unknown"}]), "unresolved_constraint", True)


@pytest.mark.parametrize("kind", ["payment.amount_range", "payment.budget", "payment.reference"])
def test_a_payment_constraint_in_a_checkout_mandate_is_unresolved(kind: str) -> None:
    bad(run([*checkout_constraints(), {"type": kind}]), "unresolved_constraint", True)


def test_constraints_missing_or_malformed() -> None:
    bad(run(open_edit=lambda c: c.pop("constraints")), "constraints:missing_or_malformed")
    bad(run([]), "checkout.line_items:required_constraint_missing")
    bad(run(open_edit=lambda c: c.update(constraints="x")), "constraints:missing_or_malformed")
    bad(run(["x"]), "constraints:constraint_malformed")
    bad(run([{"kind": "x"}]), "constraints:constraint_malformed")
    bad(run([{"type": 5}]), "constraints:constraint_malformed")


def test_line_items_is_required() -> None:
    bad(
        run([{"type": "checkout.allowed_merchants", "allowed": [dict(MERCHANT)]}]),
        "checkout.line_items:required_constraint_missing",
    )


def test_two_constraints_of_one_type_are_refused() -> None:
    bad(
        run([line_items_constraint(), line_items_constraint()]),
        "checkout.line_items:duplicate_constraint",
    )


# ----- open claims unchanged, closed values, chain shape -----


def test_a_claim_of_the_open_mandate_must_be_unchanged_in_the_closed_one() -> None:
    preset = lambda c: c.update(order_note="gift")
    bad(run(open_edit=preset), "mandate:open_claims_changed")  # dropped
    ok(run(open_edit=preset, closed_edit=lambda c: c.update(order_note="gift")))
    bad(
        run(open_edit=preset, closed_edit=lambda c: c.update(order_note="other")),
        "mandate:open_claims_changed",
    )


def test_claims_unchanged_keeps_json_types_apart() -> None:
    bad(
        run(open_edit=lambda c: c.update(flag=1), closed_edit=lambda c: c.update(flag=True)),
        "mandate:open_claims_changed",
    )
    bad(
        run(
            open_edit=lambda c: c.update(n={"a": [1, 2]}),
            closed_edit=lambda c: c.update(n={"a": [1, 3]}),
        ),
        "mandate:open_claims_changed",
    )


def test_delegation_claims_may_differ_between_open_and_closed() -> None:
    ok(run(open_edit=lambda c: c.update(exp=NOW + 100, nbf=NOW - 5)))


def test_the_closed_mandate_must_not_carry_constraints() -> None:
    bad(run(closed_edit=lambda c: c.update(constraints=[])), "mandate:closed_mandate_unexpected")


def test_a_shorter_or_longer_chain_than_expected_is_refused() -> None:
    from countersign.mandates import VCT_CHECKOUT_OPEN, verify_chain
    from tests.mandate_issuer import Keys, issue

    keys = Keys()
    issued = issue(
        "checkout",
        keys=keys,
        hops=3,
        edit_open_content=lambda c: c.update(constraints=checkout_constraints()),
    )
    chain = verify_chain(
        issued.token,
        issuer_key=keys.issuer,
        expected_vcts=[VCT_CHECKOUT_OPEN, VCT_CHECKOUT_OPEN, "mandate.checkout.1"],
        audience="merchant",
        clock=lambda: NOW,
    )
    bad(
        EVALUATOR.evaluate(chain=chain, checkout=checkout_for(), now=NOW),
        "mandate:chain_shape_unexpected",
    )


def test_human_present_mandate_has_no_open_constraints() -> None:
    from countersign.mandates import verify_chain
    from tests.mandate_issuer import Keys, issue_human_present

    keys = Keys()
    token = issue_human_present(keys, checkout_jwt_value="a.b.c")
    chain = verify_chain(
        token,
        issuer_key=keys.issuer,
        expected_vcts=["mandate.checkout.1"],
        audience="merchant",
        clock=lambda: NOW,
    )
    result = EVALUATOR.evaluate(chain=chain, checkout=checkout_for(), now=NOW)
    ok(result)
    assert result.reason == "no_open_mandate"


def test_a_merchant_id_is_required() -> None:
    with pytest.raises(ValueError):
        CheckoutConstraintEvaluator("")


def test_the_evaluator_does_not_trust_the_chain_it_is_given_to_have_the_right_vct() -> None:
    """Defense in depth: a chain whose closed or open link has another `vct` is refused here too."""
    import dataclasses

    from countersign.mandates import VerifiedChain

    chain, _ = verified_checkout_chain()
    wrong_closed = VerifiedChain(
        (chain.links[0], dataclasses.replace(chain.final, vct="mandate.payment.1"))
    )
    bad(
        EVALUATOR.evaluate(chain=wrong_closed, checkout=checkout_for(), now=NOW),
        "mandate:closed_mandate_unexpected",
    )
    wrong_open = VerifiedChain(
        (dataclasses.replace(chain.links[0], vct="mandate.payment.open.1"), chain.final)
    )
    bad(
        EVALUATOR.evaluate(chain=wrong_open, checkout=checkout_for(), now=NOW),
        "mandate:chain_shape_unexpected",
    )

"""The two model calls of the agent and the deterministic code that checks their output."""

from __future__ import annotations

from typing import Any

import pytest

from agents.shopper.plan import MAX_CEILING_MINOR, PlanError, candidates, choose_item, plan_wish
from tests.shopper_support import fake_gateway

CATEGORIES = [{"id": "headphones", "title": "Headphones"}, {"id": "cables", "title": "Cables"}]
ITEMS = [
    {"id": "a", "title": "A", "brand": "B", "category": "headphones", "price_minor": 4000,
     "description": "d"},
    {"id": "b", "title": "B", "brand": "B", "category": "headphones", "price_minor": 9000,
     "description": "d"},
    {"id": "c", "title": "C", "brand": "B", "category": "cables", "price_minor": 500,
     "description": "d"},
]  # fmt: skip


def wish(**kw: Any) -> Any:
    data = {
        "categories": ["headphones"],
        "quantity": 1,
        "ceiling_minor": 8000,
        "valid_for_hours": 24,
    }
    data.update(kw)
    return plan_wish(fake_gateway(data, "a"), "headphones", CATEGORIES)


def test_a_wish_is_clamped_to_the_bounds() -> None:
    w = wish(quantity=500, ceiling_minor=10**9, valid_for_hours=10**6)
    assert (w.quantity, w.ceiling_minor, w.valid_for_hours) == (9, MAX_CEILING_MINOR, 24 * 14)


def test_unknown_categories_are_dropped_and_none_left_is_refused() -> None:
    assert wish(categories=["nonsense", "cables", "cables"]).categories == ("cables",)
    with pytest.raises(PlanError) as caught:
        wish(categories=["nonsense"])
    assert caught.value.code == "no_known_category"


@pytest.mark.parametrize("member", ["quantity", "ceiling_minor", "valid_for_hours"])
def test_money_and_counts_are_integers_only(member: str) -> None:
    from countersign.llm import LlmSchemaError

    for bad in (80.5, "80", True):
        with pytest.raises((LlmSchemaError, PlanError)):
            wish(**{member: bad})


def test_non_positive_values_are_refused() -> None:
    for member in ("quantity", "ceiling_minor"):
        with pytest.raises(PlanError):
            wish(**{member: 0})


def test_candidates_fit_under_the_ceiling_for_the_quantity() -> None:
    w = wish(quantity=2, ceiling_minor=8000)
    assert [i["id"] for i in candidates(w, ITEMS)] == ["a"]
    assert candidates(wish(categories=["cables"]), ITEMS) == [ITEMS[2]]


def test_a_choice_must_be_one_of_the_results() -> None:
    w = wish()
    found = candidates(w, ITEMS)
    assert choose_item(fake_gateway({}, "a"), "g", w, found)["id"] == "a"
    with pytest.raises(PlanError):
        choose_item(fake_gateway({}, "b"), "g", w, found)  # real item, but over the ceiling
    with pytest.raises(PlanError):
        choose_item(fake_gateway({}, "a"), "g", w, [])


def test_a_goal_that_is_empty_or_huge_is_refused() -> None:
    for goal in ("", "   ", "x" * 501):
        with pytest.raises(PlanError):
            plan_wish(fake_gateway({}, "a"), goal, CATEGORIES)

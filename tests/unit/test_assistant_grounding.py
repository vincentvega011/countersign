"""The grounding check (Decision 128): pure, numeric, formatting tolerant, blind to identifiers."""

from __future__ import annotations

from countersign.assistant import Line, ToolResult, ground, line_is_grounded
from countersign.assistant.grounding import allowed_numbers, numerals
from countersign.assistant.model import UNVERIFIED


def result(**data: object) -> ToolResult:
    return ToolResult("t", {}, dict(data))


def test_a_fabricated_number_is_replaced_by_the_fixed_sentence() -> None:
    lines, replaced = ground(
        [Line("There are 5 orders."), Line("There were 0 attacks.")], [result(count=5)]
    )
    assert [line.text for line in lines] == ["There are 5 orders.", UNVERIFIED]
    assert replaced == 1


def test_formatting_does_not_matter() -> None:
    data = [result(total=1234, amount_minor=5400, ratio=0.5)]
    allowed = allowed_numbers(data)
    for text in ("1,234 orders", "$54.00", "54.0 dollars", "$54", "0.50", "5400 minor units"):
        assert line_is_grounded(text, allowed), text
    for text in ("1,235 orders", "$54.01", "0.51"):
        assert not line_is_grounded(text, allowed), text


def test_numbers_inside_identifiers_are_not_claims() -> None:
    allowed = allowed_numbers([result(count=3)])
    for text in (
        "Order chk_Order003x is completed.", "customer cus_seed03", "gate G-AMOUNT failed",
        "capture SIMCAPTURE3", "mandate om_sim_used", "reason http_404", "AP2 mandates", "evt-12 stopped",
        "key AgentKey3a9 found", "a 3x scale and 12abc",
    ):  # fmt: skip
        assert numerals(text) == [], text
        assert line_is_grounded(text, allowed), text
    # A real numeral next to words is still a claim, with or without a sign.
    assert [int(n) for n in numerals("Order chk_a1 has 7 items and -5 left")] == [7, 5]
    assert not line_is_grounded("Order chk_a1 has 7 items", allowed)


def test_a_number_in_another_results_data_does_not_ground_a_line_that_does_not_cite_it() -> None:
    mine, other = result(count=2), result(count=99)
    assert line_is_grounded("2 orders", allowed_numbers([mine]))
    assert not line_is_grounded("99 orders", allowed_numbers([mine]))
    assert line_is_grounded("99 orders", allowed_numbers([mine, other]))


def test_strings_in_the_data_contribute_their_numerals() -> None:
    allowed = allowed_numbers([result(created_at="2026-11-07T10:00:00Z", items="2 × x")])
    assert line_is_grounded("Created 2026-11-07T10:00:00Z with 2 items", allowed)


def test_booleans_and_none_are_not_numbers() -> None:
    assert allowed_numbers([result(flag=True, nothing=None)]) == set()
    assert not line_is_grounded("1 order", allowed_numbers([result(flag=True)]))


def test_numbers_nested_in_lists_of_rows_ground_a_line() -> None:
    allowed = allowed_numbers([result(groups=[{"key": "a", "count": 7}, {"key": "b", "count": 3}])])
    assert line_is_grounded("a: 7 orders", allowed) and line_is_grounded("b: 3 orders", allowed)
    assert not line_is_grounded("c: 5 orders", allowed)

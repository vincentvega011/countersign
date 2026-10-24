"""Request parsing: strict JSON, shape rules, and what is read and what is ignored."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from countersign.protocols.ucp.messages import ProtocolError
from countersign.protocols.ucp.requests import (
    check_content_type,
    ignored_members,
    parse_checkout_request,
    parse_json_object,
)


def _create(**line: object) -> dict[str, object]:
    base: dict[str, object] = {"item": {"id": "sku-1"}, "quantity": 2}
    base.update(line)
    return {"line_items": [base]}


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b'{"a": 1, "a": 2}', "json_duplicate_key"),
        (b'{"a": NaN}', "json_non_finite"),
        (b'{"a": Infinity}', "json_non_finite"),
        (b"\xff\xfe{}", "json_encoding"),
        (b'{"a": ', "json_syntax"),
        (b"", "json_syntax"),
        (b"   ", "json_syntax"),
    ],
)
def test_strict_json_failures_are_ucp_shaped(raw: bytes, code: str) -> None:
    with pytest.raises(ProtocolError) as exc:
        parse_json_object(raw)
    assert exc.value.status == 400
    body = exc.value.body()
    assert set(body) == {"code", "content"} and body["code"] == code and body["content"]


@pytest.mark.parametrize("raw", [b"[]", b"1", b'"x"', b"null", b"true"])
def test_body_must_be_an_object(raw: bytes) -> None:
    with pytest.raises(ProtocolError) as exc:
        parse_json_object(raw)
    assert exc.value.code == "invalid_request"


def test_empty_body_only_when_allowed() -> None:
    assert parse_json_object(b"", allow_empty=True) == {}
    assert parse_json_object(b"{}", allow_empty=True) == {}


def test_oversized_body_refused() -> None:
    with pytest.raises(ProtocolError) as exc:
        parse_json_object(b'{"a": "' + b"x" * 1_100_000 + b'"}')
    assert exc.value.code == "json_too_large"


@pytest.mark.parametrize(
    "value",
    ["application/json", "Application/JSON", "application/json; charset=utf-8"],
)
def test_content_type_accepted(value: str) -> None:
    check_content_type(value)


@pytest.mark.parametrize("value", [None, "", "text/plain", "application/jsonx", "application/xml"])
def test_content_type_refused(value: str | None) -> None:
    with pytest.raises(ProtocolError) as exc:
        check_content_type(value)
    assert exc.value.status == 400


def test_reads_item_id_and_quantity_only() -> None:
    body = _create(item={"id": "sku-1", "price": 1, "title": "x"}, totals=[{"type": "total"}])
    body["currency"] = "EUR"
    body["status"] = "completed"
    req = parse_checkout_request(body, update=False)
    (line,) = req.lines
    assert (line.item_id, line.quantity, line.line_id, line.unit) == ("sku-1", 2, None, None)
    assert not hasattr(line, "price") and not hasattr(req, "currency")


def test_line_id_is_ignored_on_create_and_read_on_update() -> None:
    assert parse_checkout_request(_create(id="li_9"), update=False).lines[0].line_id is None
    assert parse_checkout_request(_create(id="li_9"), update=True).lines[0].line_id == "li_9"


def test_unit_assertion_is_read() -> None:
    body = _create(item={"id": "s", "quantity_unit": {"unit": "KGM", "scale": 3}})
    assert parse_checkout_request(body, update=False).lines[0].unit == ("KGM", 3)
    body = _create(item={"id": "s", "quantity_unit": {"unit": "C62"}})
    assert parse_checkout_request(body, update=False).lines[0].unit == ("C62", 0)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"line_items": None},
        {"line_items": 5},
        {"line_items": {"a": 1}},
        {"line_items": {}},
        {"line_items": []},
        {"line_items": ["x"]},
        {"line_items": [{}]},
        {"line_items": [{"item": "x", "quantity": 1}]},
        {"line_items": [{"item": {}, "quantity": 1}]},
        {"line_items": [{"item": {"id": ""}, "quantity": 1}]},
        {"line_items": [{"item": {"id": 5}, "quantity": 1}]},
        {"line_items": [{"item": {"id": "x" * 128}, "quantity": 1}]},
        {"line_items": [{"item": {"id": "a"}}]},
        {"line_items": [{"item": {"id": "a"}, "quantity": 0}]},
        {"line_items": [{"item": {"id": "a"}, "quantity": -1}]},
        {"line_items": [{"item": {"id": "a"}, "quantity": 1.5}]},
        {"line_items": [{"item": {"id": "a"}, "quantity": 2.0}]},
        {"line_items": [{"item": {"id": "a"}, "quantity": "2"}]},
        {"line_items": [{"item": {"id": "a"}, "quantity": True}]},
        {"line_items": [{"item": {"id": "a"}, "quantity": 9_007_199_254_740_992}]},
        {"line_items": [{"item": {"id": "a", "quantity_unit": "C62"}, "quantity": 1}]},
        {"line_items": [{"item": {"id": "a", "quantity_unit": {}}, "quantity": 1}]},
        {
            "line_items": [
                {"item": {"id": "a", "quantity_unit": {"unit": "C62", "scale": -1}}, "quantity": 1}
            ]
        },
        {
            "line_items": [
                {"item": {"id": "a", "quantity_unit": {"unit": "C62", "scale": 1.5}}, "quantity": 1}
            ]
        },
    ],
)
def test_shape_errors_are_400_with_a_path(body: dict[str, object]) -> None:
    with pytest.raises(ProtocolError) as exc:
        parse_checkout_request(body, update=False)
    assert exc.value.status == 400 and exc.value.code == "invalid_request"
    assert exc.value.content.startswith("$")


@pytest.mark.parametrize("bad", [5, "", "x" * 128, None, ["li_1"]])
def test_bad_line_id_on_update_refused(bad: object) -> None:
    with pytest.raises(ProtocolError):
        parse_checkout_request(_create(id=bad), update=True)


def test_quantity_above_the_business_limit_still_parses() -> None:
    # The limit is a business outcome decided by the service, not a shape error.
    assert parse_checkout_request(_create(quantity=500), update=False).lines[0].quantity == 500


# ---- members that a request must not control ----

RESPONSE = {
    "id": "chk_a",
    "status": "ready_for_complete",
    "currency": "USD",
    "totals": [{"type": "total", "amount": 100}],
    "links": [],
    "line_items": [
        {
            "id": "li_1",
            "item": {"id": "s", "title": "T", "price": 100},
            "quantity": 1,
            "totals": [{"type": "total", "amount": 100}],
        }
    ],
}


def test_echoed_authoritative_values_are_not_reported() -> None:
    assert ignored_members(dict(RESPONSE), RESPONSE) == []


def test_changed_values_are_reported_with_paths() -> None:
    sent = {
        "id": "chk_other",
        "status": "completed",
        "currency": "EUR",
        "totals": [{"type": "total", "amount": 1}],
        "ucp": {"version": "x"},
        "links": [{"type": "x", "url": "u"}],
        "expires_at": "2099-01-01T00:00:00Z",
        "order": {"id": "o"},
        "line_items": [
            {
                "item": {"id": "s", "title": "Cheap", "price": 1},
                "quantity": 1,
                "totals": [{"type": "total", "amount": 1}],
            }
        ],
    }
    paths = {p for p, _ in ignored_members(sent, RESPONSE)}
    assert paths == {
        "$.id",
        "$.status",
        "$.currency",
        "$.totals",
        "$.ucp",
        "$.links",
        "$.expires_at",
        "$.order",
        "$.line_items[0].totals",
        "$.line_items[0].item.title",
        "$.line_items[0].item.price",
    }


def test_members_not_sent_are_not_reported() -> None:
    assert ignored_members({"line_items": [{"item": {"id": "s"}, "quantity": 1}]}, RESPONSE) == []


def test_item_id_of_exactly_the_maximum_length_is_accepted() -> None:
    body = {"line_items": [{"item": {"id": "x" * 127}, "quantity": 1}]}
    assert parse_checkout_request(body, update=False).lines[0].item_id == "x" * 127


def test_line_items_that_is_not_an_array_says_so() -> None:
    for value in (5, {"a": 1}, "abc"):
        with pytest.raises(ProtocolError) as exc:
            parse_checkout_request({"line_items": value}, update=False)
        assert "must be an array" in exc.value.content


def test_read_body_stops_at_the_limit() -> None:
    import asyncio

    from countersign.protocols.ucp.requests import read_body

    async def chunks(sizes: list[int]) -> AsyncIterator[bytes]:
        for n in sizes:
            yield b"x" * n

    assert asyncio.run(read_body(chunks([5, 5]), max_bytes=10)) == b"x" * 10
    with pytest.raises(ProtocolError) as exc:
        asyncio.run(read_body(chunks([5, 6]), max_bytes=10))
    assert exc.value.code == "json_too_large"
    consumed: list[int] = []

    async def counting() -> AsyncIterator[bytes]:
        for n in (6, 6, 6, 6):
            consumed.append(n)
            yield b"x" * n

    with pytest.raises(ProtocolError):
        asyncio.run(read_body(counting(), max_bytes=10))
    assert len(consumed) == 2  # it did not keep reading after the limit

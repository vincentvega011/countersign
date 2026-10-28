"""The response builder: built from the canonical model and a status, nothing else."""

from __future__ import annotations

from countersign.canonical.models import Checkout, Item
from countersign.canonical.money import Money
from countersign.protocols.ucp import messages as m
from countersign.protocols.ucp.checkout_state import Status
from countersign.protocols.ucp.profile import payment_handlers
from countersign.protocols.ucp.responses import checkout_response, rfc3339


def _checkout() -> Checkout:
    item = Item(id="sku-1", title="Thing", price=Money("USD", 250))
    return Checkout.from_lines("chk_abcdefghijklmnopqrstuv", "USD", [("li_1", item, 2)])


def test_rfc3339() -> None:
    assert rfc3339(0) == "1970-01-01T00:00:00Z"
    assert rfc3339(1_700_000_000_123_456) == "2023-11-14T22:13:20Z"


def test_shape_and_required_members() -> None:
    body = checkout_response(_checkout(), Status.READY_FOR_COMPLETE, 1_700_000_000_000_000)
    assert {"ucp", "id", "line_items", "status", "currency", "totals", "links"} <= set(body)
    assert body["status"] == "ready_for_complete" and body["links"] == []
    assert (
        body["ucp"]["status"] == "success" and body["ucp"]["payment_handlers"] == payment_handlers()
    )
    assert body["totals"] == [
        {"type": "subtotal", "amount": 500},
        {"type": "total", "amount": 500},
    ]
    assert "messages" not in body


def test_amounts_are_integers_and_come_from_the_model() -> None:
    body = checkout_response(_checkout(), Status.CANCELED, 5)
    line = body["line_items"][0]
    assert line["item"]["price"] == 250 and type(line["item"]["price"]) is int
    assert line["quantity"] == 2 and line["totals"][0]["amount"] == 500


def test_messages_are_attached_when_present() -> None:
    msg = m.error_message("code_x", "text", "recoverable", "$.a")
    body = checkout_response(_checkout(), Status.READY_FOR_COMPLETE, 5, [msg])
    assert body["messages"] == [msg]
    assert msg == {
        "type": "error",
        "code": "code_x",
        "content": "text",
        "severity": "recoverable",
        "path": "$.a",
    }


def test_status_is_what_was_passed() -> None:
    for status in Status:
        assert checkout_response(_checkout(), status, 5)["status"] == status.value


def test_error_response_needs_a_message() -> None:
    import pytest

    with pytest.raises(ValueError):
        m.error_response([])
    body = m.error_response([m.warning_message("w", "t")])
    assert body["ucp"]["status"] == "error"


def test_the_checkout_capability_is_advertised_in_the_response() -> None:
    body = checkout_response(_checkout(), Status.READY_FOR_COMPLETE, 5)
    assert body["ucp"]["capabilities"] == {"dev.ucp.shopping.checkout": [{"version": "2026-08-25"}]}
    assert body["ucp"]["version"] == "2026-08-25"

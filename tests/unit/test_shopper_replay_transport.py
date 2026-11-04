"""The replay transport of the shopping agent test maps only the per-run values and nothing else."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from countersign.paypal.cassette import CassetteError
from tests.shopper_e2e import SubstitutingTransport

REC_CHECKOUT, REC_CUSTOM, REC_BASE = "chk_REC", "cs1.RECORDED", "http://127.0.0.1:1111"
LIVE_CHECKOUT, LIVE_CUSTOM, LIVE_BASE = "chk_LIVE", "cs1.LIVE", "http://127.0.0.1:2222"


def order(checkout: str, custom: str, base: str, value: str = "45.00") -> dict[str, Any]:
    return {
        "intent": "AUTHORIZE",
        "purchase_units": [
            {
                "invoice_id": checkout, "custom_id": custom, "amount": {"value": value},
                "experience_context": {"return_url": base + "/return"},
            }
        ],
    }  # fmt: skip


def document() -> dict[str, Any]:
    return {
        "version": 1,
        "meta": {"base_url": REC_BASE, "recorded_at": "2026-11-04T10:00:00Z"},
        "interactions": [
            {
                "request": {
                    "method": "POST", "path": "/v2/checkout/orders",
                    "request_id": "cs1.create_order.RECDIGEST",
                    "body": order(REC_CHECKOUT, REC_CUSTOM, REC_BASE),
                },
                "response": {
                    "status": 201, "headers": {"content-type": "application/json"},
                    "body": {"id": "ORDER1", "purchase_units": [{"invoice_id": REC_CHECKOUT}]},
                },
            },
            {
                "request": {
                    "method": "POST", "path": "/v2/checkout/orders/ORDER1/authorize",
                    "request_id": "cs1.authorize.RECDIGEST2", "body": None,
                },
                "response": {"status": 201, "headers": {}, "body": {"id": "A1"}},
            },
        ],
    }  # fmt: skip


def send(t: SubstitutingTransport, path: str, rid: str, body: Any) -> httpx.Response:
    request = httpx.Request(
        "POST", "https://api-m.sandbox.paypal.com" + path,
        headers={"paypal-request-id": rid, "content-type": "application/json"},
        json=body,
    )  # fmt: skip
    return t.handle_request(request)


def test_the_four_per_run_values_are_mapped_both_ways() -> None:
    t = SubstitutingTransport(document(), live_base=LIVE_BASE)
    answer = send(t, "/v2/checkout/orders", "cs1.create_order.LIVEDIGEST",
                  order(LIVE_CHECKOUT, LIVE_CUSTOM, LIVE_BASE))  # fmt: skip
    assert answer.json()["purchase_units"][0]["invoice_id"] == LIVE_CHECKOUT  # back to live
    assert send(t, "/v2/checkout/orders/ORDER1/authorize", "cs1.authorize.LIVEDIGEST2", None)
    t.assert_exhausted()


def test_a_changed_amount_or_a_different_operation_still_fails() -> None:
    t = SubstitutingTransport(document(), live_base=LIVE_BASE)
    with pytest.raises(CassetteError):
        send(t, "/v2/checkout/orders", "cs1.create_order.X",
             order(LIVE_CHECKOUT, LIVE_CUSTOM, LIVE_BASE, "46.00"))  # fmt: skip
    t = SubstitutingTransport(document(), live_base=LIVE_BASE)
    with pytest.raises(AssertionError):
        send(
            t, "/v2/checkout/orders", "cs1.capture.X", order(LIVE_CHECKOUT, LIVE_CUSTOM, LIVE_BASE)
        )

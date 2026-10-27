"""Replay of the recorded sandbox authorize-and-capture cycle.

The cassette is recorded once with `scripts/record_paypal_cassette.py` (it needs one live approval
and is not available until then). Until the file exists this test is skipped with that instruction;
the same machinery is exercised against a fake PayPal in tests/unit/test_paypal_cassette.py.
Once recorded, the replay must make exactly the recorded calls, in order, with the recorded
Request-Ids and bodies, and must find the recorded states.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest

from countersign.catalog.catalog import load_catalog
from countersign.paypal.cassette import CassetteTransport, load_cassette
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.request_id import Operation, create_order_request_id, derive_request_id
from tests.ungated_capture_cycle import cycle_checkout, run_cycle

CASSETTE = Path(__file__).resolve().parents[1] / "cassettes" / "paypal_authorize_capture.json"


@pytest.fixture(scope="module")
def recorded() -> dict:  # type: ignore[type-arg]
    if not CASSETTE.exists():
        pytest.skip(
            "the PayPal cassette is not recorded yet: run "
            "`PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_paypal_cassette.py`"
        )
    return load_cassette(CASSETTE)


def replay_client(document: dict, transport: httpx.BaseTransport) -> PayPalClient:  # type: ignore[type-arg]
    recorded_at = datetime.fromisoformat(document["meta"]["recorded_at"])
    config = PayPalConfig(client_id="replay-client-id", client_secret="replay-client-secret")
    return PayPalClient(
        config,
        transport=transport,
        monotonic=lambda: 0.0,
        now=lambda: recorded_at + timedelta(minutes=5),
    )


def test_the_recorded_cycle_replays_exactly(recorded: dict) -> None:  # type: ignore[type-arg]
    checkout_id = recorded["meta"]["checkout_id"]
    transport = CassetteTransport(recorded)
    with replay_client(recorded, transport) as client:
        result = run_cycle(client, checkout_id, approve=lambda _url: None)
    transport.assert_exhausted()

    total = next(t.amount for t in result.checkout.totals if t.type == "total")
    assert result.approved.status == "APPROVED"
    assert result.authorized.status == "COMPLETED"
    assert result.authorization.status == "CREATED" and result.authorization.amount == total
    assert result.authorization.invoice_id == checkout_id
    assert result.authorization.custom_id == result.custom_id
    assert result.capture.status == "COMPLETED" and result.capture.final_capture is True
    assert result.capture.amount == total
    assert result.capture.invoice_id == checkout_id and result.capture.custom_id == result.custom_id
    assert result.captured_authorization.status == "CAPTURED"
    assert [c.id for c in result.final_order.captures] == [result.capture.id]


def test_the_recorded_request_ids_are_the_derived_ones(recorded: dict) -> None:  # type: ignore[type-arg]
    checkout_id = recorded["meta"]["checkout_id"]
    ids = [
        i["request"]["request_id"]
        for i in recorded["interactions"]
        if i["request"]["method"] == "POST" and i["request"]["request_id"]
    ]
    assert ids == [
        create_order_request_id(
            checkout_id, cycle_checkout(checkout_id, load_catalog())[0].terms_hash()
        ),
        derive_request_id(checkout_id, Operation.AUTHORIZE),
        derive_request_id(checkout_id, Operation.CAPTURE),
    ]


def test_the_recorded_capture_request_is_the_full_amount_with_final_capture(recorded: dict) -> None:  # type: ignore[type-arg]
    capture = next(i for i in recorded["interactions"] if i["request"]["path"].endswith("/capture"))
    authorization = next(
        i
        for i in recorded["interactions"]
        if i["request"]["path"].startswith("/v2/payments/authorizations/")
    )
    body = capture["request"]["body"]
    assert body["final_capture"] is True
    assert body["amount"] == authorization["response"]["body"]["amount"]
    assert set(body) == {"amount", "final_capture"}


def test_the_recorded_file_holds_no_credentials_tokens_or_account_data(recorded: dict) -> None:  # type: ignore[type-arg]
    text = CASSETTE.read_text()
    assert "Bearer " not in text and "@" not in text
    token = recorded["interactions"][0]["response"]["body"]
    assert token["access_token"] == "SCRUBBED_ACCESS_TOKEN"
    for interaction in recorded["interactions"]:
        assert "authorization" not in interaction["request"]
        body = interaction["response"]["body"] or {}
        assert body.get("payer", {}) == {} and body.get("payment_source", {}) == {}

"""Replay of the recorded create-then-get flow: canonical checkout to sandbox order and back.

The cassette is recorded once with `scripts/record_paypal_order_terms.py` (sandbox credentials only,
no payer approval). Until the file exists these tests are skipped with that instruction; the
translation itself is tested without PayPal in tests/unit/test_paypal_translate.py. Once recorded,
the reverse-translated terms of what PayPal returned must equal the checkout that was sent, exactly.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from countersign.paypal.cassette import CassetteTransport, load_cassette
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.terms_flow import KINDS, TermsResult, run_terms_flow
from countersign.paypal.translate import expected_terms

CASSETTE = Path(__file__).resolve().parents[1] / "cassettes" / "paypal_order_terms.json"


@pytest.fixture(scope="module")
def recorded() -> dict[str, Any]:
    if not CASSETTE.exists():
        pytest.skip(
            "the order terms cassette is not recorded yet: run "
            "`PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_paypal_order_terms.py`"
        )
    return load_cassette(CASSETTE)


def replay(document: dict[str, Any]) -> list[TermsResult]:
    recorded_at = datetime.fromisoformat(document["meta"]["recorded_at"])
    config = PayPalConfig(client_id="replay-client-id", client_secret="replay-client-secret")
    transport = CassetteTransport(document)
    client = PayPalClient(
        config,
        transport=transport,
        monotonic=lambda: 0.0,
        now=lambda: recorded_at + timedelta(minutes=5),
    )
    with client:
        results = [
            run_terms_flow(client, kind, document["meta"]["checkout_ids"][kind]) for kind in KINDS
        ]
    transport.assert_exhausted()
    return results


def test_the_recorded_orders_reverse_to_the_checkouts_that_were_sent(
    recorded: dict[str, Any],
) -> None:
    for result in replay(recorded):
        assert result.terms.checkout.terms_bytes() == result.checkout.terms_bytes(), result.kind
        want = expected_terms(
            result.checkout,
            payee_merchant_id=result.terms.payee_merchant_id,
            custom_id=result.custom_id,
        )
        assert result.terms.terms_hash() == want.terms_hash(), result.kind
        assert result.terms.invoice_id == result.checkout.id


def test_the_recorded_requests_were_sent_as_the_forward_translation_builds_them(
    recorded: dict[str, Any],
) -> None:
    results = replay(recorded)
    sent = [
        i["request"]["body"]["purchase_units"][0]
        for i in recorded["interactions"]
        if i["request"]["method"] == "POST" and i["request"]["path"] == "/v2/checkout/orders"
    ]
    assert [u["invoice_id"] for u in sent] == [r.checkout.id for r in results]


def test_the_recorded_file_holds_no_credentials_or_account_data(recorded: dict[str, Any]) -> None:
    text = CASSETTE.read_text()
    assert "Bearer " not in text and "@" not in text
    assert (
        recorded["interactions"][0]["response"]["body"]["access_token"] == "SCRUBBED_ACCESS_TOKEN"
    )


# ---- real data that is already recorded: the authorize and capture cassette

CYCLE_CASSETTE = Path(__file__).resolve().parents[1] / "cassettes" / "paypal_authorize_capture.json"


def test_orders_recorded_in_the_authorize_capture_cassette_reverse_to_the_checkout() -> None:
    """Every GET of the order in that recording, from created to captured, has the same terms."""
    from countersign.paypal.translate import paypal_order_to_canonical_terms
    from tests.ungated_capture_cycle import run_cycle

    document = load_cassette(CYCLE_CASSETTE)
    recorded_at = datetime.fromisoformat(document["meta"]["recorded_at"])
    transport = CassetteTransport(document)
    config = PayPalConfig(client_id="replay-client-id", client_secret="replay-client-secret")
    client = PayPalClient(
        config,
        transport=transport,
        monotonic=lambda: 0.0,
        now=lambda: recorded_at + timedelta(minutes=5),
    )
    with client:
        result = run_cycle(client, document["meta"]["checkout_id"], approve=lambda _url: None)
    line_ids = [line.id for line in result.checkout.line_items]
    seen = []
    for order in (result.approved, result.authorized, result.final_order):
        terms = paypal_order_to_canonical_terms(order, line_ids=line_ids)
        assert terms.checkout.terms_bytes() == result.checkout.terms_bytes()
        assert terms.custom_id == result.custom_id
        seen.append(terms.terms_hash())
    assert len(set(seen)) == 1

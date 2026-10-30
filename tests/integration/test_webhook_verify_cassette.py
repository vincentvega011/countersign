"""Replay of PayPal's real answer to `verify-webhook-signature` for a fabricated notification.

Recorded by `scripts/record_webhook_failure_cassette.py` once a webhook id is configured; skipped
until then. It covers the failure path only: a success answer needs a real delivery from PayPal to a
public URL and is a pending item for the Render deploy (docs/ENV.md).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from countersign.paypal.cassette import CassetteTransport, load_cassette
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.errors import PayPalError
from scripts.record_webhook_failure_cassette import FABRICATED

CASSETTE = Path(__file__).resolve().parents[1] / "cassettes" / "webhook_verify_failure.json"


def test_a_fabricated_event_is_never_taken_for_genuine() -> None:
    if not CASSETTE.exists():
        pytest.skip(
            "not recorded yet (needs PAYPAL_WEBHOOK_ID): "
            "`PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_webhook_failure_cassette.py`"
        )
    document = load_cassette(CASSETTE)
    transport = CassetteTransport(document)
    client = PayPalClient(
        PayPalConfig(client_id="replay-id", client_secret="replay-secret", webhook_id="REPLAY-WH"),
        transport=transport,
        monotonic=lambda: 0.0,
        now=lambda: datetime.now(UTC),
        sleep=lambda _: None,
    )
    try:
        genuine = client.verify_webhook_signature(
            transmission_id="00000000-0000-0000-0000-00000000fab1",
            transmission_time="2026-10-30T10:00:00Z",
            transmission_sig="ZmFicmljYXRlZA==",
            cert_url="https://api.sandbox.paypal.com/v1/notifications/certs/CERT-FABRICATED",
            auth_algo="SHA256withRSA",
            webhook_id="REPLAY-WH",
            raw_event=FABRICATED,
        )
    except PayPalError:
        genuine = False  # PayPal refused to check it: not genuine either way
    assert genuine is False

"""Replay of the Credential Provider flow recorded from the REAL PayPal sandbox.

The cassette and the mandates it was recorded with are produced by
`PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_cp_cassette.py` (it needs one live payer
approval) and are never edited by hand. Until they exist these tests are skipped with that
instruction. The replay runs the same code (tests/cp_flow.py) against the recording and must make
exactly the recorded calls, in order, with the recorded Request-Ids and bodies.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from countersign.canonical import sd_hash
from countersign.cp import CpApprovalRequired, custom_id_for, evidence_reference
from countersign.ledger.store import entries_for_checkout, verify_log
from countersign.mandates import split_chain
from countersign.paypal.cassette import CassetteTransport, load_cassette
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.request_id import authorize_request_id, create_order_request_id
from tests.cp_flow import FlowFixture, authorized, flow_checkout, make_provider, run_flow

DIRECTORY = Path(__file__).resolve().parents[1] / "cassettes"
CASSETTE = DIRECTORY / "cp_authorize.json"
FIXTURE = DIRECTORY / "cp_authorize.mandates.json"
PLACEHOLDER_MERCHANT = "SCRUBBED_MERCHANT_ID"
INSTRUCTION = (
    "the Credential Provider cassette is not recorded yet: run "
    "`PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_cp_cassette.py`"
)


@pytest.fixture(scope="module")
def recorded() -> dict[str, Any]:
    if not CASSETTE.exists() or not FIXTURE.exists():
        pytest.skip(INSTRUCTION)
    return load_cassette(CASSETTE)  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def fixture(recorded: dict[str, Any]) -> FlowFixture:
    return FlowFixture.from_json(FIXTURE.read_text(encoding="utf-8"))


def replay(
    recorded: dict[str, Any], engine: Engine, fixture: FlowFixture
) -> tuple[Any, Any, CassetteTransport]:
    transport = CassetteTransport(recorded)
    recorded_at = datetime.fromisoformat(recorded["meta"]["recorded_at"])
    client = PayPalClient(
        PayPalConfig(client_id="replay-client-id", client_secret="replay-client-secret"),
        transport=transport,
        monotonic=lambda: 0.0,
        now=lambda: recorded_at + timedelta(minutes=5),
        sleep=lambda _: None,
    )
    provider = make_provider(engine, client, fixture, payee_merchant_id=PLACEHOLDER_MERCHANT)
    started, finished = run_flow(provider, fixture, approve=lambda _url: None)
    return started, finished, transport


def test_the_recorded_flow_replays_exactly(
    recorded: dict[str, Any], fixture: FlowFixture, app_engine: Engine, clean_payments: None
) -> None:
    started, finished, transport = replay(recorded, app_engine, fixture)
    transport.assert_exhausted()
    assert isinstance(started, CpApprovalRequired)
    done = authorized(finished)
    checkout = flow_checkout(fixture.checkout_id)
    total = next(t.amount for t in checkout.totals if t.type == "total")
    assert done.amount == total and done.mode == "redirect"

    expected_custom = custom_id_for(
        evidence_reference(
            checkout_hash=_session_hash(fixture),
            checkout_mandate_digest=sd_hash(
                split_chain(fixture.checkout_mandate)[-1].serialization
            ),
            payment_mandate_digest=sd_hash(split_chain(fixture.payment_token)[-1].serialization),
        )
    )
    assert done.custom_id == expected_custom

    posts = [i["request"] for i in recorded["interactions"] if i["request"]["method"] == "POST"]
    paths = [p["path"] for p in posts]
    assert paths.count("/v2/checkout/orders") == 1
    assert not any(p.endswith(("/capture", "/void")) for p in paths)
    create = next(p for p in posts if p["path"] == "/v2/checkout/orders")
    unit = create["body"]["purchase_units"][0]
    assert create["body"]["intent"] == "AUTHORIZE"
    assert unit["invoice_id"] == fixture.checkout_id and unit["custom_id"] == expected_custom
    assert create["request_id"] == create_order_request_id(fixture.checkout_id, create["body"])
    authorize = next(p for p in posts if p["path"].endswith("/authorize"))
    assert authorize["request_id"] == authorize_request_id(fixture.checkout_id, done.order_id)
    assert all(len(p["request_id"]) <= 108 for p in posts if p["request_id"])


def _session_hash(fixture: FlowFixture) -> str:
    from joserfc.jwk import ECKey

    from countersign.canonical import checkout_hash
    from countersign.mandates import verify_chain

    chain = verify_chain(
        fixture.checkout_mandate,
        issuer_key=ECKey.import_key(fixture.platform_jwk),
        expected_vcts=["mandate.checkout.open.1", "mandate.checkout.1"],
        audience="merchant",
        clock=lambda: float(fixture.now),
    )
    return checkout_hash(str(chain.final.content["checkout_jwt"]))


def test_the_replayed_decisions_are_in_a_verified_chain(
    recorded: dict[str, Any], fixture: FlowFixture, app_engine: Engine, clean_payments: None
) -> None:
    replay(recorded, app_engine, fixture)
    with app_engine.connect() as conn:
        kinds = [e.kind for e in entries_for_checkout(conn, fixture.checkout_id)]
        assert verify_log(conn).ok
    assert kinds[0] == "cp.reserved" and kinds[-1] == "cp.authorized"


def test_the_cassette_holds_no_secret_and_only_the_scrub_placeholders(
    recorded: dict[str, Any], fixture: FlowFixture
) -> None:
    text = CASSETTE.read_text(encoding="utf-8") + FIXTURE.read_text(encoding="utf-8")
    # The only token in the file is the placeholder; "Bearer" appears only as the token type label.
    assert text.count("SCRUBBED_ACCESS_TOKEN") >= 1
    for match in re.finditer("Bearer", text):
        assert (
            text[match.start() - len('"token_type": "') : match.end() + 1]
            == '"token_type": "Bearer"'
        )
    assert not re.search(r'"access_token":\s*"(?!SCRUBBED_ACCESS_TOKEN")', text)
    assert "@" not in text and not re.search(r"A21A[A-Za-z0-9_-]{20,}", text)
    assert "authorization" not in {
        h.lower() for i in recorded["interactions"] for h in i["request"].get("headers", {})
    }

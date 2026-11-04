"""The shopping agent end to end: goal to a captured sandbox order, replaying recorded PayPal and model calls.

The customer's phone is a headless browser (a WebCrypto device key is enrolled in a fresh browser context and
the consent is tapped on the real page). The service is the real composition root on a real Postgres. The
agent runs in this process but talks to the service over HTTP only. PayPal is replayed from
tests/cassettes/shopper_e2e.json (recorded by `scripts/record_shopper_cassette.py` against the live
sandbox), the model from eval/cassettes/llm/. Until the recording exists this test FAILS with the command
to run; it is never skipped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from agents.shopper import ShopperError, ShopperResult, run_shopper
from countersign.ledger.store import verify_log
from countersign.llm import LlmConfig, LlmGateway
from countersign.paypal.cassette import load_cassette
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from tests.mode_support import reset
from tests.phone import phone_consent
from tests.shopper_e2e import (
    CASSETTE_NAME,
    GOAL,
    SubstitutingTransport,
    build_service,
    recorded_clock,
    reserve_port,
    serve,
)

CASSETTE = Path(__file__).resolve().parents[1] / "cassettes" / CASSETTE_NAME
PLACEHOLDER_MERCHANT = "SCRUBBED_MERCHANT_ID"
INSTRUCTION = (
    "the shopping agent cassette is not recorded yet: run `PAYPAL_RECORD_CASSETTES=1 uv run python "
    "scripts/record_shopper_cassette.py` (see its docstring for the LLM_* variables)"
)


@pytest.fixture(scope="module")
def recorded() -> dict[str, Any]:
    if not CASSETTE.exists():
        pytest.fail(INSTRUCTION)
    return load_cassette(CASSETTE)  # type: ignore[no-any-return]


def replay(
    recorded: dict[str, Any], engine: Engine, admin: Engine
) -> tuple[ShopperResult, Any, Any]:
    reset(admin)
    sock, base = reserve_port()
    transport = SubstitutingTransport(recorded, live_base=base)
    now = recorded_clock(recorded)
    paypal = PayPalClient(
        PayPalConfig(client_id="replay-client-id", client_secret="replay-client-secret"),
        transport=transport, monotonic=lambda: 0.0, now=now, sleep=lambda _: None,
    )  # fmt: skip
    app = build_service(
        engine, base, paypal, payee_merchant_id=PLACEHOLDER_MERCHANT, paypal_now=now
    )
    gateway = LlmGateway(LlmConfig(mode="replay", model=str(recorded["meta"]["llm_model"])))
    with serve(app, sock):
        result = run_shopper(
            str(recorded["meta"]["goal"]),
            base_url=base,
            gateway=gateway,
            on_approve_url=phone_consent,
            on_payer_approval=lambda _url: None,  # approved at PayPal during the recording
            poll_s=0.5,
        )
    return result, transport, gateway


def test_the_recorded_run_replays_to_a_captured_order(
    recorded: dict[str, Any], app_engine: Engine, admin_engine: Engine
) -> None:
    assert recorded["meta"]["goal"] == GOAL
    result, transport, gateway = replay(recorded, app_engine, admin_engine)
    transport.assert_exhausted()
    assert result.outcome == "completed" and result.attempts == 1
    posts = [i["request"] for i in recorded["interactions"] if i["request"]["method"] == "POST"]
    assert sum(p["path"].endswith("/capture") for p in posts) == 1
    assert not any(p["path"].endswith("/void") for p in posts)
    captured = next(
        i["response"]["body"]["id"]
        for i in recorded["interactions"]
        if i["request"]["path"].startswith("/v2/payments/captures/")
    )
    assert result.capture_id == captured
    assert result.receipts["payment"]["status"] == "Success"
    assert gateway.config.mode == "replay"
    assert result.amount_minor is not None and result.amount_minor <= 8000


def test_the_decision_log_of_the_replayed_run_verifies(
    recorded: dict[str, Any], app_engine: Engine, admin_engine: Engine
) -> None:
    replay(recorded, app_engine, admin_engine)
    with app_engine.connect() as conn:
        report = verify_log(conn)
    assert report.ok, report


def _mutate(doc: dict[str, Any], what: str) -> dict[str, Any]:
    import copy

    out = copy.deepcopy(doc)
    first = next(i for i in out["interactions"] if i["request"]["path"] == "/v2/checkout/orders")
    unit = first["request"]["body"]["purchase_units"][0]
    if what == "amount":
        unit["amount"]["value"] = "1.00"
    elif what == "item":
        unit["items"][0]["name"] = "Another Product"
    elif what == "path":
        next(i for i in out["interactions"] if i["request"]["path"].endswith("/authorize"))[
            "request"
        ]["path"] += "x"
    elif what == "quantity":
        unit["items"][0]["quantity"] = "2"
    return out


@pytest.mark.parametrize("what", ["amount", "item", "path", "quantity"])
def test_a_mutated_recording_no_longer_replays(
    recorded: dict[str, Any], app_engine: Engine, admin_engine: Engine, what: str
) -> None:
    """Only the four per-run values are mapped: a different amount, item, quantity or path fails."""
    try:
        result, transport, _ = replay(_mutate(recorded, what), app_engine, admin_engine)
    except ShopperError:
        return  # the service refused or failed: nothing was bought
    assert result.outcome != "completed" and result.capture_id is None
    assert transport.remaining > 0  # the recording was not played to the end

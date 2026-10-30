"""Replay of the capture gate flows recorded from the REAL PayPal sandbox.

The cassette and the mandates it was recorded with are produced by
`PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_gate_cassette.py` (it needs two live payer
approvals) and are never edited by hand. Until they exist these tests are skipped with that
instruction. The replay runs the same code (tests/gate_flow.py) against the recording and must make
exactly the recorded calls, in order, with the recorded Request-Ids and bodies.

Scenario A ends in a gate pass and a real capture confirmed by GET. Scenario B is an order PATCHed
while `APPROVED`, authorized with the pre-authorize check off, caught by the gate, voided, and the
void confirmed by GET. Scenario B never captures.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from countersign.ablations import Ablations
from countersign.cp import CpAuthorized
from countersign.gate import GatePassed, GateRejected
from countersign.ledger.store import entries_for_checkout, verify_log
from countersign.paypal.cassette import CassetteTransport, load_cassette
from countersign.paypal.client import PayPalClient
from tests.gate_flow import (
    GateFixtures,
    authorize_flow,
    make_stack,
    patch_raise,
    paypal_config,
    probe_refusal,
    run_gate,
)

DIRECTORY = Path(__file__).resolve().parents[1] / "cassettes"
CASSETTE = DIRECTORY / "gate_flow.json"
FIXTURE = DIRECTORY / "gate_flow.mandates.json"
PLACEHOLDER_MERCHANT = "SCRUBBED_MERCHANT_ID"
INSTRUCTION = (
    "the capture gate cassette is not recorded yet: run "
    "`PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_gate_cassette.py`"
)


@pytest.fixture(scope="module")
def recorded() -> dict[str, Any]:
    if not CASSETTE.exists() or not FIXTURE.exists():
        pytest.skip(INSTRUCTION)
    return load_cassette(CASSETTE)  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def fixtures(recorded: dict[str, Any]) -> GateFixtures:
    return GateFixtures.from_json(FIXTURE.read_text(encoding="utf-8"))


@dataclass
class Replayed:
    transport: CassetteTransport
    outcome_a: Any
    outcome_b: Any
    raised: Any
    finished_b: Any
    refusal: Any


def replay(recorded: dict[str, Any], engine: Engine, fixtures: GateFixtures) -> Replayed:
    transport = CassetteTransport(recorded)
    recorded_at = datetime.fromisoformat(recorded["meta"]["recorded_at"])
    now = lambda: recorded_at + timedelta(minutes=5)
    client = PayPalClient(
        paypal_config(), transport=transport, monotonic=lambda: 0.0, now=now, sleep=lambda _: None
    )
    a = make_stack(engine, client, fixtures.clean, payee_merchant_id=PLACEHOLDER_MERCHANT,
                   paypal_now=now)  # fmt: skip
    _, finished = authorize_flow(a, fixtures.clean, lambda _url: None)
    assert isinstance(finished, CpAuthorized)
    outcome_a = run_gate(a, fixtures.clean)
    b = make_stack(engine, client, fixtures.changed, payee_merchant_id=PLACEHOLDER_MERCHANT,
                   paypal_now=now, cp_ablations=Ablations(no_preauth_check=True))  # fmt: skip
    raised: list[Any] = []

    def raise_order(order_id: str) -> None:
        raised.append(patch_raise(client, transport, client._config.base_url, order_id))

    _, finished_b = authorize_flow(b, fixtures.changed, lambda _url: None, between=raise_order)
    outcome_b = run_gate(b, fixtures.changed)
    refusal = probe_refusal(client, fixtures.changed.checkout_id, finished_b.authorization_id)
    return Replayed(transport, outcome_a, outcome_b, raised[0], finished_b, refusal)


def test_the_recorded_flows_replay_exactly(
    recorded: dict[str, Any], fixtures: GateFixtures, app_engine: Engine, clean_payments: None
) -> None:
    played = replay(recorded, app_engine, fixtures)
    played.transport.assert_exhausted()

    # A: the gate passed, captured once, and the capture was read back COMPLETED.
    assert isinstance(played.outcome_a, GatePassed)
    interactions = recorded["interactions"]
    posts = [i["request"] for i in interactions if i["request"]["method"] == "POST"]
    captures = [p for p in posts if p["path"].endswith("/capture")]
    assert len(captures) == 1 and captures[0]["body"]["final_capture"] is True
    capture_path = f"/v2/payments/captures/{played.outcome_a.capture_id}"
    capture_get = next(i for i in interactions if i["request"]["path"] == capture_path)
    assert capture_get["response"]["body"]["status"] == "COMPLETED"
    assert capture_get["response"]["body"]["final_capture"] is True

    # B: rejected by the gate, voided once, the void confirmed by a GET, never captured.
    assert isinstance(played.outcome_b, GateRejected)
    assert played.outcome_b.code in ("G-TERMS", "G-AMOUNT")
    assert isinstance(played.finished_b, CpAuthorized)
    assert played.finished_b.amount == played.raised  # PayPal authorized the raised amount
    voids = [p for p in posts if p["path"].endswith("/void")]
    # Two void requests are recorded: the gate's, then the deliberate error probe at the very end,
    # which uses another Request-Id and is answered 422.
    assert len(voids) == 2 and voids[0]["request_id"] != voids[1]["request_id"]
    assert interactions[-1]["response"]["status"] == 422
    assert interactions[-1]["request"]["path"] == voids[1]["path"]
    after_void = interactions[interactions.index(next(
        i for i in interactions if i["request"]["path"].endswith("/void")
    )) + 1]  # fmt: skip
    assert after_void["request"]["method"] == "GET"
    assert after_void["response"]["body"]["status"] == "VOIDED"
    b_authorization = voids[0]["path"].split("/")[-2]
    assert not any(
        p["path"] == f"/v2/payments/authorizations/{b_authorization}/capture" for p in posts
    )
    assert all(len(p["request_id"]) <= 108 for p in posts if p["request_id"])


def test_paypal_error_codes_are_found_by_the_mapper_where_the_recording_puts_them(
    recorded: dict[str, Any], fixtures: GateFixtures, app_engine: Engine, clean_payments: None
) -> None:
    from countersign.paypal.errors import PreviouslyVoided

    played = replay(recorded, app_engine, fixtures)
    assert isinstance(played.refusal, PreviouslyVoided) and played.refusal.status == 422
    body = recorded["interactions"][-1]["response"]["body"]
    in_name = body.get("name") == "PREVIOUSLY_VOIDED"
    in_details = any(d.get("issue") == "PREVIOUSLY_VOIDED" for d in body.get("details", []))
    # The answer recorded in docs/PROTOCOL.md 4.5 comes from this body.
    assert in_name or in_details, body


def test_the_replayed_decisions_are_in_a_verified_chain(
    recorded: dict[str, Any], fixtures: GateFixtures, app_engine: Engine, clean_payments: None
) -> None:
    replay(recorded, app_engine, fixtures)
    with app_engine.connect() as conn:
        clean = [e.kind for e in entries_for_checkout(conn, fixtures.clean.checkout_id)]
        changed = entries_for_checkout(conn, fixtures.changed.checkout_id)
        assert verify_log(conn).ok
    assert clean[-1] == "gate.captured" and "gate.rejected" not in clean
    assert changed[-1].kind == "gate.rejected"
    failed = [
        json.loads(e.payload) for e in changed if e.kind == "gate.step"
        if json.loads(e.payload)["outcome"] == "fail"
    ]  # fmt: skip
    assert failed and failed[0]["code"] in ("G-TERMS", "G-AMOUNT")


def test_the_receipts_of_the_replay_verify(
    recorded: dict[str, Any], fixtures: GateFixtures, app_engine: Engine, clean_payments: None
) -> None:
    played = replay(recorded, app_engine, fixtures)
    for outcome, status in ((played.outcome_a, "Success"), (played.outcome_b, "Error")):
        # The signing key is random per run, so only the signed claims are read here.
        segment = outcome.receipt.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        assert claims["status"] == status


# --------------------------------------------------------------- the cassette holds nothing private


def test_the_cassette_contains_no_credentials_and_no_buyer_data(recorded: dict[str, Any]) -> None:
    text = CASSETTE.read_text(encoding="utf-8") + FIXTURE.read_text(encoding="utf-8")
    assert "SCRUBBED_ACCESS_TOKEN" in text
    assert not re.search(r"@[A-Za-z0-9-]+\.[A-Za-z]", text), "an e-mail address"
    for needle in ("Bearer ", "client_secret", "access_token\": \"A", "payer_id", "given_name",
                   "surname", "address_line", "postal_code", "email_address"):  # fmt: skip
        cleaned = text.replace('"token_type": "Bearer"', "")
        cleaned = re.sub(r'"(\w+)": "SCRUBBED_[A-Z_]+"', "", cleaned)  # sentinels are allowed
        assert needle not in cleaned, needle
    for token in re.findall(r'"access_token": "([^"]*)"', text):
        assert token == "SCRUBBED_ACCESS_TOKEN"

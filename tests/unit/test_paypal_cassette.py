"""Cassette recording and replay, proved against a fake PayPal that leaks everything it can."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from countersign.catalog.catalog import load_catalog
from countersign.paypal.cassette import (
    CassetteError,
    CassetteTransport,
    RecordingTransport,
    check_clean,
    load_cassette,
    recording_enabled,
    scrub,
)
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from tests import paypal_fake as fake
from tests.ungated_capture_cycle import CycleResult, cycle_checkout, run_cycle

CLIENT_ID = "client-id-ABCDEF"
SECRET = "client-secret-ZYXWVU"
CHECKOUT = "chk_abcdefghijklmnopqrstuv"
ROOT = Path(__file__).resolve().parents[2]


class Ticker:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def client_for(transport: httpx.BaseTransport) -> PayPalClient:
    config = PayPalConfig(client_id=CLIENT_ID, client_secret=SECRET)
    return PayPalClient(
        config, transport=transport, monotonic=Ticker(), now=lambda: fake.RECORDED_AT
    )


def record(
    tmp_path: Path, checkout_id: str = CHECKOUT
) -> tuple[Path, CycleResult, fake.FakePayPal]:
    upstream = fake.FakePayPal()
    recorder = RecordingTransport(
        upstream.transport(),
        secrets=[CLIENT_ID, SECRET],
        meta={"checkout_id": checkout_id, "recorded_at": "2026-10-24T10:00:00Z"},
    )
    with client_for(recorder) as client:
        result = run_cycle(client, checkout_id, approve=upstream.approve)
    path = tmp_path / "cassette.json"
    recorder.save(path)
    return path, result, upstream


# ---------------------------------------------------------------- the cycle itself


def test_the_cycle_against_the_fake_reads_every_state_back(tmp_path: Path) -> None:
    _, result, upstream = record(tmp_path)
    assert result.approved.status == "APPROVED" and result.authorized.status == "COMPLETED"
    assert result.authorization.status == "CREATED" and result.authorization.id == "AUTH9"
    assert result.captured_authorization.status == "CAPTURED"
    assert result.capture.id == "CAP9" and result.capture.final_capture is True
    assert result.capture.amount == result.authorization.amount
    assert result.final_order.captures[0].id == "CAP9"
    total = next(t.amount for t in result.checkout.totals if t.type == "total")
    assert result.authorization.amount == total
    assert (
        result.authorization.invoice_id == CHECKOUT
        and result.authorization.custom_id == result.custom_id
    )
    sequence = [f"{m} {p}" for m, p in upstream.requests]
    assert sequence == [
        "POST /v1/oauth2/token",
        "POST /v2/checkout/orders",
        "GET /v2/checkout/orders/ORDER9",
        "POST /v2/checkout/orders/ORDER9/authorize",
        "GET /v2/checkout/orders/ORDER9",
        "GET /v2/payments/authorizations/AUTH9",
        "GET /v2/payments/authorizations/AUTH9",
        "POST /v2/payments/authorizations/AUTH9/capture",
        "GET /v2/checkout/orders/ORDER9",
        "GET /v2/payments/captures/CAP9",
        "GET /v2/payments/authorizations/AUTH9",
    ]


def test_an_unapproved_order_cannot_be_authorized(tmp_path: Path) -> None:
    upstream = fake.FakePayPal()
    with (
        client_for(upstream.transport()) as client,
        pytest.raises(Exception, match="ORDER_NOT_APPROVED"),
    ):
        run_cycle(client, CHECKOUT, approve=lambda _url: None)


def test_the_cycle_order_matches_the_checkout() -> None:
    checkout, request, custom_id = cycle_checkout(CHECKOUT, load_catalog())
    total = next(t.amount for t in checkout.totals if t.type == "total")
    assert request.amount == total and request.invoice_id == CHECKOUT
    assert request.custom_id == custom_id and custom_id.startswith("cs1.") and len(custom_id) <= 255
    assert len(request.items) == 2 and request.items[1].quantity == 2


# ---------------------------------------------------------------- scrubbing


def test_the_saved_cassette_has_nothing_sensitive(tmp_path: Path) -> None:
    path, _, _ = record(tmp_path)
    text = path.read_text()
    for leak in (
        CLIENT_ID,
        SECRET,
        fake.TOKEN,
        fake.APP_ID,
        fake.MERCHANT,
        fake.PAYER_EMAIL,
        fake.PAYER_NAME,
        fake.PAYER_ID,
        "Testbuyer",
        "1 Main St",
        "merchant@example.com",
        "Bearer ",
        "@",
    ):
        assert leak not in text, leak
    assert "authorization" not in text.lower().replace("authorizations", "").replace(
        "/authorize", ""
    )
    document = json.loads(text)
    token_exchange = document["interactions"][0]["response"]["body"]
    assert token_exchange["access_token"] == "SCRUBBED_ACCESS_TOKEN"
    assert token_exchange["app_id"] == "SCRUBBED_APP_ID"


def test_scrubbing_keeps_what_the_models_read(tmp_path: Path) -> None:
    path, _, _ = record(tmp_path)
    document = json.loads(path.read_text())
    orders = [
        i["response"]["body"]
        for i in document["interactions"]
        if i["request"]["method"] == "GET" and i["request"]["path"].endswith("/ORDER9")
    ]
    unit = orders[0]["purchase_units"][0]
    assert unit["payee"]["merchant_id"] == "SCRUBBED_MERCHANT_ID"
    assert unit["amount"]["value"] and unit["invoice_id"] == CHECKOUT
    assert orders[0]["payer"] == {} and orders[0]["payment_source"] == {} and unit["shipping"] == {}


def test_scrub_replaces_keys_drops_subtrees_and_known_strings() -> None:
    original = {
        "access_token": "tok-1234",
        "nested": {
            "merchant_id": "M1",
            "email_address": "a@b.c",
            "keep": "fine",
            "msg": "has SECRETVALUE in it",
        },
        "payer": {"name": "x"},
        "list": [{"payer_id": "P"}, "SECRETVALUE", 5, None, True],
        "shipping": {"a": 1},
        "payment_source": {"b": 2},
    }
    out = scrub(original, ["SECRETVALUE", "ab"])
    assert out["access_token"] == "SCRUBBED_ACCESS_TOKEN"
    assert out["nested"]["merchant_id"] == "SCRUBBED_MERCHANT_ID"
    assert out["nested"]["email_address"] == "SCRUBBED_EMAIL_ADDRESS"
    assert out["nested"]["keep"] == "fine" and out["nested"]["msg"] == "has SCRUBBED in it"
    assert out["payer"] == {} and out["shipping"] == {} and out["payment_source"] == {}
    assert out["list"] == [{"payer_id": "SCRUBBED_PAYER_ID"}, "SCRUBBED", 5, None, True]
    assert original["nested"]["merchant_id"] == "M1"  # the input is untouched


def test_very_short_secrets_are_not_used_for_replacement() -> None:
    assert scrub({"a": "abc abc"}, ["abc"]) == {"a": "abc abc"}
    assert scrub({"a": "abcd abcd"}, ["abcd"]) == {"a": "SCRUBBED SCRUBBED"}


@pytest.mark.parametrize("text", ["x@y.z", "Bearer abc", f"has {SECRET} inside", f"id {CLIENT_ID}"])
def test_check_clean_refuses_leaks(text: str) -> None:
    with pytest.raises(CassetteError):
        check_clean(text, [CLIENT_ID, SECRET])
    check_clean("nothing here", [CLIENT_ID, SECRET])


def test_save_refuses_to_write_when_something_leaks_through(tmp_path: Path) -> None:
    class Leaky(fake.FakePayPal):
        def handle(self, request: httpx.Request) -> httpx.Response:
            response = super().handle(request)
            if request.url.path == "/v2/checkout/orders" and request.method == "POST":
                return httpx.Response(
                    201, json={**response.json(), "note": "mail jane@example.org"}
                )
            return response

    upstream = Leaky()
    recorder = RecordingTransport(upstream.transport(), secrets=[CLIENT_ID, SECRET])
    with client_for(recorder) as client:
        run_cycle(client, CHECKOUT, approve=upstream.approve)
    target = tmp_path / "leaky.json"
    with pytest.raises(CassetteError, match="e-mail"):
        recorder.save(target)
    assert not target.exists()


def test_a_known_secret_echoed_by_the_server_is_replaced_not_refused(tmp_path: Path) -> None:
    class Echo(fake.FakePayPal):
        def handle(self, request: httpx.Request) -> httpx.Response:
            response = super().handle(request)
            if request.url.path == "/v2/checkout/orders" and request.method == "POST":
                return httpx.Response(
                    201, json={**response.json(), "note": f"client {CLIENT_ID} {SECRET}"}
                )
            return response

    upstream = Echo()
    recorder = RecordingTransport(upstream.transport(), secrets=[CLIENT_ID, SECRET])
    with client_for(recorder) as client:
        run_cycle(client, CHECKOUT, approve=upstream.approve)
    target = tmp_path / "echo.json"
    recorder.save(target)
    assert CLIENT_ID not in target.read_text() and SECRET not in target.read_text()


# ---------------------------------------------------------------- replay


def replay(path: Path, checkout_id: str = CHECKOUT) -> tuple[CycleResult, CassetteTransport]:
    transport = CassetteTransport(load_cassette(path))
    with client_for(transport) as client:
        return run_cycle(client, checkout_id, approve=lambda _url: None), transport


def test_replay_reproduces_the_recorded_cycle(tmp_path: Path) -> None:
    path, recorded, _ = record(tmp_path)
    replayed, transport = replay(path)
    transport.assert_exhausted()
    assert replayed.capture == recorded.capture
    assert replayed.authorization == recorded.authorization
    assert replayed.final_order.captures == recorded.final_order.captures
    assert replayed.checkout == recorded.checkout


def test_replay_fails_when_the_client_sends_something_else(tmp_path: Path) -> None:
    path, _, _ = record(tmp_path)
    with pytest.raises(CassetteError, match="PayPal-Request-Id"):
        replay(path, checkout_id="chk_ZZZZZZZZZZZZZZZZZZZZZZ")


def test_replay_detects_a_changed_body(tmp_path: Path) -> None:
    path, _, _ = record(tmp_path)
    document = json.loads(path.read_text())
    create = document["interactions"][1]["request"]
    create["body"]["purchase_units"][0]["description"] = "changed"
    path.write_text(json.dumps(document))
    with pytest.raises(CassetteError, match="different body"):
        replay(path)


def test_replay_detects_a_different_path(tmp_path: Path) -> None:
    path, _, _ = record(tmp_path)
    document = json.loads(path.read_text())
    document["interactions"][2]["request"]["path"] = "/v2/checkout/orders/OTHER"
    path.write_text(json.dumps(document))
    with pytest.raises(CassetteError, match="the cassette has"):
        replay(path)


def test_replay_detects_a_request_the_cassette_does_not_have(tmp_path: Path) -> None:
    path, _, _ = record(tmp_path)
    document = json.loads(path.read_text())
    document["interactions"] = document["interactions"][:5]
    path.write_text(json.dumps(document))
    with pytest.raises(CassetteError, match="unexpected request"):
        replay(path)


def test_replay_detects_recorded_exchanges_that_were_never_requested(tmp_path: Path) -> None:
    path, _, _ = record(tmp_path)
    transport = CassetteTransport(load_cassette(path))
    checkout, request, _ = cycle_checkout(CHECKOUT, load_catalog())
    with client_for(transport) as client:
        client.create_order(
            CHECKOUT, request, terms_hash=checkout.terms_hash()
        )  # only the token and create exchanges are used
    assert transport.remaining == 9
    with pytest.raises(CassetteError, match="never requested"):
        transport.assert_exhausted()


def test_replay_responses_are_strictly_in_order(tmp_path: Path) -> None:
    path, _, _ = record(tmp_path)
    transport = CassetteTransport(load_cassette(path))
    client = client_for(transport)
    with pytest.raises(CassetteError):
        client.get_order("ORDER9")  # the first recorded request is the token call, then a create


def test_cassette_files_must_be_a_known_version(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": 99, "interactions": []}))
    with pytest.raises(CassetteError):
        load_cassette(bad)
    bad.write_text(json.dumps({"version": 1, "interactions": "x"}))
    with pytest.raises(CassetteError):
        load_cassette(bad)


# ---------------------------------------------------------------- recording is opt in


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, False),
        ({"PAYPAL_RECORD_CASSETTES": "0"}, False),
        ({"PAYPAL_RECORD_CASSETTES": "true"}, False),
        ({"PAYPAL_RECORD_CASSETTES": ""}, False),
        ({"PAYPAL_RECORD_CASSETTES": "1"}, True),
    ],
)
def test_recording_is_off_unless_the_variable_is_one(env: dict[str, str], expected: bool) -> None:
    assert recording_enabled(env) is expected


def _load_script() -> Any:
    spec = importlib.util.spec_from_file_location(
        "record_script", ROOT / "scripts" / "record_paypal_cassette.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_recording_script_does_nothing_without_the_opt_in(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_script()
    monkeypatch.setattr(module, "parse_env_file", lambda _p: {})
    for name in list(__import__("os").environ):
        if name.startswith("PAYPAL_"):
            monkeypatch.delenv(name)
    monkeypatch.setattr(module, "OUTPUT", Path("/nonexistent/never-written.json"))
    assert module.main() == 2
    assert "Recording is off" in capsys.readouterr().err
    assert not Path("/nonexistent/never-written.json").exists()


def test_the_recording_script_refuses_a_live_host_even_when_opted_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    env = {
        "PAYPAL_RECORD_CASSETTES": "1",
        "PAYPAL_CLIENT_ID": CLIENT_ID,
        "PAYPAL_CLIENT_SECRET": SECRET,
        "PAYPAL_API_BASE": "https://api-m.paypal.com",  # secret-scan:allow (must be refused)
    }
    monkeypatch.setattr(module, "parse_env_file", lambda _p: env)
    from countersign.paypal.errors import PayPalConfigError

    with pytest.raises(PayPalConfigError):
        module.main()


def test_recorded_at_is_a_timezone_aware_instant() -> None:
    assert fake.RECORDED_AT == datetime(2026, 10, 24, 10, 0, tzinfo=UTC)


# ---------------------------------------------------------------- order terms flow


def test_terms_flow_records_and_replays_with_equal_terms(tmp_path: Path) -> None:
    """The flow behind the order terms cassette, against the fake: record, save, replay."""
    from countersign.paypal.terms_flow import KINDS, run_terms_flow

    ids = {kind: f"chk_{kind}_AAAAAAAAAAAA" for kind in KINDS}
    upstream = fake.FakePayPal()
    recorder = RecordingTransport(
        upstream.transport(), secrets=[CLIENT_ID, SECRET], meta={"checkout_ids": ids}
    )
    with client_for(recorder) as client:
        recorded = [run_terms_flow(client, kind, ids[kind]) for kind in KINDS]
    path = tmp_path / "terms.json"
    recorder.save(path)

    transport = CassetteTransport(load_cassette(path))
    with client_for(transport) as client:
        replayed = [run_terms_flow(client, kind, ids[kind]) for kind in KINDS]
    transport.assert_exhausted()
    for before, after in zip(recorded, replayed, strict=True):
        assert after.terms.checkout.terms_bytes() == after.checkout.terms_bytes()
        assert after.terms.checkout.terms_hash() == before.terms.checkout.terms_hash()
        assert before.terms.payee_merchant_id == fake.MERCHANT
        assert after.terms.payee_merchant_id == "SCRUBBED_MERCHANT_ID"  # scrubbed, never empty


def test_scrub_keeps_the_shipping_amount_in_a_breakdown_but_drops_the_address() -> None:
    from countersign.paypal.cassette import scrub

    body = {
        "purchase_units": [
            {
                "amount": {"breakdown": {"shipping": {"currency_code": "USD", "value": "4.99"}}},
                "shipping": {"address": {"address_line_1": "1 Main St"}},
            }
        ]
    }
    out = scrub(body, [])
    unit = out["purchase_units"][0]
    assert unit["amount"]["breakdown"]["shipping"] == {"currency_code": "USD", "value": "4.99"}
    assert unit["shipping"] == {}

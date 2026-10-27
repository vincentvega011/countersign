"""Every PayPal body goes through the strict loader: success, error, token and cassette paths.

A body a standard parser would read one way (the last of two equal keys, NaN, Infinity) or that is not
valid UTF-8 must be refused with a typed error, never turned into an object that is then hashed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from countersign.paypal import errors as E
from countersign.paypal.cassette import (
    CassetteError,
    RecordingTransport,
    _json_or_none,
    load_cassette,
)
from countersign.paypal.client import PayPalClient
from tests.unit.test_paypal_client import (
    BASE,
    CHECKOUT,
    Clock,
    auth_json,
    make_client,
    order_json,
    order_request,
    token_response,
)

DUPLICATE = b'{"id": "A1", "id": "B2", "status": "CREATED"}'
NAN = b'{"id": "A1", "amount": {"value": NaN}}'
INFINITY = b'{"id": "A1", "amount": {"value": -Infinity}}'
BAD_UTF8 = b'{"id": "A1\xff"}'
BOM = b'\xef\xbb\xbf{"id": "A1"}'
REFUSED = [DUPLICATE, NAN, INFINITY, BAD_UTF8, BOM]
IDS = ["duplicate-key", "nan", "infinity", "bad-utf8", "byte-order-mark"]
JSON_TYPE = {"content-type": "application/json"}


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def pp(clock: Clock) -> PayPalClient:
    return make_client(clock)


@pytest.fixture
def paypal(respx_mock: respx.MockRouter) -> respx.MockRouter:
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(return_value=token_response())
    return respx_mock


def raw(status: int, content: bytes) -> httpx.Response:
    return httpx.Response(status, content=content, headers=JSON_TYPE)


# ---------------------------------------------------------------- success bodies


@pytest.mark.parametrize("body", REFUSED, ids=IDS)
@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda c: c.get_order("ORDER1"), id="get_order"),
        pytest.param(lambda c: c.get_authorization("AUTH1"), id="get_authorization"),
        pytest.param(lambda c: c.get_capture("CAP1"), id="get_capture"),
    ],
)
def test_a_refused_success_body_is_not_read(
    paypal: respx.MockRouter, pp: PayPalClient, call: Any, body: bytes
) -> None:
    paypal.get(url__regex=rf"{BASE}/v2/.*").mock(return_value=raw(200, body))
    with pytest.raises(E.PayPalResponseError, match="strict JSON loader"):
        call(pp)


@pytest.mark.parametrize("body", REFUSED, ids=IDS)
def test_a_refused_create_order_body_is_not_read(
    paypal: respx.MockRouter, pp: PayPalClient, body: bytes
) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders").mock(return_value=raw(201, body))
    with pytest.raises(E.PayPalResponseError, match="strict JSON loader"):
        pp.create_order(CHECKOUT, order_request())


@pytest.mark.parametrize("body", REFUSED, ids=IDS)
def test_a_refused_token_body_gives_no_token(
    respx_mock: respx.MockRouter, pp: PayPalClient, body: bytes
) -> None:
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(return_value=raw(200, body))
    with pytest.raises(E.PayPalResponseError):
        pp.get_order("ORDER1")


def test_the_last_duplicate_wins_nowhere(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    """The exact attack: two amounts in one object must not become the second one."""
    body = json.dumps(order_json()).encode()
    twice = body.replace(b'"APPROVED"', b'"APPROVED", "status": "COMPLETED"', 1)
    assert json.loads(twice)["status"] == "COMPLETED"  # a standard parser takes the last
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(return_value=raw(200, twice))
    with pytest.raises(E.PayPalResponseError):
        pp.get_order("ORDER1")


# ---------------------------------------------------------------- error bodies


@pytest.mark.parametrize("body", REFUSED, ids=IDS)
@pytest.mark.parametrize("status", [404, 422, 400])
def test_a_refused_error_body_fails_closed_with_the_typed_error(
    paypal: respx.MockRouter, pp: PayPalClient, status: int, body: bytes
) -> None:
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(return_value=raw(status, body))
    with pytest.raises(E.PayPalResponseError) as caught:
        pp.get_order("ORDER1")
    assert caught.value.status == status


@pytest.mark.parametrize("body", REFUSED, ids=IDS)
def test_a_refused_error_body_on_a_mutation_has_an_unknown_outcome(
    paypal: respx.MockRouter, pp: PayPalClient, body: bytes
) -> None:
    route = paypal.post(f"{BASE}/v2/payments/authorizations/AUTH1/void").mock(
        return_value=raw(500, body)
    )
    with pytest.raises(E.PayPalResponseError) as caught:
        pp.void_authorization(CHECKOUT, "AUTH1")
    assert caught.value.outcome_unknown is True
    assert route.call_count == 1  # fail closed: not retried as if it were an outage


@pytest.mark.parametrize("body", REFUSED, ids=IDS)
def test_a_refused_error_body_on_a_read_is_not_retried(
    paypal: respx.MockRouter, pp: PayPalClient, body: bytes
) -> None:
    route = paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(return_value=raw(503, body))
    with pytest.raises(E.PayPalResponseError) as caught:
        pp.get_order("ORDER1")
    assert caught.value.outcome_unknown is False
    assert route.call_count == 1


@pytest.mark.parametrize("body", REFUSED, ids=IDS)
def test_a_refused_error_body_on_a_non_listed_status_is_refused_in_map_error(body: bytes) -> None:
    with pytest.raises(E.PayPalResponseError):
        E.map_error(raw(302, body))


def test_a_body_that_is_not_json_is_still_just_no_object() -> None:
    assert E.error_body(httpx.Response(502, content=b"<html>Bad gateway</html>")) == {}
    assert E.error_body(httpx.Response(204)) == {}
    assert E.error_body(raw(200, b"[1, 2]")) == {}


def test_a_valid_body_is_still_read() -> None:
    assert E.error_body(raw(200, json.dumps(auth_json()).encode()))["id"] == "AUTH1"


# ---------------------------------------------------------------- cassettes


@pytest.mark.parametrize("body", [DUPLICATE, NAN, INFINITY, BAD_UTF8], ids=IDS[:4])
def test_a_cassette_file_with_a_refused_body_is_not_loaded(tmp_path: Path, body: bytes) -> None:
    path = tmp_path / "c.json"
    path.write_bytes(b'{"version": 1, "interactions": [], "meta": ' + body + b"}")
    with pytest.raises(CassetteError, match="strict JSON loader"):
        load_cassette(path)


def test_a_cassette_file_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    path.write_text("[1]")
    with pytest.raises(CassetteError):
        load_cassette(path)


@pytest.mark.parametrize("body", [DUPLICATE, NAN, INFINITY, BAD_UTF8], ids=IDS[:4])
def test_a_refused_body_is_not_recorded(body: bytes) -> None:
    with pytest.raises(CassetteError, match="strict JSON loader"):
        _json_or_none(body, "application/json")


def test_recording_refuses_a_response_with_a_duplicate_key() -> None:
    upstream = httpx.MockTransport(lambda request: raw(200, DUPLICATE))
    recorder = RecordingTransport(upstream, secrets=[], meta={})
    with httpx.Client(transport=recorder, base_url=BASE) as http, pytest.raises(CassetteError):
        http.get("/v2/checkout/orders/ORDER1")

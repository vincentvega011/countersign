"""The PayPal client against mocked HTTP: every operation, errors, retries, limits and secrecy."""

from __future__ import annotations

import inspect
import json
import traceback
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
import structlog

from countersign.canonical.money import Money
from countersign.paypal import errors as E
from countersign.paypal.approval import CaptureApproval, mint_capture_approval
from countersign.paypal.client import Mutation, OrderCreated, PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.limits import (
    MAX_CUSTOM_ID,
    MAX_INVOICE_ID,
    MAX_REQUEST_ID,
    LimitError,
)
from countersign.paypal.models import ExperienceContext, OrderItem, OrderRequest
from countersign.paypal.request_id import (
    Operation,
    authorize_request_id,
    capture_request_id,
    create_order_request_id,
    derive_request_id,
    void_request_id,
)

BASE = "https://api-m.sandbox.paypal.com"
CLIENT_ID = "client-id-ABCDEF"
SECRET = "client-secret-ZYXWVU"
TOKEN = "access-token-QWERTY-0001"
USD = "USD"
NOW = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
CHECKOUT = "chk_abcdefghijklmnopqrstuv"
RK = "refund-1"
CUSTOM = "cs1.x"  # the custom_id auth_json carries


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


def make_client(clock: Clock, **overrides: Any) -> PayPalClient:
    config = PayPalConfig(client_id=CLIENT_ID, client_secret=SECRET, **overrides)
    return PayPalClient(config, monotonic=clock.monotonic, now=lambda: NOW, sleep=clock.sleep)


@pytest.fixture
def pp(clock: Clock) -> PayPalClient:
    return make_client(clock)


def token_response(expires_in: int = 3600, token: str = TOKEN) -> httpx.Response:
    return httpx.Response(
        200, json={"access_token": token, "token_type": "Bearer", "expires_in": expires_in}
    )


@pytest.fixture
def paypal(respx_mock: respx.MockRouter) -> respx.MockRouter:
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(return_value=token_response())
    return respx_mock


def money(value: str, currency: str = USD) -> dict[str, str]:
    return {"currency_code": currency, "value": value}


def auth_json(
    ident: str = "AUTH1", status: str = "CREATED", amount: str = "74.00", **extra: Any
) -> dict[str, Any]:
    return {
        "id": ident,
        "status": status,
        "amount": money(amount),
        "invoice_id": CHECKOUT,
        "custom_id": "cs1.x",
        "expiration_time": "2026-11-20T10:00:00Z",
        "create_time": "2026-10-24T10:00:00Z",
        **extra,
    }


def capture_json(ident: str = "CAP1", status: str = "COMPLETED", amount: str = "74.00") -> Any:
    return {"id": ident, "status": status, "amount": money(amount), "final_capture": True}


def order_json(status: str = "APPROVED", **extra: Any) -> dict[str, Any]:
    return {
        "id": "ORDER1",
        "status": status,
        "intent": "AUTHORIZE",
        "purchase_units": [
            {
                "reference_id": "default",
                "amount": {
                    **money("74.00"),
                    "breakdown": {"item_total": money("68.50"), "tax_total": money("5.50")},
                },
                "invoice_id": CHECKOUT,
                "custom_id": "cs1.x",
                "payee": {"merchant_id": "MERCHANT123"},
                "items": [
                    {
                        "name": "Thing",
                        "quantity": "2",
                        "unit_amount": money("25.00"),
                        "tax": money("2.00"),
                        "sku": "S1",
                    }
                ],
            }
        ],
        **extra,
    }


def order_request(**overrides: Any) -> OrderRequest:
    fields: dict[str, Any] = {
        "amount": Money(USD, 7400),
        "invoice_id": CHECKOUT,
        "custom_id": "cs1.abcdef",
        "items": (
            OrderItem(
                "Sample headphones", 2, Money(USD, 2500), Money(USD, 200), "HP-100", "DIGITAL_GOODS"
            ),
            OrderItem(
                "Sample cable", 1, Money(USD, 1850), Money(USD, 150), "CB-200", "DIGITAL_GOODS"
            ),
        ),
        "experience_context": ExperienceContext("https://example.com/r", "https://example.com/c"),
        "description": "Test order",
    }
    fields.update(overrides)
    return OrderRequest(**fields)


def approval(minor: int = 7400, **overrides: Any) -> CaptureApproval:
    """A capture approval as the gate would mint it (the tests stand in for the gate)."""
    fields: dict[str, Any] = {
        "checkout_id": CHECKOUT,
        "authorization_id": "AUTH1",
        "expected_total": Money(USD, minor),
        "invoice_id": CHECKOUT,
        "custom_id": CUSTOM,
    }
    fields.update(overrides)
    return mint_capture_approval(**fields)


def post_calls(router: respx.MockRouter) -> list[httpx.Request]:
    return [c.request for c in router.calls if c.request.url.path != "/v1/oauth2/token"]


# =============================================================== configuration


def test_config_defaults_to_the_sandbox_and_hides_credentials() -> None:
    config = PayPalConfig(client_id=CLIENT_ID, client_secret=SECRET)
    assert config.base_url == BASE
    for text in (repr(config), str(config), f"{config}", f"{config!r}"):
        assert CLIENT_ID not in text and SECRET not in text


@pytest.mark.parametrize(
    "url",
    [  # secret-scan:allow (hosts the client must refuse)
        "https://api-m.paypal.com",  # secret-scan:allow
        "https://api.paypal.com",  # secret-scan:allow
        "https://API-M.PAYPAL.COM",  # secret-scan:allow
    ],
)
def test_live_hosts_are_refused_even_when_other_hosts_are_allowed(url: str) -> None:
    for allow in (False, True):
        with pytest.raises(E.PayPalConfigError, match="live"):
            PayPalConfig(
                client_id=CLIENT_ID, client_secret=SECRET, base_url=url, allow_non_sandbox=allow
            )


def test_other_hosts_need_the_explicit_flag() -> None:
    with pytest.raises(E.PayPalConfigError, match="unless explicitly allowed"):
        PayPalConfig(
            client_id=CLIENT_ID, client_secret=SECRET, base_url="https://mock.example.test"
        )
    config = PayPalConfig(
        client_id=CLIENT_ID,
        client_secret=SECRET,
        base_url="https://mock.example.test",
        allow_non_sandbox=True,
    )
    assert config.base_url == "https://mock.example.test"


@pytest.mark.parametrize(
    "url",
    [
        "http://api-m.sandbox.paypal.com",
        "ftp://api-m.sandbox.paypal.com",
        "https://user:pw@api-m.sandbox.paypal.com",
        "https://api-m.sandbox.paypal.com/v2",
        "https://api-m.sandbox.paypal.com?x=1",
        "https://api-m.sandbox.paypal.com#f",
        "http://mock.example.test",
    ],
)
def test_malformed_or_insecure_base_urls_are_refused(url: str) -> None:
    with pytest.raises(E.PayPalConfigError):
        PayPalConfig(
            client_id=CLIENT_ID, client_secret=SECRET, base_url=url, allow_non_sandbox=True
        )


def test_http_is_allowed_for_a_local_host_only_with_the_flag() -> None:
    PayPalConfig(
        client_id=CLIENT_ID,
        client_secret=SECRET,
        base_url="http://127.0.0.1:9000",
        allow_non_sandbox=True,
    )
    with pytest.raises(E.PayPalConfigError):
        PayPalConfig(client_id=CLIENT_ID, client_secret=SECRET, base_url="http://127.0.0.1:9000")


@pytest.mark.parametrize("bad", ["", " ", "a\nb", " a", "a ", "a\x00"])
def test_credentials_must_be_clean(bad: str) -> None:
    with pytest.raises(E.PayPalConfigError):
        PayPalConfig(client_id=bad, client_secret=SECRET)
    with pytest.raises(E.PayPalConfigError):
        PayPalConfig(client_id=CLIENT_ID, client_secret=bad)


@pytest.mark.parametrize("attempts", [0, 6, -1])
def test_attempts_are_bounded(attempts: int) -> None:
    with pytest.raises(E.PayPalConfigError):
        PayPalConfig(client_id=CLIENT_ID, client_secret=SECRET, max_attempts=attempts)


def test_from_env() -> None:
    env = {
        "PAYPAL_CLIENT_ID": CLIENT_ID,
        "PAYPAL_CLIENT_SECRET": SECRET,
        "PAYPAL_API_BASE": BASE + "/",
    }
    assert PayPalConfig.from_env(env).base_url == BASE
    assert PayPalConfig.from_env({**env, "PAYPAL_API_BASE": ""}).base_url == BASE
    with pytest.raises(E.PayPalConfigError):
        PayPalConfig.from_env({})
    odd = {**env, "PAYPAL_API_BASE": "https://mock.example.test"}
    with pytest.raises(E.PayPalConfigError):
        PayPalConfig.from_env(odd)
    assert PayPalConfig.from_env({**odd, "PAYPAL_ALLOW_NON_SANDBOX": "1"}).allow_non_sandbox


# =============================================================== limits


def test_the_limits_are_the_confirmed_ones() -> None:
    assert (MAX_REQUEST_ID, MAX_CUSTOM_ID, MAX_INVOICE_ID) == (108, 255, 127)


@pytest.mark.parametrize(("size", "ok"), [(1, True), (127, True), (128, False), (0, False)])
def test_invoice_id_boundary(size: int, ok: bool) -> None:
    if ok:
        assert order_request(invoice_id="i" * size).invoice_id == "i" * size
    else:
        with pytest.raises(LimitError):
            order_request(invoice_id="i" * size)


@pytest.mark.parametrize(("size", "ok"), [(1, True), (255, True), (256, False), (0, False)])
def test_custom_id_boundary(size: int, ok: bool) -> None:
    if ok:
        assert order_request(custom_id="c" * size).custom_id == "c" * size
    else:
        with pytest.raises(LimitError):
            order_request(custom_id="c" * size)


@pytest.mark.parametrize("bad", ["a\nb", "a\x00b", "a\x1fb", "a\x7fb", "a\rb", "a\tb", None, 5])
def test_ids_refuse_control_characters_and_non_strings(bad: Any) -> None:
    with pytest.raises(LimitError):
        order_request(invoice_id=bad)
    with pytest.raises(LimitError):
        order_request(custom_id=bad)
    assert (
        order_request(invoice_id="a b", custom_id="x y~z").invoice_id == "a b"
    )  # space and ~ are fine


def test_item_text_is_held_to_127() -> None:
    OrderItem("n" * 127, 1, Money(USD, 100), sku="s" * 127)
    with pytest.raises(LimitError):
        OrderItem("n" * 128, 1, Money(USD, 100))
    with pytest.raises(LimitError):
        OrderItem("n", 1, Money(USD, 100), sku="s" * 128)
    with pytest.raises(LimitError):
        OrderItem("", 1, Money(USD, 100))


@pytest.mark.parametrize("quantity", [0, -1, 10_000_000_000, 1.5, True, "2"])
def test_item_quantity_must_be_a_small_positive_integer(quantity: Any) -> None:
    with pytest.raises(LimitError):
        OrderItem("n", quantity, Money(USD, 100))
    OrderItem("n", 9_999_999_999, Money(USD, 100))


def test_order_totals_must_add_up_and_share_a_currency() -> None:
    with pytest.raises(LimitError, match="breakdown total"):
        order_request(amount=Money(USD, 7401))
    with pytest.raises(LimitError, match="positive"):
        order_request(amount=Money(USD, 0), items=(OrderItem("n", 1, Money(USD, 0)),))
    with pytest.raises(LimitError, match="currency"):
        order_request(
            items=(OrderItem("n", 1, Money("EUR", 7400)),),
        )
    with pytest.raises(LimitError, match="at least one item"):
        order_request(items=())


def test_experience_urls_must_be_http_urls() -> None:
    for url in ("", "javascript:alert(1)", "example.com", "ftp://x.test/", "https://"):
        with pytest.raises(LimitError):
            ExperienceContext(url, "https://example.com/c")
    with pytest.raises(LimitError):
        ExperienceContext("https://example.com/r", "https://example.com/" + "a" * 2000)


def test_order_json_shape_is_exact() -> None:
    body = order_request().to_json()
    assert body["intent"] == "AUTHORIZE"
    (unit,) = body["purchase_units"]
    assert unit["invoice_id"] == CHECKOUT and unit["custom_id"] == "cs1.abcdef"
    assert unit["amount"] == {
        "currency_code": "USD",
        "value": "74.00",
        "breakdown": {"item_total": money("68.50"), "tax_total": money("5.50")},
    }
    assert unit["items"][0] == {
        "name": "Sample headphones",
        "quantity": "2",
        "unit_amount": money("25.00"),
        "tax": money("2.00"),
        "sku": "HP-100",
        "category": "DIGITAL_GOODS",
    }
    ctx = body["payment_source"]["paypal"]["experience_context"]
    assert ctx["user_action"] == "PAY_NOW" and ctx["shipping_preference"] == "NO_SHIPPING"
    assert (
        "tax_total"
        not in order_request(
            amount=Money(USD, 6850),
            items=(OrderItem("n", 1, Money(USD, 6850)),),
        ).to_json()["purchase_units"][0]["amount"]["breakdown"]
    )


def test_zero_decimal_currency_amounts() -> None:
    request = order_request(
        amount=Money("JPY", 1000), items=(OrderItem("n", 1, Money("JPY", 1000)),)
    )
    assert request.to_json()["purchase_units"][0]["amount"]["value"] == "1000"


# =============================================================== request ids


def test_request_id_is_deterministic_and_distinct() -> None:
    a = derive_request_id(CHECKOUT, Operation.CAPTURE)
    assert a == derive_request_id(CHECKOUT, Operation.CAPTURE)
    ids = {derive_request_id(CHECKOUT, op) for op in Operation}
    assert len(ids) == len(Operation)
    assert derive_request_id("chk_other", Operation.CAPTURE) != a
    assert derive_request_id(CHECKOUT, Operation.REFUND, "x") != derive_request_id(
        CHECKOUT, Operation.REFUND, "y"
    )
    assert derive_request_id(CHECKOUT, Operation.REFUND, "x") != derive_request_id(
        CHECKOUT, Operation.REFUND
    )


def test_request_id_fields_are_unambiguous() -> None:
    # Length prefixes: moving a character between fields changes the id.
    a = derive_request_id("ab", Operation.REFUND, "c")
    b = derive_request_id("a", Operation.REFUND, "bc")
    assert a != b
    assert derive_request_id("a", Operation.REFUND, "") != derive_request_id("a", Operation.REFUND)


def test_request_id_shape_and_length() -> None:
    for op in Operation:
        value = derive_request_id(CHECKOUT, op, "p" * 500)
        assert value.startswith(f"cs1.{op.value}.") and len(value) <= MAX_REQUEST_ID
        assert len(value.rsplit(".", 1)[1]) == 43
    assert len(derive_request_id("x" * 10_000, Operation.CREATE_ORDER)) <= MAX_REQUEST_ID


def _reference_request_id(checkout_id: str, operation: str, *parts: str) -> str:
    """The derivation written out with hashlib alone, as an independent reference."""
    import base64
    import hashlib
    import struct

    fields = [checkout_id, operation, *parts]
    data = b"".join(struct.pack(">I", len(f.encode())) + f.encode() for f in fields)
    digest = hashlib.sha256(b"cs.paypal.request.v1\x00" + data).digest()
    return f"cs1.{operation}." + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def test_request_id_golden_values_and_independent_reference() -> None:
    # Pins the derivation: a change here changes every replay key, so it must be deliberate.
    capture = "cs1.capture.6SAp26KoaWG2Qey0UPQeqd9RyjdJ8aa7o7an14hZiHU"
    refund = "cs1.refund.Ei3_ioiA51i4xlzHQGXyiF3obEXc6Aq5KUG-XMWvG5A"
    assert derive_request_id(CHECKOUT, Operation.CAPTURE) == capture
    assert derive_request_id(CHECKOUT, Operation.REFUND, "CAP1", "full") == refund
    for op in Operation:
        assert derive_request_id(CHECKOUT, op, "a", "") == _reference_request_id(
            CHECKOUT, op.value, "a", ""
        )


def test_create_order_request_id_covers_the_request_body() -> None:
    body = order_request().to_json()
    repriced = order_request(custom_id="cs1.other").to_json()
    a = create_order_request_id(CHECKOUT, body)
    assert a == create_order_request_id(CHECKOUT, order_request().to_json())
    assert a != create_order_request_id(CHECKOUT, repriced)  # a changed request is a new request
    assert a != create_order_request_id("chk_other", body)
    assert a != derive_request_id(CHECKOUT, Operation.CREATE_ORDER)  # the first derivation
    assert len(a) <= MAX_REQUEST_ID
    # Independent reference: SHA-256 with hashlib over the JCS bytes (the rfc8785 library), then the
    # generic derivation written out above.
    import base64
    import hashlib

    import rfc8785

    digest = hashlib.sha256(b"cs.paypal.order_request.v1\x00" + rfc8785.dumps(body)).digest()
    part = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert a == _reference_request_id(CHECKOUT, "create_order", part)
    # Pinned. The generic derivation did not change, so its golden values above still hold; this value
    # pins the create-order form: checkout id, operation and the hash of the body that is sent.
    assert a == "cs1.create_order.6Khit-OAGH4yArD4z0bHNMlCxFUhnVTGshLuHMk1rFw"


def test_authorize_capture_and_void_request_ids_name_what_they_act_on() -> None:
    money = Money(USD, 7400)
    a1 = authorize_request_id(CHECKOUT, "ORDER1")
    assert a1 == authorize_request_id(CHECKOUT, "ORDER1")
    assert a1 != authorize_request_id(CHECKOUT, "ORDER2")  # a re-priced checkout's second order
    assert a1 != authorize_request_id("chk_other", "ORDER1")

    v1 = void_request_id(CHECKOUT, "AUTH1")
    assert v1 == void_request_id(CHECKOUT, "AUTH1")
    assert v1 != void_request_id(
        CHECKOUT, "AUTH2"
    )  # the second authorization is not voided by replay

    c1 = capture_request_id(CHECKOUT, "AUTH1", money, CHECKOUT, CUSTOM)
    assert c1 == capture_request_id(CHECKOUT, "AUTH1", money, CHECKOUT, CUSTOM)
    assert c1 != capture_request_id(CHECKOUT, "AUTH2", money, CHECKOUT, CUSTOM)
    assert c1 != capture_request_id(CHECKOUT, "AUTH1", Money(USD, 7401), CHECKOUT, CUSTOM)
    assert c1 != capture_request_id(CHECKOUT, "AUTH1", Money("EUR", 7400), CHECKOUT, CUSTOM)
    assert c1 != capture_request_id(CHECKOUT, "AUTH1", money, "chk_other", CUSTOM)
    assert c1 != capture_request_id(CHECKOUT, "AUTH1", money, CHECKOUT, "cs1.other")
    # none of them is the first derivation, from the checkout id and operation alone
    assert {a1, v1, c1}.isdisjoint(derive_request_id(CHECKOUT, op) for op in Operation)
    assert all(len(x) <= MAX_REQUEST_ID for x in (a1, v1, c1))


def test_authorize_capture_and_void_request_ids_match_an_independent_reference() -> None:
    assert authorize_request_id(CHECKOUT, "ORDER1") == _reference_request_id(
        CHECKOUT, "authorize", "ORDER1"
    )
    assert void_request_id(CHECKOUT, "AUTH1") == _reference_request_id(CHECKOUT, "void", "AUTH1")
    assert capture_request_id(
        CHECKOUT, "AUTH1", Money(USD, 7400), CHECKOUT, CUSTOM
    ) == _reference_request_id(CHECKOUT, "capture", "AUTH1", "USD:74.00", CHECKOUT, CUSTOM)
    # Pinned: these values change every replay key, so a change must be deliberate.
    assert (
        authorize_request_id(CHECKOUT, "ORDER1")
        == "cs1.authorize.li2HNEL7Qv_NFW8x_BFGcOOFZcnA4HqQZLXhIuwbXNo"
    )
    assert (
        void_request_id(CHECKOUT, "AUTH1") == "cs1.void.CuWjXe4NcQJjMi9AnQX6LJUsdW_zDp7W9HswiiaMTls"
    )
    assert (
        capture_request_id(CHECKOUT, "AUTH1", Money(USD, 7400), CHECKOUT, CUSTOM)
        == "cs1.capture.jQoqx108h_K6xhVm_YoEJ20y-eDrTtpTIbtxCWhdR-8"
    )


def test_a_second_authorization_of_the_same_checkout_is_voided_with_its_own_id(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(url__regex=rf"{BASE}/v2/payments/authorizations/AUTH\d/void").mock(
        return_value=httpx.Response(204)
    )
    pp.void_authorization(CHECKOUT, "AUTH1")
    pp.void_authorization(CHECKOUT, "AUTH2")
    first, second = (r.headers["paypal-request-id"] for r in post_calls(paypal))
    assert first != second


def test_authorizing_two_orders_of_one_checkout_uses_two_ids(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(url__regex=rf"{BASE}/v2/checkout/orders/ORDER\d/authorize").mock(
        return_value=httpx.Response(201, json={})
    )
    pp.authorize_order(CHECKOUT, "ORDER1")
    pp.authorize_order(CHECKOUT, "ORDER2")
    first, second = (r.headers["paypal-request-id"] for r in post_calls(paypal))
    assert first != second


def test_capture_sends_the_id_for_the_approved_terms(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    route = capture_routes(paypal)
    pp.capture_authorization(approval(7400))
    sent = route.calls[0].request.headers["paypal-request-id"]
    assert sent == capture_request_id(CHECKOUT, "AUTH1", Money(USD, 7400), CHECKOUT, CUSTOM)


def test_the_caller_cannot_supply_the_create_order_hash() -> None:
    assert set(inspect.signature(PayPalClient.create_order).parameters) == {
        "self",
        "checkout_id",
        "order",
    }


def test_key_order_does_not_change_the_create_order_request_id() -> None:
    body = order_request().to_json()
    shuffled = dict(reversed(list(body.items())))
    assert create_order_request_id(CHECKOUT, body) == create_order_request_id(CHECKOUT, shuffled)


def test_a_repriced_checkout_sends_a_different_create_request_id(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(201, json={"id": "ORDER1", "status": "CREATED"})
    )
    pp.create_order(CHECKOUT, order_request())
    pp.create_order(CHECKOUT, order_request())
    pp.create_order(CHECKOUT, order_request(custom_id="cs1.other"))
    first, again, repriced = (r.headers["paypal-request-id"] for r in post_calls(paypal))
    assert first == again
    assert repriced != first


def test_request_id_parts_must_be_strings() -> None:
    for part in (5, None, b"x", ("a",)):
        with pytest.raises(ValueError):
            derive_request_id(CHECKOUT, Operation.REFUND, part)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [("", Operation.CAPTURE), (5, Operation.CAPTURE)])
def test_request_id_needs_a_checkout_id(bad: tuple[Any, Operation]) -> None:
    with pytest.raises(ValueError):
        derive_request_id(*bad)


def test_request_id_needs_an_operation() -> None:
    with pytest.raises(TypeError):
        derive_request_id(CHECKOUT, "capture")  # type: ignore[arg-type]


# =============================================================== OAuth


def test_token_request_uses_basic_auth_and_the_client_credentials_grant(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=order_json())
    )
    pp.get_order("ORDER1")
    token_call = paypal.calls[0].request
    assert token_call.method == "POST" and token_call.url.path == "/v1/oauth2/token"
    assert token_call.headers["authorization"].startswith("Basic ")
    assert token_call.content == b"grant_type=client_credentials"
    api = paypal.calls[1].request
    assert api.headers["authorization"] == f"Bearer {TOKEN}"


def test_token_is_cached_across_calls(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=order_json())
    )
    for _ in range(5):
        pp.get_order("ORDER1")
    assert sum(c.request.url.path == "/v1/oauth2/token" for c in paypal.calls) == 1


def test_token_is_refreshed_before_it_expires(
    respx_mock: respx.MockRouter, clock: Clock, pp: PayPalClient
) -> None:
    tokens = iter(["tok-one-1111", "tok-two-2222", "tok-three-3333"])
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(
        side_effect=lambda r: token_response(3600, next(tokens))
    )
    respx_mock.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=order_json())
    )
    pp.get_order("ORDER1")  # token one, expires at t = 1000 + 3600
    clock.t = 1000 + 3600 - 61  # one second more than the 60 s skew remains
    pp.get_order("ORDER1")
    assert respx_mock.calls.last.request.headers["authorization"] == "Bearer tok-one-1111"
    clock.t = 1000 + 3600 - 60  # exactly the skew: refresh
    pp.get_order("ORDER1")
    assert respx_mock.calls.last.request.headers["authorization"] == "Bearer tok-two-2222"
    clock.t = 1000 + 3600 + 5000
    pp.get_order("ORDER1")
    assert respx_mock.calls.last.request.headers["authorization"] == "Bearer tok-three-3333"


def test_a_401_refreshes_the_token_once_and_retries(
    respx_mock: respx.MockRouter, pp: PayPalClient
) -> None:
    tokens = iter(["tok-one-1111", "tok-two-2222"])
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(
        side_effect=lambda r: token_response(3600, next(tokens))
    )
    route = respx_mock.get(f"{BASE}/v2/checkout/orders/ORDER1")
    route.side_effect = [
        httpx.Response(401, json={"name": "AUTHENTICATION_FAILURE", "message": "expired"}),
        httpx.Response(200, json=order_json()),
    ]
    assert pp.get_order("ORDER1").id == "ORDER1"
    assert [c.request.headers["authorization"] for c in route.calls] == [
        "Bearer tok-one-1111",
        "Bearer tok-two-2222",
    ]


def test_a_401_refresh_works_even_with_a_single_attempt(
    respx_mock: respx.MockRouter, clock: Clock
) -> None:
    client = make_client(clock, max_attempts=1)
    tokens = iter(["tok-one-1111", "tok-two-2222"])
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(
        side_effect=lambda r: token_response(3600, next(tokens))
    )
    route = respx_mock.get(f"{BASE}/v2/checkout/orders/ORDER1")
    route.side_effect = [
        httpx.Response(401, json={"name": "X"}),
        httpx.Response(200, json=order_json()),
    ]
    assert client.get_order("ORDER1").id == "ORDER1"
    assert route.call_count == 2


def test_a_token_refresh_does_not_use_up_a_retry(
    respx_mock: respx.MockRouter, clock: Clock
) -> None:
    client = make_client(clock, max_attempts=2)
    tokens = iter(["tok-one-1111", "tok-two-2222"])
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(
        side_effect=lambda r: token_response(3600, next(tokens))
    )
    route = respx_mock.get(f"{BASE}/v2/checkout/orders/ORDER1")
    route.side_effect = [
        httpx.Response(401, json={"name": "X"}),
        httpx.Response(500),
        httpx.Response(200, json=order_json()),
    ]
    assert (
        client.get_order("ORDER1").id == "ORDER1"
    )  # the 401 refresh, then one retry after the 500
    assert route.call_count == 3


def test_a_second_401_is_an_auth_error(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(401, json={"name": "AUTHENTICATION_FAILURE", "message": "no"})
    )
    with pytest.raises(E.PayPalAuthError) as exc:
        pp.get_order("ORDER1")
    assert exc.value.status == 401
    assert sum(c.request.url.path == "/v1/oauth2/token" for c in paypal.calls) == 2


def test_the_token_endpoint_refusing_is_an_auth_error_without_credentials(
    respx_mock: respx.MockRouter, pp: PayPalClient
) -> None:
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(
        return_value=httpx.Response(
            401,
            json={"error": "invalid_client", "error_description": "Client Authentication failed"},
        )
    )
    with pytest.raises(E.PayPalAuthError) as exc:
        pp.get_order("ORDER1")
    assert exc.value.name == "invalid_client"
    assert CLIENT_ID not in str(exc.value) and SECRET not in str(exc.value)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"access_token": "", "token_type": "Bearer", "expires_in": 10},
        {"access_token": 5, "token_type": "Bearer", "expires_in": 10},
        {"access_token": "t", "token_type": "Bearer"},
        {"access_token": "t", "token_type": "Bearer", "expires_in": "10"},
        {"access_token": "t", "token_type": "Bearer", "expires_in": 0},
        {"access_token": "t", "token_type": "Bearer", "expires_in": -5},
        {"access_token": "t", "token_type": "Bearer", "expires_in": 1.5},
        {"access_token": "t", "token_type": "Basic", "expires_in": 10},
        {"access_token": "t", "expires_in": 10},
    ],
)
def test_a_bad_token_response_is_refused(
    respx_mock: respx.MockRouter, pp: PayPalClient, body: dict[str, Any]
) -> None:
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(return_value=httpx.Response(200, json=body))
    with pytest.raises(E.PayPalResponseError):
        pp.get_order("ORDER1")


def test_token_requests_are_retried_on_server_errors(
    respx_mock: respx.MockRouter, pp: PayPalClient
) -> None:
    route = respx_mock.post(f"{BASE}/v1/oauth2/token")
    route.side_effect = [httpx.Response(503), token_response()]
    respx_mock.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=order_json())
    )
    pp.get_order("ORDER1")
    assert route.call_count == 2


# =============================================================== reads


def test_get_order_parses_a_typed_order(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json={**order_json("COMPLETED"), "future_field": {"a": 1}})
    )
    order = pp.get_order("ORDER1")
    unit = order.purchase_units[0]
    assert (order.id, order.status, order.intent) == ("ORDER1", "COMPLETED", "AUTHORIZE")
    assert unit.amount == Money(USD, 7400) and unit.invoice_id == CHECKOUT
    assert unit.breakdown is not None and unit.breakdown.item_total == Money(USD, 6850)
    assert unit.items[0].unit_amount == Money(USD, 2500) and unit.payee is not None
    assert unit.payee.merchant_id == "MERCHANT123"
    assert order.authorizations == () and order.captures == ()


def test_get_order_exposes_embedded_payments(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    body = order_json("COMPLETED")
    body["purchase_units"][0]["payments"] = {
        "authorizations": [auth_json("AUTH1")],
        "captures": [capture_json("CAP1")],
    }
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=body)
    )
    order = pp.get_order("ORDER1")
    assert order.authorizations[0].id == "AUTH1" and order.captures[0].id == "CAP1"


@pytest.mark.parametrize("missing", ["id", "status", "intent", "purchase_units"])
def test_get_order_fails_on_a_missing_required_field(
    paypal: respx.MockRouter, pp: PayPalClient, missing: str
) -> None:
    body = order_json()
    del body[missing]
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=body)
    )
    with pytest.raises(E.PayPalResponseError, match=missing):
        pp.get_order("ORDER1")


def test_get_order_fails_on_a_missing_amount_or_empty_units(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    body = order_json()
    del body["purchase_units"][0]["amount"]
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=body)
    )
    with pytest.raises(E.PayPalResponseError):
        pp.get_order("ORDER1")
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json={**order_json(), "purchase_units": []})
    )
    with pytest.raises(E.PayPalResponseError):
        pp.get_order("ORDER1")


@pytest.mark.parametrize(
    "amount",
    [
        {"currency_code": "USD", "value": 74.0},
        {"currency_code": "USD", "value": "74.001"},
        {"currency_code": "USD", "value": "-1.00"},
        {"currency_code": "USD", "value": "1e2"},
        {"currency_code": "USD", "value": ".5"},
        {"currency_code": "XXX", "value": "1.00"},
        {"currency_code": "USD"},
        {"value": "1.00"},
        "74.00",
        None,
        {"currency_code": "JPY", "value": "10.5"},
    ],
)
def test_amounts_that_are_not_exact_decimals_are_refused(
    paypal: respx.MockRouter, pp: PayPalClient, amount: Any
) -> None:
    body = order_json()
    body["purchase_units"][0]["amount"] = amount
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=body)
    )
    with pytest.raises(E.PayPalResponseError):
        pp.get_order("ORDER1")


def test_error_text_from_parsing_never_includes_the_values(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    body = order_json()
    body["purchase_units"][0]["amount"] = {"currency_code": "USD", "value": "SECRET-ACCOUNT-DATA"}
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=body)
    )
    with pytest.raises(E.PayPalResponseError) as exc:
        pp.get_order("ORDER1")
    assert "SECRET-ACCOUNT-DATA" not in str(exc.value)


def test_get_authorization_and_capture(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.get(f"{BASE}/v2/payments/authorizations/AUTH1").mock(
        return_value=httpx.Response(200, json=auth_json(extra_unknown=1))
    )
    paypal.get(f"{BASE}/v2/payments/captures/CAP1").mock(
        return_value=httpx.Response(200, json=capture_json())
    )
    auth = pp.get_authorization("AUTH1")
    assert auth.amount == Money(USD, 7400) and auth.status == "CREATED"
    assert auth.expiration_time == datetime(2026, 11, 20, 10, 0, tzinfo=UTC)
    assert auth.invoice_id == CHECKOUT and auth.custom_id == "cs1.x"
    cap = pp.get_capture("CAP1")
    assert cap.final_capture is True and cap.amount == Money(USD, 7400)


@pytest.mark.parametrize("missing", ["id", "status", "amount", "expiration_time"])
def test_authorization_requires_its_fields(
    paypal: respx.MockRouter, pp: PayPalClient, missing: str
) -> None:
    body = auth_json()
    del body[missing]
    paypal.get(f"{BASE}/v2/payments/authorizations/AUTH1").mock(
        return_value=httpx.Response(200, json=body)
    )
    with pytest.raises(E.PayPalResponseError, match=missing):
        pp.get_authorization("AUTH1")


@pytest.mark.parametrize("missing", ["id", "status", "amount", "final_capture"])
def test_capture_requires_its_fields(
    paypal: respx.MockRouter, pp: PayPalClient, missing: str
) -> None:
    body = capture_json()
    del body[missing]
    paypal.get(f"{BASE}/v2/payments/captures/CAP1").mock(
        return_value=httpx.Response(200, json=body)
    )
    with pytest.raises(E.PayPalResponseError, match=missing):
        pp.get_capture("CAP1")


@pytest.mark.parametrize("body", [[], "x", None, 5])
def test_a_response_that_is_not_an_object_is_refused(
    paypal: respx.MockRouter, pp: PayPalClient, body: Any
) -> None:
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=body)
    )
    with pytest.raises(E.PayPalResponseError):
        pp.get_order("ORDER1")


def test_a_non_json_success_body_is_refused(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, text="<html>")
    )
    with pytest.raises(E.PayPalResponseError):
        pp.get_order("ORDER1")


@pytest.mark.parametrize("ident", ["", "a/b", "../x", "A B", "A?x=1", "A" * 65, "a.b", "é"])
def test_ids_that_would_change_the_path_are_refused_before_sending(
    paypal: respx.MockRouter, pp: PayPalClient, ident: str
) -> None:
    for call in (pp.get_order, pp.get_authorization, pp.get_capture):
        with pytest.raises(LimitError):
            call(ident)
    with pytest.raises(LimitError):
        pp.authorize_order(CHECKOUT, ident)
    with pytest.raises(LimitError):
        pp.void_authorization(CHECKOUT, ident)
    with pytest.raises(LimitError):
        pp.refund_capture(CHECKOUT, ident, refund_key=RK)
    assert paypal.calls.call_count == 0


# =============================================================== create order


def test_create_order_sends_the_exact_request(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    approve = "https://www.sandbox.paypal.com/checkoutnow?token=ORDER1"
    paypal.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": "ORDER1",
                "status": "PAYER_ACTION_REQUIRED",
                "links": [
                    {"rel": "self", "href": "https://x/self"},
                    {"rel": "payer-action", "href": approve},
                ],
            },
        )
    )
    result = pp.create_order(CHECKOUT, order_request())
    assert isinstance(result, OrderCreated)
    assert (result.resource_id, result.approval_url, result.status_code) == ("ORDER1", approve, 201)
    (request,) = post_calls(paypal)
    assert request.headers["paypal-request-id"] == create_order_request_id(
        CHECKOUT, order_request().to_json()
    )
    assert request.headers["authorization"] == f"Bearer {TOKEN}"
    assert request.headers["prefer"] == "return=representation"
    assert json.loads(request.content) == order_request().to_json()


def test_create_order_200_is_a_normal_success_and_prefers_payer_action(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "ORDER1",
                "links": [
                    {"rel": "approve", "href": "https://approve.example/a"},
                    {"rel": "payer-action", "href": "https://payer.example/p"},
                ],
            },
        )
    )
    result = pp.create_order(CHECKOUT, order_request())
    # The sandbox answered 200 on every create; the status code says nothing about replays.
    assert (result.status_code, result.resource_id) == (200, "ORDER1")
    assert result.approval_url == "https://payer.example/p"
    assert not hasattr(result, "replayed")


@pytest.mark.parametrize(
    "links",
    [
        None,
        [],
        "x",
        [{"rel": "payer-action"}],
        [{"rel": "payer-action", "href": "http://insecure/x"}],
        [5],
    ],
)
def test_create_order_without_a_usable_approval_link(
    paypal: respx.MockRouter, pp: PayPalClient, links: Any
) -> None:
    body: dict[str, Any] = {"id": "ORDER1"}
    if links is not None:
        body["links"] = links
    paypal.post(f"{BASE}/v2/checkout/orders").mock(return_value=httpx.Response(201, json=body))
    assert pp.create_order(CHECKOUT, order_request()).approval_url is None


@pytest.mark.parametrize("body", [{}, {"id": ""}, {"id": 5}, {"id": "a/b"}, []])
def test_create_order_requires_an_id(paypal: respx.MockRouter, pp: PayPalClient, body: Any) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders").mock(return_value=httpx.Response(201, json=body))
    with pytest.raises((E.PayPalResponseError, LimitError)):
        pp.create_order(CHECKOUT, order_request())


def test_create_order_rejects_other_success_codes(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(202, json={"id": "ORDER1"})
    )
    with pytest.raises(E.PayPalRequestError):
        pp.create_order(CHECKOUT, order_request())


def test_create_order_invalid_string_length(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(
            400,
            headers={"paypal-debug-id": "dbg1"},
            json={
                "name": "INVALID_REQUEST",
                "details": [{"issue": "INVALID_STRING_LENGTH", "field": "/x"}],
            },
        )
    )
    with pytest.raises(E.InvalidStringLength) as exc:
        pp.create_order(CHECKOUT, order_request())
    assert exc.value.status == 400 and exc.value.debug_id == "dbg1"


# =============================================================== authorize


def test_authorize_posts_without_reading_the_response(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        return_value=httpx.Response(201, content=b"not even json")
    )
    result = pp.authorize_order(CHECKOUT, "ORDER1")
    assert result == Mutation("ORDER1", 201, None)
    (request,) = post_calls(paypal)
    assert request.headers["paypal-request-id"] == authorize_request_id(CHECKOUT, "ORDER1")
    assert request.content == b"{}"


def test_authorize_200_is_a_normal_success(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        return_value=httpx.Response(200, headers={"paypal-debug-id": "d1"}, json={})
    )
    result = pp.authorize_order(CHECKOUT, "ORDER1")
    assert result.status_code == 200 and result.debug_id == "d1"
    assert not hasattr(result, "replayed")


# =============================================================== capture


def capture_routes(
    router: respx.MockRouter, *, authorization: dict[str, Any] | None = None, status: int = 201
) -> respx.Route:
    router.get(f"{BASE}/v2/payments/authorizations/AUTH1").mock(
        return_value=httpx.Response(200, json=authorization or auth_json())
    )
    return router.post(f"{BASE}/v2/payments/authorizations/AUTH1/capture").mock(
        return_value=httpx.Response(status, json=capture_json())
    )


def test_capture_fetches_first_then_sends_the_full_amount_with_final_capture(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    route = capture_routes(paypal)
    result = pp.capture_authorization(approval(7400))
    assert result == Mutation("CAP1", 201, None)
    methods = [(c.request.method, c.request.url.path) for c in paypal.calls]
    assert methods == [
        ("POST", "/v1/oauth2/token"),
        ("GET", "/v2/payments/authorizations/AUTH1"),
        ("POST", "/v2/payments/authorizations/AUTH1/capture"),
    ]
    request = route.calls[0].request
    assert json.loads(request.content) == {"amount": money("74.00"), "final_capture": True}
    assert request.headers["paypal-request-id"] == capture_request_id(
        CHECKOUT, "AUTH1", Money(USD, 7400), CHECKOUT, CUSTOM
    )


def test_capture_has_no_way_to_choose_an_amount_or_partial() -> None:
    parameters = inspect.signature(PayPalClient.capture_authorization).parameters
    assert set(parameters) == {"self", "approval"}
    for name in ("amount", "final_capture", "partial"):
        assert name not in parameters
    public = {n for n in dir(PayPalClient) if not n.startswith("_")}
    assert not {n for n in public if "partial" in n}


def test_capture_sends_the_fetched_amount_not_a_caller_amount(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    route = capture_routes(paypal, authorization=auth_json(amount="19.99"))
    pp.capture_authorization(approval(1999))
    assert json.loads(route.calls[0].request.content)["amount"] == money("19.99")


@pytest.mark.parametrize(
    "override",
    [
        {"invoice_id": "chk_ZZZZZZZZZZZZZZZZZZZZZZ"},  # another checkout's authorization
        {"invoice_id": None},
        {"invoice_id": ""},
        {"custom_id": "cs1.other"},
        {"custom_id": None},
        {"custom_id": ""},
        {"id": "AUTH2"},
    ],
)
def test_capture_refuses_an_authorization_that_is_not_the_approved_one(
    paypal: respx.MockRouter, pp: PayPalClient, override: dict[str, Any]
) -> None:
    body = auth_json()
    body.update(override)
    if body.get("invoice_id", "x") is None:
        del body["invoice_id"]
    if body.get("custom_id", "x") is None:
        del body["custom_id"]
    route = capture_routes(paypal, authorization=body)
    with pytest.raises(E.AuthorizationMismatch):
        pp.capture_authorization(approval(7400))
    assert route.call_count == 0


def test_capture_is_for_the_approved_checkout_whatever_the_amount_matches(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    """Checkout B's authorization for the same total must not be captured as checkout A."""
    route = capture_routes(paypal, authorization=auth_json(invoice_id="chk_B_bbbbbbbbbbbbbbbbbbbb"))
    with pytest.raises(E.AuthorizationMismatch, match="invoice_id"):
        pp.capture_authorization(approval(7400, checkout_id=CHECKOUT))
    assert route.call_count == 0


@pytest.mark.parametrize("bad", [None, "AUTH1", {"checkout_id": CHECKOUT}, (CHECKOUT, "AUTH1")])
def test_capture_takes_only_a_capture_approval(
    paypal: respx.MockRouter, pp: PayPalClient, bad: Any
) -> None:
    route = capture_routes(paypal)
    with pytest.raises(TypeError):
        pp.capture_authorization(bad)
    assert paypal.calls.call_count == 0 and route.call_count == 0


@pytest.mark.parametrize(
    "status",
    ["PARTIALLY_CAPTURED", "CAPTURED", "VOIDED", "PENDING", "DENIED", "EXPIRED", "created", ""],
)
def test_capture_refuses_any_status_but_created_without_sending(
    paypal: respx.MockRouter, pp: PayPalClient, status: str
) -> None:
    route = capture_routes(paypal, authorization=auth_json(status=status))
    with pytest.raises(E.AuthorizationNotCapturable, match="status"):
        pp.capture_authorization(approval(7400))
    assert route.call_count == 0


@pytest.mark.parametrize("amount", ["74.01", "73.99", "0.01", "740.00"])
def test_capture_refuses_an_amount_that_is_not_the_expected_total(
    paypal: respx.MockRouter, pp: PayPalClient, amount: str
) -> None:
    route = capture_routes(paypal, authorization=auth_json(amount=amount))
    with pytest.raises(E.AmountMismatch):
        pp.capture_authorization(approval(7400))
    assert route.call_count == 0


def test_capture_refuses_a_different_currency(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    body = auth_json()
    body["amount"] = money("74.00", "EUR")
    route = capture_routes(paypal, authorization=body)
    with pytest.raises(E.AmountMismatch):
        pp.capture_authorization(approval(7400))
    assert route.call_count == 0


def test_capture_refuses_an_expired_authorization_by_expiration_time(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    for exp in ("2026-10-24T12:00:00Z", "2026-10-24T11:59:59Z", "2020-01-01T00:00:00Z"):
        route = capture_routes(paypal, authorization=auth_json(expiration_time=exp))
        with pytest.raises(E.AuthorizationNotCapturable, match="expired"):
            pp.capture_authorization(approval(7400))
        assert route.call_count == 0
    route = capture_routes(paypal, authorization=auth_json(expiration_time="2026-10-24T12:01:01Z"))
    pp.capture_authorization(approval(7400))
    assert route.call_count == 1


@pytest.mark.parametrize(
    ("expiration", "capturable"),
    [
        ("2026-10-24T12:01:01Z", True),  # one second beyond the 60 second skew
        ("2026-10-24T12:01:00Z", False),  # exactly the skew away: counts as expired
        ("2026-10-24T12:00:59Z", False),  # inside the skew, though not yet expired
        ("2026-10-24T12:00:01Z", False),
    ],
)
def test_capture_treats_an_authorization_within_the_clock_skew_as_expired(
    paypal: respx.MockRouter, pp: PayPalClient, expiration: str, capturable: bool
) -> None:
    route = capture_routes(paypal, authorization=auth_json(expiration_time=expiration))
    if capturable:
        pp.capture_authorization(approval(7400))
        assert route.call_count == 1
    else:
        with pytest.raises(E.AuthorizationNotCapturable, match="clock skew"):
            pp.capture_authorization(approval(7400))
        assert route.call_count == 0


def test_the_expiry_skew_is_configurable_and_never_negative(
    paypal: respx.MockRouter, clock: Clock
) -> None:
    route = capture_routes(paypal, authorization=auth_json(expiration_time="2026-10-24T12:00:30Z"))
    pp = make_client(clock, authorization_expiry_skew_s=0.0)
    pp.capture_authorization(approval(7400))
    assert route.call_count == 1
    with pytest.raises(E.PayPalConfigError):
        PayPalConfig(client_id=CLIENT_ID, client_secret=SECRET, authorization_expiry_skew_s=-1)


def test_capture_refuses_an_expiration_time_without_a_zone(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    route = capture_routes(paypal, authorization=auth_json(expiration_time="2030-01-01T00:00:00"))
    with pytest.raises(E.PayPalResponseError, match="time zone"):
        pp.capture_authorization(approval(7400))
    assert route.call_count == 0


@pytest.mark.parametrize(
    ("issue", "exc"),
    [
        ("MAX_CAPTURE_AMOUNT_EXCEEDED", E.MaxCaptureAmountExceeded),
        ("AUTHORIZATION_ALREADY_CAPTURED", E.AuthorizationAlreadyCaptured),
        ("AUTHORIZATION_VOIDED", E.AuthorizationVoided),
        ("AUTHORIZATION_EXPIRED", E.AuthorizationExpired),
    ],
)
def test_capture_errors_are_mapped(
    paypal: respx.MockRouter, pp: PayPalClient, issue: str, exc: type
) -> None:
    route = capture_routes(paypal)
    route.mock(return_value=httpx.Response(422, json={"name": issue, "message": "no"}))
    with pytest.raises(exc):
        pp.capture_authorization(approval(7400))
    assert route.call_count == 1  # a 422 is not retried


# =============================================================== void


@pytest.mark.parametrize("status", [200, 204])
def test_void(paypal: respx.MockRouter, pp: PayPalClient, status: int) -> None:
    paypal.post(f"{BASE}/v2/payments/authorizations/AUTH1/void").mock(
        return_value=httpx.Response(status)
    )
    result = pp.void_authorization(CHECKOUT, "AUTH1")
    assert result == Mutation("AUTH1", status, None)
    (request,) = post_calls(paypal)
    assert request.headers["paypal-request-id"] == void_request_id(CHECKOUT, "AUTH1")
    assert request.content == b""


@pytest.mark.parametrize(
    ("issue", "exc"),
    [("PREVIOUSLY_CAPTURED", E.PreviouslyCaptured), ("PREVIOUSLY_VOIDED", E.PreviouslyVoided)],
)
def test_void_errors(paypal: respx.MockRouter, pp: PayPalClient, issue: str, exc: type) -> None:
    paypal.post(f"{BASE}/v2/payments/authorizations/AUTH1/void").mock(
        return_value=httpx.Response(
            422, json={"name": "UNPROCESSABLE_ENTITY", "details": [{"issue": issue}]}
        )
    )
    with pytest.raises(exc):
        pp.void_authorization(CHECKOUT, "AUTH1")


def test_void_with_an_unexpected_success_code(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.post(f"{BASE}/v2/payments/authorizations/AUTH1/void").mock(
        return_value=httpx.Response(201)
    )
    with pytest.raises(E.PayPalRequestError):
        pp.void_authorization(CHECKOUT, "AUTH1")


# =============================================================== refund


def test_full_refund_sends_an_empty_json_object(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.post(f"{BASE}/v2/payments/captures/CAP1/refund").mock(
        return_value=httpx.Response(201, json={"id": "REF1", "status": "COMPLETED"})
    )
    result = pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK)
    assert result.resource_id == "REF1" and result.status_code == 201
    (request,) = post_calls(paypal)
    assert request.content == b"{}" and request.headers["content-type"] == "application/json"
    assert request.headers["paypal-request-id"] == derive_request_id(
        CHECKOUT, Operation.REFUND, "CAP1", "full", RK
    )


def test_partial_refund_sends_the_amount_and_a_distinct_request_id(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(f"{BASE}/v2/payments/captures/CAP1/refund").mock(
        return_value=httpx.Response(201, json={"id": "REF1"})
    )
    pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK, amount=Money(USD, 1000))
    pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK, amount=Money(USD, 1000))
    pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK, amount=Money(USD, 2000))
    first, same, other = post_calls(paypal)
    assert json.loads(first.content) == {"amount": money("10.00")}
    ids = [r.headers["paypal-request-id"] for r in (first, same, other)]
    assert ids[0] == ids[1] != ids[2]
    assert ids[0] == derive_request_id(CHECKOUT, Operation.REFUND, "CAP1", "USD:10.00", RK)


def test_two_equal_partial_refunds_with_different_keys_do_not_collide(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(f"{BASE}/v2/payments/captures/CAP1/refund").mock(
        return_value=httpx.Response(201, json={"id": "REF1"})
    )
    pp.refund_capture(CHECKOUT, "CAP1", refund_key="first", amount=Money(USD, 1000))
    pp.refund_capture(CHECKOUT, "CAP1", refund_key="second", amount=Money(USD, 1000))
    pp.refund_capture(CHECKOUT, "CAP1", refund_key="first", amount=Money(USD, 1000))  # a retry
    one, two, retry = (r.headers["paypal-request-id"] for r in post_calls(paypal))
    assert one != two
    assert one == retry
    assert one == derive_request_id(CHECKOUT, Operation.REFUND, "CAP1", "USD:10.00", "first")


def test_a_full_refund_key_also_distinguishes_requests(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(f"{BASE}/v2/payments/captures/CAP1/refund").mock(
        return_value=httpx.Response(201, json={"id": "REF1"})
    )
    pp.refund_capture(CHECKOUT, "CAP1", refund_key="a")
    pp.refund_capture(CHECKOUT, "CAP1", refund_key="b")
    a, b = (r.headers["paypal-request-id"] for r in post_calls(paypal))
    assert a != b


@pytest.mark.parametrize("bad", ["", "x" * 65, "a b", "a/b", "a.b", "k\n", None, 5, b"k"])
def test_a_refund_key_must_be_a_short_plain_token(
    paypal: respx.MockRouter, pp: PayPalClient, bad: Any
) -> None:
    with pytest.raises(LimitError):
        pp.refund_capture(CHECKOUT, "CAP1", refund_key=bad)
    assert paypal.calls.call_count == 0


def test_a_refund_needs_a_key() -> None:
    assert inspect.signature(PayPalClient.refund_capture).parameters["refund_key"].default is (
        inspect.Parameter.empty
    )


@pytest.mark.parametrize("minor", [0, -100])
def test_refund_amount_must_be_positive(
    paypal: respx.MockRouter, pp: PayPalClient, minor: int
) -> None:
    with pytest.raises(LimitError):
        pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK, amount=Money(USD, minor))
    assert paypal.calls.call_count == 0


@pytest.mark.parametrize(
    ("issue", "exc"),
    [
        ("REFUND_AMOUNT_EXCEEDED", E.RefundAmountExceeded),
        ("CAPTURE_FULLY_REFUNDED", E.CaptureFullyRefunded),
        ("TRANSACTION_DISPUTED", E.TransactionDisputed),
    ],
)
def test_refund_errors(paypal: respx.MockRouter, pp: PayPalClient, issue: str, exc: type) -> None:
    paypal.post(f"{BASE}/v2/payments/captures/CAP1/refund").mock(
        return_value=httpx.Response(422, json={"name": issue, "message": "no"})
    )
    with pytest.raises(exc):
        pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK)


def test_refund_without_an_id_in_the_response(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    paypal.post(f"{BASE}/v2/payments/captures/CAP1/refund").mock(
        return_value=httpx.Response(201, json={"status": "x"})
    )
    with pytest.raises(E.PayPalResponseError):
        pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK)


# =============================================================== error mapping

NAMED = {
    "INVALID_STRING_LENGTH": E.InvalidStringLength,
    "ORDER_NOT_APPROVED": E.OrderNotApproved,
    "ORDER_ALREADY_AUTHORIZED": E.OrderAlreadyAuthorized,
    "ORDER_ALREADY_COMPLETED": E.OrderAlreadyCompleted,
    "MAX_CAPTURE_AMOUNT_EXCEEDED": E.MaxCaptureAmountExceeded,
    "AUTHORIZATION_ALREADY_CAPTURED": E.AuthorizationAlreadyCaptured,
    "AUTHORIZATION_VOIDED": E.AuthorizationVoided,
    "AUTHORIZATION_EXPIRED": E.AuthorizationExpired,
    "PREVIOUSLY_CAPTURED": E.PreviouslyCaptured,
    "PREVIOUSLY_VOIDED": E.PreviouslyVoided,
    "REFUND_AMOUNT_EXCEEDED": E.RefundAmountExceeded,
    "CAPTURE_FULLY_REFUNDED": E.CaptureFullyRefunded,
    "TRANSACTION_DISPUTED": E.TransactionDisputed,
    "PREVIOUS_REQUEST_IN_PROGRESS": E.PreviousRequestInProgress,
}


def response(status: int, body: Any, **headers: str) -> httpx.Response:
    return httpx.Response(status, json=body, headers=headers)


def test_the_table_covers_every_recorded_code() -> None:
    assert set(E.ERROR_CODES) == set(NAMED)
    for code, cls in NAMED.items():
        assert E.ERROR_CODES[code] is cls


@pytest.mark.parametrize(("code", "cls"), list(NAMED.items()))
def test_each_code_maps_by_name_and_by_issue(code: str, cls: type) -> None:
    by_name = E.map_error(response(422, {"name": code, "message": "m", "debug_id": "d1"}))
    by_issue = E.map_error(
        response(
            422, {"name": "UNPROCESSABLE_ENTITY", "details": [{"issue": "OTHER"}, {"issue": code}]}
        )
    )
    assert type(by_name) is cls and type(by_issue) is cls
    assert by_name.status == 422 and by_name.debug_id == "d1" and by_name.name == code
    assert isinstance(by_name, E.PayPalRequestError)


def test_the_name_wins_over_an_issue_when_both_are_known() -> None:
    body = {"name": "PREVIOUSLY_VOIDED", "details": [{"issue": "PREVIOUSLY_CAPTURED"}]}
    assert type(E.map_error(response(422, body))) is E.PreviouslyVoided
    body = {
        "name": "UNPROCESSABLE_ENTITY",
        "details": [{"issue": "PREVIOUSLY_CAPTURED"}, {"issue": "PREVIOUSLY_VOIDED"}],
    }
    assert type(E.map_error(response(422, body))) is E.PreviouslyCaptured  # the first known issue


def test_oauth_style_error_bodies_are_read() -> None:
    error = E.map_error(
        response(
            401, {"error": "invalid_client", "error_description": "Client Authentication failed"}
        )
    )
    assert error.name == "invalid_client" and "Client Authentication failed" in str(error)
    assert type(error) is E.PayPalAuthError


def test_error_codes_map_whatever_the_http_status_but_5xx() -> None:
    for status in (400, 404, 409, 422):
        assert (
            type(E.map_error(response(status, {"name": "ORDER_NOT_APPROVED"})))
            is E.OrderNotApproved
        )
    assert type(E.map_error(response(500, {"name": "ORDER_NOT_APPROVED"}))) is E.PayPalServerError


@pytest.mark.parametrize(
    ("status", "body", "cls"),
    [
        (500, {"name": "INTERNAL_SERVICE_ERROR"}, E.PayPalServerError),
        (503, {}, E.PayPalServerError),
        (401, {"name": "AUTHENTICATION_FAILURE"}, E.PayPalAuthError),
        (404, {"name": "RESOURCE_NOT_FOUND"}, E.PayPalNotFound),
        (409, {"name": "SOMETHING_ELSE"}, E.PayPalConflict),
        (400, {"name": "INVALID_REQUEST"}, E.PayPalRequestError),
        (
            422,
            {"name": "UNPROCESSABLE_ENTITY", "details": [{"issue": "UNKNOWN"}]},
            E.PayPalRequestError,
        ),
        (400, {}, E.PayPalRequestError),
    ],
)
def test_unlisted_errors_fall_back_by_status(status: int, body: dict[str, Any], cls: type) -> None:
    error = E.map_error(response(status, body))
    assert type(error) is cls and error.status == status


def test_mapping_tolerates_malformed_bodies() -> None:
    for resp in (
        httpx.Response(422, text="<html>nope</html>"),
        httpx.Response(422, json=[1, 2]),
        httpx.Response(422, json={"name": 5, "details": "x"}),
        httpx.Response(422, json={"details": [5, {"issue": 7}, {}]}),
    ):
        error = E.map_error(resp)
        assert type(error) is E.PayPalRequestError and error.issues == ()


def test_debug_id_prefers_the_header_then_the_body() -> None:
    assert (
        E.map_error(response(400, {"debug_id": "body"}, **{"paypal-debug-id": "head"})).debug_id
        == "head"
    )
    assert E.map_error(response(400, {"debug_id": "body"})).debug_id == "body"
    assert E.map_error(response(400, {})).debug_id is None


def test_the_issue_codes_and_a_missing_message_are_kept() -> None:
    error = E.map_error(
        response(422, {"name": "UNPROCESSABLE_ENTITY", "details": [{"issue": "A"}, {"issue": "B"}]})
    )
    assert (
        error.issues == ("A", "B") and "issues=A,B" in str(error) and "PayPal error" in str(error)
    )


def test_outcome_unknown_is_set_for_mutating_server_errors_and_in_progress() -> None:
    assert E.map_error(response(500, {}), mutating=True).outcome_unknown is True
    assert E.map_error(response(500, {}), mutating=False).outcome_unknown is False
    assert (
        E.map_error(response(422, {"name": "PREVIOUSLY_VOIDED"}), mutating=True).outcome_unknown
        is False
    )


# =============================================================== retries


def test_5xx_on_a_create_is_retried_with_the_same_request_id(
    paypal: respx.MockRouter, pp: PayPalClient, clock: Clock
) -> None:
    route = paypal.post(f"{BASE}/v2/checkout/orders")
    route.side_effect = [
        httpx.Response(500, json={"name": "INTERNAL_SERVICE_ERROR"}),
        httpx.Response(503),
        httpx.Response(201, json={"id": "ORDER1"}),
    ]
    assert pp.create_order(CHECKOUT, order_request()).resource_id == "ORDER1"
    ids = {c.request.headers["paypal-request-id"] for c in route.calls}
    assert len(route.calls) == 3 and ids == {
        create_order_request_id(CHECKOUT, order_request().to_json())
    }
    assert clock.sleeps == [0.5, 1.0]


@pytest.mark.parametrize(
    ("call", "success"),
    [
        (lambda pp: pp.create_order(CHECKOUT, order_request()), 201),
        (lambda pp: pp.authorize_order(CHECKOUT, "ORDER1"), 201),
        (lambda pp: pp.void_authorization(CHECKOUT, "AUTH1"), 200),
        (lambda pp: pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK), 201),
    ],
)
def test_every_state_changing_retry_reuses_one_request_id(
    paypal: respx.MockRouter, pp: PayPalClient, call: Callable[[PayPalClient], Any], success: int
) -> None:
    router = paypal.route(method="POST", path__regex=r"^/v2/.*")
    router.side_effect = [
        httpx.Response(502),
        httpx.Response(504),
        httpx.Response(success, json={"id": "X1"}),
    ]
    call(pp)
    ids = [c.request.headers.get("paypal-request-id") for c in router.calls]
    assert len(ids) == 3 and ids[0] and len(set(ids)) == 1


def test_capture_retry_reuses_the_request_id_and_does_not_refetch(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    route = capture_routes(paypal)
    route.side_effect = [httpx.Response(500), httpx.Response(201, json=capture_json())]
    pp.capture_authorization(approval(7400))
    assert len(route.calls) == 2
    assert len({c.request.headers["paypal-request-id"] for c in route.calls}) == 1
    gets = [c for c in paypal.calls if c.request.method == "GET"]
    assert len(gets) == 1


def test_reads_are_retried_too(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    route = paypal.get(f"{BASE}/v2/checkout/orders/ORDER1")
    route.side_effect = [httpx.Response(500), httpx.Response(200, json=order_json())]
    assert pp.get_order("ORDER1").id == "ORDER1"


def test_exhausted_5xx_on_a_state_change_is_outcome_unknown(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    route = paypal.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(500, json={"name": "INTERNAL_SERVICE_ERROR"})
    )
    with pytest.raises(E.PayPalServerError) as exc:
        pp.create_order(CHECKOUT, order_request())
    assert route.call_count == 3 and exc.value.outcome_unknown is True


def test_exhausted_5xx_on_a_read_is_not_outcome_unknown(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(return_value=httpx.Response(503))
    with pytest.raises(E.PayPalServerError) as exc:
        pp.get_order("ORDER1")
    assert exc.value.outcome_unknown is False


@pytest.mark.parametrize(
    "failure", [httpx.ReadTimeout("t"), httpx.ConnectTimeout("t"), httpx.WriteTimeout("t")]
)
def test_timeouts_are_retried_with_the_same_request_id(
    paypal: respx.MockRouter, pp: PayPalClient, failure: Exception
) -> None:
    route = paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize")
    route.side_effect = [failure, httpx.Response(201, json={})]
    assert pp.authorize_order(CHECKOUT, "ORDER1").status_code == 201
    assert (
        len({c.request.headers["paypal-request-id"] for c in route.calls}) == 1
        and len(route.calls) == 2
    )


def test_exhausted_timeouts_are_outcome_unknown_for_state_changes_only(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        side_effect=httpx.ReadTimeout("t")
    )
    with pytest.raises(E.PayPalTimeout) as exc:
        pp.authorize_order(CHECKOUT, "ORDER1")
    assert exc.value.outcome_unknown is True
    paypal.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(side_effect=httpx.ReadTimeout("t"))
    with pytest.raises(E.PayPalTimeout) as exc2:
        pp.get_order("ORDER1")
    assert exc2.value.outcome_unknown is False


def test_connection_errors_are_retried_then_reported(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    route = paypal.post(f"{BASE}/v2/payments/authorizations/AUTH1/void")
    route.side_effect = [httpx.ConnectError("c"), httpx.Response(200)]
    pp.void_authorization(CHECKOUT, "AUTH1")
    route.side_effect = httpx.ConnectError("c")
    with pytest.raises(E.PayPalTransportError) as exc:
        pp.void_authorization(CHECKOUT, "AUTH1")
    assert exc.value.outcome_unknown is True


def test_409_in_progress_is_retried_then_outcome_unknown(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    body = {"name": "PREVIOUS_REQUEST_IN_PROGRESS", "message": "busy"}
    route = capture_routes(paypal)
    route.side_effect = [httpx.Response(409, json=body), httpx.Response(201, json=capture_json())]
    pp.capture_authorization(approval(7400))
    assert route.call_count == 2
    route.side_effect = None
    route.mock(return_value=httpx.Response(409, json=body))
    with pytest.raises(E.PreviousRequestInProgress) as exc:
        pp.capture_authorization(approval(7400))
    assert exc.value.outcome_unknown is True


def test_a_409_that_is_not_in_progress_is_not_retried(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    route = paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        return_value=httpx.Response(409, json={"name": "RESOURCE_CONFLICT"})
    )
    with pytest.raises(E.PayPalConflict):
        pp.authorize_order(CHECKOUT, "ORDER1")
    assert route.call_count == 1


@pytest.mark.parametrize("status", [400, 403, 404, 422])
def test_client_errors_are_not_retried(
    paypal: respx.MockRouter, pp: PayPalClient, status: int
) -> None:
    route = paypal.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(status, json={"name": "X"})
    )
    with pytest.raises(E.PayPalRequestError):
        pp.create_order(CHECKOUT, order_request())
    assert route.call_count == 1


def test_attempts_are_configurable(paypal: respx.MockRouter, clock: Clock) -> None:
    one = make_client(clock, max_attempts=1)
    route = paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        return_value=httpx.Response(500)
    )
    with pytest.raises(E.PayPalServerError):
        one.authorize_order(CHECKOUT, "ORDER1")
    assert route.call_count == 1
    five = make_client(clock, max_attempts=5, backoff_s=1.0)
    clock.sleeps.clear()
    route.mock(return_value=httpx.Response(500))
    route.reset()
    with pytest.raises(E.PayPalServerError):
        five.authorize_order(CHECKOUT, "ORDER1")
    assert route.call_count == 5 and clock.sleeps == [1.0, 2.0, 4.0, 8.0]


def test_backoff_is_capped(paypal: respx.MockRouter, clock: Clock) -> None:
    client = make_client(clock, max_attempts=5, backoff_s=6.0)
    paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        return_value=httpx.Response(500)
    )
    with pytest.raises(E.PayPalServerError):
        client.authorize_order(CHECKOUT, "ORDER1")
    assert clock.sleeps == [6.0, 8.0, 8.0, 8.0]


def test_redirects_are_not_followed(paypal: respx.MockRouter, pp: PayPalClient) -> None:
    route = paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        return_value=httpx.Response(307, headers={"location": "https://evil.example/steal"})
    )
    evil = paypal.post("https://evil.example/steal").mock(return_value=httpx.Response(201, json={}))
    with pytest.raises(E.PayPalRequestError) as exc:
        pp.authorize_order(CHECKOUT, "ORDER1")
    assert exc.value.status == 307 and route.call_count == 1 and evil.call_count == 0


def test_a_state_changing_call_cannot_be_sent_without_a_request_id(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    with pytest.raises(RuntimeError, match="PayPal-Request-Id"):
        pp._call("POST", "/v2/checkout/orders", op="x", ok=(201,), body={})
    with pytest.raises(RuntimeError):
        pp._call("GET", "/v2/checkout/orders/A", op="x", ok=(200,), request_id="cs1.x.y")
    assert paypal.calls.call_count == 0


def test_a_request_id_over_108_characters_is_never_sent(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    for size in (109, 200):
        with pytest.raises(LimitError):
            pp._call(
                "POST", "/v2/checkout/orders", op="x", ok=(201,), body={}, request_id="a" * size
            )
    assert paypal.calls.call_count == 0
    route = paypal.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(201, json={"id": "O1"})
    )
    pp._call("POST", "/v2/checkout/orders", op="x", ok=(201,), body={}, request_id="a" * 108)
    assert route.call_count == 1


def test_the_derived_request_id_is_checked_at_send_time(
    paypal: respx.MockRouter, pp: PayPalClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        return_value=httpx.Response(201, json={})
    )
    monkeypatch.setattr(
        "countersign.paypal.request_id.derive_request_id", lambda *a, **k: "x" * 109
    )
    with pytest.raises(LimitError):
        pp.authorize_order(CHECKOUT, "ORDER1")
    assert paypal.calls.call_count == 0


@pytest.mark.parametrize("bad", ["", "a b", "a\nb", "a/b", "é", "a;b"])
def test_request_id_characters_are_restricted(bad: str) -> None:
    from countersign.paypal.limits import check_request_id

    with pytest.raises(LimitError):
        check_request_id(bad)
    assert check_request_id("a" * 108) == "a" * 108
    assert check_request_id("cs1.capture:x-y_z.0") == "cs1.capture:x-y_z.0"


# =============================================================== secrets


def test_secrets_never_appear_in_logs_errors_or_reprs(
    clock: Clock, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(return_value=token_response())
    respx_mock.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=order_json())
    )
    respx_mock.get(f"{BASE}/v2/checkout/orders/BAD").mock(
        return_value=httpx.Response(500, json={"name": "INTERNAL_SERVICE_ERROR", "message": "oops"})
    )
    respx_mock.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(201, json={"id": "ORDER1"})
    )
    respx_mock.post(f"{BASE}/v2/checkout/orders/T/authorize").mock(
        side_effect=httpx.ReadTimeout("slow")
    )
    respx_mock.post(f"{BASE}/v2/checkout/orders/C/authorize").mock(
        side_effect=httpx.ConnectError("down")
    )
    respx_mock.post(f"{BASE}/v2/payments/authorizations/AUTH1/void").mock(
        return_value=httpx.Response(422, json={"name": "PREVIOUSLY_VOIDED", "message": "again"})
    )
    client = make_client(clock)
    outputs: list[str] = [repr(client), str(client), repr(client._config), str(client._config)]
    with structlog.testing.capture_logs() as logs:
        client.get_order("ORDER1")
        client.create_order(CHECKOUT, order_request())
        for call in (
            lambda: client.get_order("BAD"),
            lambda: client.authorize_order(CHECKOUT, "T"),
            lambda: client.authorize_order(CHECKOUT, "C"),
            lambda: client.void_authorization(CHECKOUT, "AUTH1"),
        ):
            with pytest.raises(E.PayPalError) as exc:
                call()
            outputs += [str(exc.value), repr(exc.value), repr(exc.value.args)]
            outputs.append("".join(traceback.format_exception(exc.value)))
    outputs.append(json.dumps(logs, default=str))
    outputs.append(repr(client._token))
    assert logs, "the client logs its calls"
    text = "\n".join(outputs)
    for secret in (CLIENT_ID, SECRET, TOKEN):
        assert secret not in text
    import base64

    assert base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode() not in text


def test_log_entries_hold_only_the_expected_fields(
    clock: Clock, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(return_value=token_response())
    respx_mock.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=order_json(), headers={"paypal-debug-id": "dbg9"})
    )
    client = make_client(clock)
    with structlog.testing.capture_logs() as logs:
        client.get_order("ORDER1")
    allowed = {"event", "log_level", "op", "path", "status", "attempt", "debug_id", "outcome"}
    assert logs and all(set(entry) <= allowed for entry in logs)
    assert {e["op"] for e in logs} == {"oauth_token", "get_order"}


def test_a_token_in_an_error_body_is_not_echoed_by_the_client_state(
    clock: Clock, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(f"{BASE}/v1/oauth2/token").mock(return_value=token_response())
    respx_mock.get(f"{BASE}/v2/checkout/orders/ORDER1").mock(
        return_value=httpx.Response(200, json=order_json())
    )
    client = make_client(clock)
    client.get_order("ORDER1")
    assert TOKEN not in repr(client.__dict__.get("_token")) and TOKEN not in repr(client)


# ----------------------------------------------- content type and body on every POST


def test_every_post_sends_the_content_type_and_body_paypal_accepted(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    """Pinned to the working smoke and confirmation runs (docs/ENV.md 2.5).

    Authorize with no body and no content type was answered 415 UNSUPPORTED_MEDIA_TYPE, so a POST
    that carries no payload still sends a JSON object. Void is the exception the accepted runs show:
    no body and no content type.
    """
    capture_routes(paypal)
    paypal.post(f"{BASE}/v2/checkout/orders").mock(
        return_value=httpx.Response(201, json={"id": "O1"})
    )
    paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        return_value=httpx.Response(201, json={})
    )
    paypal.post(f"{BASE}/v2/payments/authorizations/AUTH2/void").mock(
        return_value=httpx.Response(204)
    )
    paypal.post(f"{BASE}/v2/payments/captures/CAP1/refund").mock(
        return_value=httpx.Response(201, json={"id": "REF1"})
    )
    pp.create_order(CHECKOUT, order_request())
    pp.authorize_order(CHECKOUT, "ORDER1")
    pp.capture_authorization(approval(7400))
    pp.void_authorization(CHECKOUT, "AUTH2")
    pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK)
    pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK, amount=Money(USD, 1000))

    sent = {(r.url.path, r.content): r.headers.get("content-type") for r in post_calls(paypal)}
    by_path = {}
    for request in post_calls(paypal):
        by_path.setdefault(request.url.path, []).append(request)

    (authorize,) = by_path["/v2/checkout/orders/ORDER1/authorize"]
    assert authorize.headers["content-type"] == "application/json"
    assert authorize.content == b"{}"

    (capture,) = by_path["/v2/payments/authorizations/AUTH1/capture"]
    assert capture.headers["content-type"] == "application/json"
    assert json.loads(capture.content) == {"amount": money("74.00"), "final_capture": True}

    (void,) = by_path["/v2/payments/authorizations/AUTH2/void"]
    assert void.content == b"" and "content-type" not in void.headers

    full, partial = by_path["/v2/payments/captures/CAP1/refund"]
    assert full.headers["content-type"] == "application/json" and full.content == b"{}"
    assert partial.headers["content-type"] == "application/json"
    assert json.loads(partial.content) == {"amount": money("10.00")}

    (create,) = by_path["/v2/checkout/orders"]
    assert create.headers["content-type"] == "application/json"
    assert json.loads(create.content) == order_request().to_json()
    assert all(ct in ("application/json", None) for ct in sent.values())


def test_a_server_that_wants_a_json_body_gets_one(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    """The sandbox's behaviour, reproduced: no content type on an authorize is a 415."""

    def reject_unless_json(request: httpx.Request) -> httpx.Response:
        if request.headers.get("content-type") != "application/json":
            return httpx.Response(
                415,
                json={
                    "name": "UNSUPPORTED_MEDIA_TYPE",
                    "message": "The request payload is not supported",
                },
            )
        return httpx.Response(201, json={"id": "X1"})

    paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(side_effect=reject_unless_json)
    paypal.post(f"{BASE}/v2/payments/captures/CAP1/refund").mock(side_effect=reject_unless_json)
    assert pp.authorize_order(CHECKOUT, "ORDER1").status_code == 201
    assert pp.refund_capture(CHECKOUT, "CAP1", refund_key=RK).status_code == 201


def test_a_415_is_a_request_error_and_is_not_retried(
    paypal: respx.MockRouter, pp: PayPalClient
) -> None:
    route = paypal.post(f"{BASE}/v2/checkout/orders/ORDER1/authorize").mock(
        return_value=httpx.Response(
            415,
            json={
                "name": "UNSUPPORTED_MEDIA_TYPE",
                "message": "The request payload is not supported",
            },
        )
    )
    with pytest.raises(E.PayPalRequestError) as exc:
        pp.authorize_order(CHECKOUT, "ORDER1")
    assert exc.value.status == 415 and exc.value.name == "UNSUPPORTED_MEDIA_TYPE"
    assert route.call_count == 1


def test_the_context_manager_closes_the_client(clock: Clock) -> None:
    with make_client(clock) as client:
        assert isinstance(client, PayPalClient)
    assert client._http.is_closed

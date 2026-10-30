"""`PayPalClient.verify_webhook_signature` and the webhook id setting, against a mocked endpoint.

Shapes follow the request and response in docs/PROTOCOL.md 4.8 (documentation only: no live
verification success has been observed).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.errors import PayPalConfigError, PayPalError, PayPalResponseError

RAW = b'{"id":"WH-1","event_type":"PAYMENT.AUTHORIZATION.VOIDED","resource":{"id":"A1","n":1.50}}'
ARGS: dict[str, Any] = {
    "transmission_id": "tid", "transmission_time": "2026-10-30T10:00:00Z", "transmission_sig": "sig",
    "cert_url": "https://api.sandbox.paypal.com/v1/notifications/certs/C", "auth_algo": "SHA256withRSA",
    "webhook_id": "WH-ID", "raw_event": RAW,
}  # fmt: skip


def client(handler: Any) -> tuple[PayPalClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def route(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(
                200, json={"access_token": "t" * 20, "token_type": "Bearer", "expires_in": 3000}
            )
        seen.append(request)
        return handler(request)

    return (
        PayPalClient(
            PayPalConfig(client_id="id", client_secret="secret"),
            transport=httpx.MockTransport(route),
            sleep=lambda _: None,
        ),
        seen,
    )


def test_success_and_failure_are_booleans_and_the_request_has_the_documented_members() -> None:
    for status, expected in (("SUCCESS", True), ("FAILURE", False)):
        paypal, seen = client(
            lambda r, s=status: httpx.Response(200, json={"verification_status": s})
        )
        assert paypal.verify_webhook_signature(**ARGS) is expected
        request = seen[0]
        assert (
            request.method == "POST"
            and request.url.path == "/v1/notifications/verify-webhook-signature"
        )
        assert "paypal-request-id" not in {
            k.lower() for k in request.headers
        }  # a read: no Request-Id
        sent = json.loads(request.content)
        assert set(sent) == {
            "auth_algo", "cert_url", "transmission_id", "transmission_sig", "transmission_time",
            "webhook_id", "webhook_event",
        }  # fmt: skip
        assert sent["webhook_event"] == json.loads(RAW) and sent["webhook_id"] == "WH-ID"


def test_the_notification_bytes_are_embedded_unchanged() -> None:
    paypal, seen = client(lambda r: httpx.Response(200, json={"verification_status": "SUCCESS"}))
    paypal.verify_webhook_signature(**ARGS)
    assert RAW in seen[0].content  # not re-serialized: 1.50 stays 1.50


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, json={"verification_status": "MAYBE"}),
        httpx.Response(200, json={}),
        httpx.Response(200, content=b"not json"),
        httpx.Response(
            200, content=b'{"verification_status": "SUCCESS", "verification_status": "FAILURE"}'
        ),
        httpx.Response(401, json={"name": "AUTHENTICATION_FAILURE"}),
        httpx.Response(422, json={"name": "VALIDATION_ERROR"}),
        httpx.Response(500, json={"name": "INTERNAL_SERVER_ERROR"}),
    ],
)
def test_anything_but_a_clear_verdict_raises_so_it_is_never_taken_for_success(
    response: httpx.Response,
) -> None:
    paypal, _ = client(lambda r: response)
    with pytest.raises(PayPalError):
        paypal.verify_webhook_signature(**ARGS)


def test_a_duplicate_key_in_the_answer_is_refused_by_the_strict_loader() -> None:
    paypal, _ = client(
        lambda r: httpx.Response(
            200,
            content=b'{"verification_status":"SUCCESS","verification_status":"FAILURE"}',
            headers={"content-type": "application/json"},
        )
    )
    with pytest.raises(PayPalResponseError):
        paypal.verify_webhook_signature(**ARGS)


def test_the_webhook_id_comes_from_the_environment_and_is_checked() -> None:
    env = {"PAYPAL_CLIENT_ID": "i", "PAYPAL_CLIENT_SECRET": "s"}
    assert PayPalConfig.from_env(env).webhook_id == ""
    assert PayPalConfig.from_env({**env, "PAYPAL_WEBHOOK_ID": " 1AB23 "}).webhook_id == "1AB23"
    for bad in ("has space", "x" * 65, "ctl\x01"):
        with pytest.raises(PayPalConfigError):
            PayPalConfig(client_id="i", client_secret="s", webhook_id=bad)
    assert "WH" not in repr(PayPalConfig(client_id="i", client_secret="s", webhook_id="WH-SECRET"))

"""A small stateful stand-in for the PayPal sandbox, for testing the cassette machinery.

It answers the calls in `countersign.paypal.cycle` and deliberately puts the things a recording must
scrub into its responses: an access token, an application id, a merchant account id, and payer
personal data. Nothing here is a real credential.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

TOKEN = "A21AAFakeTokenValueThatLooksLikeARealPayPalToken1234567890"
APP_ID = "APP-80W284485P519543T"
MERCHANT = "MERCHANTACCT123"
PAYER_EMAIL = "sb-buyer1234@personal.example.com"
PAYER_NAME = "Testbuyer Persona"
PAYER_ID = "PAYERID12345"
RECORDED_AT = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)


class FakePayPal:
    def __init__(self) -> None:
        self.order: dict[str, Any] | None = None
        self.status = "CREATED"
        self.authorization: dict[str, Any] | None = None
        self.capture: dict[str, Any] | None = None
        self.requests: list[tuple[str, str]] = []

    def approve(self, _url: str) -> None:
        self.status = "APPROVED"

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    # -- bodies

    def _order_body(self) -> dict[str, Any]:
        assert self.order is not None
        unit = json.loads(json.dumps(self.order["purchase_units"][0]))
        unit["payee"] = {"merchant_id": MERCHANT, "email_address": "merchant@example.com"}
        unit["shipping"] = {
            "name": {"full_name": PAYER_NAME},
            "address": {"address_line_1": "1 Main St"},
        }
        payments: dict[str, Any] = {}
        if self.authorization:
            payments["authorizations"] = [self.authorization]
        if self.capture:
            payments["captures"] = [self.capture]
        if payments:
            unit["payments"] = payments
        status = "COMPLETED" if self.authorization else self.status
        return {
            "id": "ORDER9",
            "status": status,
            "intent": "AUTHORIZE",
            "purchase_units": [unit],
            "payer": {
                "name": {"given_name": "Testbuyer", "surname": "Persona"},
                "email_address": PAYER_EMAIL,
                "payer_id": PAYER_ID,
            },
            "payment_source": {"paypal": {"email_address": PAYER_EMAIL, "account_id": PAYER_ID}},
            "links": [
                {
                    "href": "https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER9",
                    "rel": "self",
                }
            ],
        }

    def handle(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        self.requests.append((method, path))
        debug = {"paypal-debug-id": "debug-" + str(len(self.requests))}
        if (method, path) == ("POST", "/v1/oauth2/token"):
            return httpx.Response(
                200,
                headers=debug,
                json={
                    "scope": "https://uri.paypal.com/services/payments/payment/authcapture",
                    "access_token": TOKEN,
                    "token_type": "Bearer",
                    "app_id": APP_ID,
                    "expires_in": 32400,
                    "nonce": "2026-10-24T10:00:00Zabc",
                },
            )
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        if (method, path) == ("POST", "/v2/checkout/orders"):
            self.order = json.loads(request.content)
            return httpx.Response(
                201,
                headers=debug,
                json={
                    "id": "ORDER9",
                    "status": "PAYER_ACTION_REQUIRED",
                    "links": [
                        {
                            "href": "https://www.sandbox.paypal.com/checkoutnow?token=ORDER9",
                            "rel": "payer-action",
                        }
                    ],
                },
            )
        if (method, path) == ("GET", "/v2/checkout/orders/ORDER9"):
            return httpx.Response(200, headers=debug, json=self._order_body())
        if (method, path) == ("POST", "/v2/checkout/orders/ORDER9/authorize"):
            if self.status != "APPROVED":
                return httpx.Response(
                    422, headers=debug, json={"name": "ORDER_NOT_APPROVED", "message": "no"}
                )
            assert self.order is not None
            unit = self.order["purchase_units"][0]
            self.authorization = {
                "id": "AUTH9",
                "status": "CREATED",
                "amount": {
                    "currency_code": unit["amount"]["currency_code"],
                    "value": unit["amount"]["value"],
                },
                "invoice_id": unit["invoice_id"],
                "custom_id": unit["custom_id"],
                "create_time": RECORDED_AT.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expiration_time": (RECORDED_AT + timedelta(days=29)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
            return httpx.Response(201, headers=debug, json={"id": "ORDER9", "status": "COMPLETED"})
        if (method, path) == ("GET", "/v2/payments/authorizations/AUTH9"):
            assert self.authorization is not None
            return httpx.Response(200, headers=debug, json=self.authorization)
        if (method, path) == ("POST", "/v2/payments/authorizations/AUTH9/capture"):
            assert self.authorization is not None
            body = json.loads(request.content)
            assert body["final_capture"] is True and body["amount"] == self.authorization["amount"]
            self.authorization = {**self.authorization, "status": "CAPTURED"}
            self.capture = {
                "id": "CAP9",
                "status": "COMPLETED",
                "amount": body["amount"],
                "final_capture": True,
                "invoice_id": self.authorization["invoice_id"],
                "custom_id": self.authorization["custom_id"],
            }
            return httpx.Response(201, headers=debug, json={"id": "CAP9", "status": "COMPLETED"})
        if (method, path) == ("GET", "/v2/payments/captures/CAP9"):
            assert self.capture is not None
            return httpx.Response(200, headers=debug, json=self.capture)
        return httpx.Response(404, headers=debug, json={"name": "RESOURCE_NOT_FOUND"})

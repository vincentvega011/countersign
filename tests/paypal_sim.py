"""A stateful stand-in for the PayPal sandbox for Credential Provider tests.

It models what the recorded runs showed (docs/PROTOCOL.md section 4): create answers once per
Request-Id (a repeated id replays the first result), an order is `APPROVED` only after the payer
approves it, authorize needs `APPROVED` and authorizes the amount the order has AT THAT MOMENT
(so a PATCH while `APPROVED` flows into the authorization), a vaulted merchant-initiated order is
created and authorized in one call, void is idempotent per Request-Id. Failures can be injected per
operation. Nothing here is a real credential.
"""

from __future__ import annotations

import copy
import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

MERCHANT = "SIMMERCHANT1"
NOW = datetime(2026, 10, 30, 10, 0, tzinfo=UTC)

Hook = Callable[[httpx.Request], httpx.Response | None]


class PayPalSim:
    def __init__(self) -> None:
        self.orders: dict[str, dict[str, Any]] = {}
        self.authorizations: dict[str, dict[str, Any]] = {}
        self.replays: dict[str, httpx.Response] = {}
        self.calls: list[tuple[str, str, str | None]] = []
        self.hooks: dict[str, list[Hook]] = {}
        self._n = 0
        self.vault_ids: dict[str, str] = {}
        self._lock = threading.RLock()
        self.vault_needs_action = False
        self.auth_status = "CREATED"
        self.extra_auth = False
        self.auth_amount_override: str | None = None
        self.vault_mutation: dict[str, str] | None = None

    # ---- controls for tests

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def approve(self, order_id: str) -> None:
        self.orders[order_id]["status"] = "APPROVED"

    def patch(
        self,
        order_id: str,
        *,
        amount: str | None = None,
        custom_id: str | None = None,
        item_name: str | None = None,
    ) -> None:
        order = self.orders[order_id]
        unit = order["unit"]
        if amount is not None:
            # A consistent patch (items plus shipping equal the new amount), as the recorded
            # PATCH of items and amount together was (docs/PROTOCOL.md 4.3).
            from decimal import Decimal

            breakdown = unit["amount"]["breakdown"]
            shipping = Decimal(breakdown.get("shipping", {}).get("value", "0"))
            items_total = f"{Decimal(amount) - shipping:.2f}"
            unit["amount"]["value"] = amount
            breakdown["item_total"]["value"] = items_total
            unit["items"] = unit["items"][:1]
            unit["items"][0]["unit_amount"]["value"] = items_total
            unit["items"][0]["quantity"] = "1"
        if custom_id is not None:
            unit["custom_id"] = custom_id
        if item_name is not None:
            unit["items"][0]["name"] = item_name

    def inject(self, op: str, hook: Hook, *, times: int = 1) -> None:
        """Run `hook` instead of the normal handler for the next `times` calls of `op`."""
        for _ in range(times):
            self.hooks.setdefault(op, []).append(hook)

    def lose_response(self, op: str, *, times: int = 1, replayable: bool = True) -> None:
        """The call takes effect at PayPal, but the caller gets a 500 (the response was lost).

        With `replayable` PayPal replays the original result for a repeated Request-Id, as observed
        (docs/PROTOCOL.md 4.2); without it a repeat does not find the first result.
        """

        def hook(request: httpx.Request) -> httpx.Response:
            response = self._route(
                request.method, request.url.path, request, {"paypal-debug-id": "lost"}
            )
            rid = request.headers.get("paypal-request-id")
            if replayable and rid and response.status_code < 300:
                self.replays[rid] = response
            return server_error(request)

        self.inject(op, hook, times=times)

    def count(self, suffix: str, method: str = "POST") -> int:
        return sum(1 for m, p, _ in self.calls if m == method and p.endswith(suffix))

    # ---- helpers

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}{self._n}"

    def _order_json(self, order_id: str) -> dict[str, Any]:
        order = self.orders[order_id]
        unit = copy.deepcopy(order["unit"])
        unit["payee"] = {"merchant_id": MERCHANT}
        auths = [a for a in self.authorizations.values() if a["order"] == order_id]
        if auths:
            unit["payments"] = {"authorizations": [self._auth_json(a) for a in auths]}
        body: dict[str, Any] = {
            "id": order_id,
            "status": order["status"],
            "intent": "AUTHORIZE",
            "purchase_units": [unit],
        }
        if order.get("vault_id_out"):
            body["payment_source"] = {
                "paypal": {
                    "attributes": {"vault": {"id": order["vault_id_out"], "status": "VAULTED"}}
                }
            }
        return body

    @staticmethod
    def _auth_json(auth: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in auth.items() if k != "order"}

    def _make_authorization(self, order_id: str) -> dict[str, Any]:
        unit = self.orders[order_id]["unit"]
        if self.extra_auth:
            self.extra_auth = False
            self._make_authorization(order_id)
        auth = {
            "id": self._id("AUTH"),
            "order": order_id,
            "status": self.auth_status,
            "amount": {
                "currency_code": unit["amount"]["currency_code"],
                "value": self.auth_amount_override or unit["amount"]["value"],
            },
            "invoice_id": unit["invoice_id"],
            "custom_id": unit["custom_id"],
            "create_time": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expiration_time": (NOW + timedelta(days=29)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self.authorizations[auth["id"]] = auth
        self.orders[order_id]["status"] = "COMPLETED"
        return auth

    # ---- the transport

    def handle(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            return self._handle(request)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        request_id = request.headers.get("paypal-request-id")
        self.calls.append((method, path, request_id))
        debug = {"paypal-debug-id": f"sim-{len(self.calls)}"}
        if (method, path) == ("POST", "/v1/oauth2/token"):
            return httpx.Response(
                200, headers=debug,
                json={"access_token": "SIM-TOKEN-NOT-REAL-1234567890", "token_type": "Bearer",
                      "expires_in": 32400},
            )  # fmt: skip
        op = self._op(method, path)
        for hook in self.hooks.get(op, [])[:1]:
            self.hooks[op].pop(0)
            injected = hook(request)
            if injected is not None:
                return injected
        if request_id and request_id in self.replays:
            return self.replays[request_id]
        response = self._route(method, path, request, debug)
        if request_id and method == "POST" and response.status_code < 300:
            self.replays[request_id] = response
        return response

    @staticmethod
    def _op(method: str, path: str) -> str:
        if method == "POST" and path == "/v2/checkout/orders":
            return "create"
        if method == "POST" and path.endswith("/authorize"):
            return "authorize"
        if method == "POST" and path.endswith("/void"):
            return "void"
        if method == "GET" and path.startswith("/v2/checkout/orders/"):
            return "get_order"
        if method == "GET" and path.startswith("/v2/payments/authorizations/"):
            return "get_authorization"
        return "other"

    def _route(
        self, method: str, path: str, request: httpx.Request, debug: dict[str, str]
    ) -> httpx.Response:
        if (method, path) == ("POST", "/v2/checkout/orders"):
            body = json.loads(request.content)
            order_id = self._id("ORDER")
            source = body["payment_source"]["paypal"]
            vaulted = "vault_id" in source
            if vaulted and source["vault_id"] not in self.vault_ids.values():
                return httpx.Response(422, headers=debug, json={"name": "INVALID_RESOURCE_ID"})
            self.orders[order_id] = {
                "unit": body["purchase_units"][0],
                "status": "PAYER_ACTION_REQUIRED",
                "request": body,
            }
            if "attributes" in source:
                vault_id = self._id("VAULT")
                self.vault_ids[order_id] = vault_id
                self.orders[order_id]["vault_id_out"] = vault_id
            if vaulted and not self.vault_needs_action:
                if self.vault_mutation:
                    self.patch(order_id, **self.vault_mutation)
                self._make_authorization(order_id)
                return httpx.Response(201, headers=debug, json=self._order_json(order_id))
            return httpx.Response(
                201, headers=debug,
                json={"id": order_id, "status": "PAYER_ACTION_REQUIRED",
                      "links": [{"href": f"https://www.sandbox.paypal.com/checkoutnow?token={order_id}",
                                 "rel": "payer-action"}]},
            )  # fmt: skip
        if method == "GET" and path.startswith("/v2/checkout/orders/"):
            order_id = path.rsplit("/", 1)[1]
            if order_id not in self.orders:
                return httpx.Response(404, headers=debug, json={"name": "RESOURCE_NOT_FOUND"})
            return httpx.Response(200, headers=debug, json=self._order_json(order_id))
        if method == "POST" and path.endswith("/authorize"):
            order_id = path.split("/")[-2]
            order = self.orders.get(order_id)
            if order is None:
                return httpx.Response(404, headers=debug, json={"name": "RESOURCE_NOT_FOUND"})
            if order["status"] == "COMPLETED":
                return httpx.Response(
                    422, headers=debug,
                    json={"name": "UNPROCESSABLE_ENTITY", "details": [{"issue": "ORDER_ALREADY_AUTHORIZED"}]},
                )  # fmt: skip
            if order["status"] != "APPROVED":
                return httpx.Response(
                    422, headers=debug,
                    json={"name": "UNPROCESSABLE_ENTITY", "details": [{"issue": "ORDER_NOT_APPROVED"}]},
                )  # fmt: skip
            self._make_authorization(order_id)
            return httpx.Response(201, headers=debug, json={"id": order_id, "status": "COMPLETED"})
        if method == "GET" and path.startswith("/v2/payments/authorizations/"):
            auth = self.authorizations.get(path.rsplit("/", 1)[1])
            if auth is None:
                return httpx.Response(404, headers=debug, json={"name": "RESOURCE_NOT_FOUND"})
            return httpx.Response(200, headers=debug, json=self._auth_json(auth))
        if method == "POST" and path.endswith("/void"):
            auth = self.authorizations.get(path.split("/")[-2])
            if auth is None:
                return httpx.Response(404, headers=debug, json={"name": "RESOURCE_NOT_FOUND"})
            if auth["status"] == "VOIDED":
                return httpx.Response(
                    422, headers=debug,
                    json={"name": "UNPROCESSABLE_ENTITY", "details": [{"issue": "PREVIOUSLY_VOIDED"}]},
                )  # fmt: skip
            auth["status"] = "VOIDED"
            return httpx.Response(204, headers=debug)
        return httpx.Response(404, headers=debug, json={"name": "RESOURCE_NOT_FOUND"})


def server_error(_: httpx.Request) -> httpx.Response:
    return httpx.Response(500, json={"name": "INTERNAL_SERVER_ERROR"})


def timeout(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("simulated timeout", request=request)

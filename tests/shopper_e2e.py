"""Shared pieces of the recorded end-to-end run of the shopping agent (recorder and replay test).

The service is the real composition root on a real Postgres, served by uvicorn on a loopback port so a
headless browser can be the customer's phone. Only PayPal differs: the recorder talks to the sandbox
through a recording transport, the test replays that recording.

Replay and the values that change between runs. A checkout id, the `custom_id` derived from the mandate
digests, the PayPal-Request-Ids derived from the checkout id, and the loopback port in the return URLs
are new on every run (they depend on random ids and salts, and the browser's own key). The replay
transport therefore maps those four kinds of value, and only those, between the live run and the
recording, in requests and in responses. Everything else must match the recording exactly and in order
(method, path, body, the Request-Id prefix naming the operation), so a changed amount, item, payee,
call order or operation still fails the replay. Decision 99.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI
from joserfc.jwk import ECKey
from sqlalchemy import Engine

from countersign.composition import Wiring, build_app
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.paypal.cassette import CassetteTransport
from countersign.paypal.client import PayPalClient
from countersign.runtime import Mode, RuntimeSettings

GOAL = "wireless headphones under 80 dollars, valid for one week"
MERCHANT_ID = "merchant-1"
MERCHANT_NAME = "Countersign demo store"
CASSETTE_NAME = "shopper_e2e.json"


def build_service(
    engine: Engine, base: str, paypal: PayPalClient, *, payee_merchant_id: str,
    paypal_now: Callable[[], datetime] | None = None,
) -> FastAPI:  # fmt: skip
    return build_app(
        RuntimeSettings(Mode.FULL, "dev"),
        Wiring(
            engine=engine, merchant_key=validate_jwk(generate_jwk()),
            platform_key=ECKey.generate_key("P-256"), paypal=paypal, public_base_url=base,
            payee={"id": MERCHANT_ID, "name": MERCHANT_NAME},
            paypal_payee_merchant_id=payee_merchant_id, merchant_constraint_id=MERCHANT_ID,
            paypal_now=paypal_now,
        ),
    )  # fmt: skip


def reserve_port() -> tuple[socket.socket, str]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock, f"http://127.0.0.1:{sock.getsockname()[1]}"


@contextmanager
def serve(app: FastAPI, sock: socket.socket) -> Iterator[None]:
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started, "the app did not start"
    try:
        yield
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


def _create_order(document: dict[str, Any]) -> dict[str, Any]:
    for item in document["interactions"]:
        request = item["request"]
        if request["method"] == "POST" and request["path"] == "/v2/checkout/orders":
            body: dict[str, Any] = request["body"]
            return body
    raise AssertionError("the cassette has no create-order request")


class SubstitutingTransport(CassetteTransport):
    """Strict in-order replay with the four per-run values mapped (see the module docstring)."""

    def __init__(self, document: dict[str, Any], *, live_base: str) -> None:
        super().__init__(document)
        unit = _create_order(document)["purchase_units"][0]
        self._recorded = {
            "checkout": unit["invoice_id"],
            "custom": unit["custom_id"],
            "base": str(document["meta"]["base_url"]),
        }
        self._live: dict[str, str | None] = {"checkout": None, "custom": None, "base": live_base}
        self._rids: dict[str, str] = {}
        self._documents = document["interactions"]

    def _pairs(self) -> list[tuple[str, str]]:
        return [
            (str(self._live[name]), self._recorded[name])
            for name in ("checkout", "custom", "base")
            if self._live[name]
        ]

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body = request.read()
        if request.method == "POST" and request.url.path == "/v2/checkout/orders":
            unit = json.loads(body)["purchase_units"][0]
            self._live["checkout"], self._live["custom"] = unit["invoice_id"], unit["custom_id"]
        text = body.decode("utf-8")
        for live, recorded in self._pairs():
            text = text.replace(live, recorded)
        headers = dict(request.headers)
        rid = request.headers.get("paypal-request-id")
        if rid is not None:
            want = self._documents[self._next]["request"]["request_id"]
            if want is None or rid.split(".")[:2] != want.split(".")[:2]:
                raise AssertionError("a different PayPal operation than the recording")
            if self._rids.setdefault(rid, want) != want or len(set(self._rids.values())) != len(
                self._rids
            ):
                raise AssertionError("a Request-Id was reused for another operation")
            headers["paypal-request-id"] = want
        headers.pop("content-length", None)
        mapped = httpx.Request(
            request.method, request.url, headers=headers, content=text.encode("utf-8")
        )
        answer = super().handle_request(mapped)
        reply = answer.content.decode("utf-8")
        for live, recorded in self._pairs():
            reply = reply.replace(recorded, live)
        reply_headers = {k: v for k, v in answer.headers.items() if k.lower() != "content-length"}
        return httpx.Response(answer.status_code, headers=reply_headers, content=reply.encode())


def recorded_clock(document: dict[str, Any]) -> Callable[[], datetime]:
    """Five minutes after the recording began: authorizations were live then, as in the gate replay."""
    at = datetime.fromisoformat(str(document["meta"]["recorded_at"]))
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return lambda: at + timedelta(minutes=5)

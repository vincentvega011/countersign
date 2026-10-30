"""Shared setup for webhook tests: the real service, gate, lock and Postgres over the PayPal simulator.

The simulator answers `verify-webhook-signature` with a verdict the test sets; nothing here
claims that a real PayPal delivery was seen (docs/ENV.md, pending item for the Render deploy).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, select

from countersign.tables import spend_entries, webhook_events
from countersign.webhooks import WebhookResult, WebhookService
from tests.gate_support import GateWorld, make_gate_world

WEBHOOK_ID = "WH-TEST-WEBHOOK-ID"
HEADERS = {
    "PAYPAL-TRANSMISSION-ID": "00000000-0000-0000-0000-000000000001",
    "PAYPAL-TRANSMISSION-TIME": "2026-10-30T10:00:00Z",
    "PAYPAL-TRANSMISSION-SIG": "c2lnbmF0dXJl",
    "PAYPAL-CERT-URL": "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-test",
    "PAYPAL-AUTH-ALGO": "SHA256withRSA",
}


def body(event_id: str, event_type: str, resource: dict[str, Any], **extra: Any) -> bytes:
    return json.dumps(
        {"id": event_id, "event_type": event_type, "resource": resource, "summary": "s", **extra}
    ).encode()


def authorization_event(
    event_id: str, event_type: str, authorization_id: str, **claims: Any
) -> bytes:
    return body(event_id, event_type, {"id": authorization_id, **claims})


def capture_event(event_id: str, event_type: str, capture_id: str, **claims: Any) -> bytes:
    return body(event_id, event_type, {"id": capture_id, **claims})


def refund_event(event_id: str, refund_id: str, capture_id: str, **claims: Any) -> bytes:
    link = {
        "rel": "up",
        "href": f"https://api.sandbox.paypal.com/v2/payments/captures/{capture_id}",
    }
    return body(event_id, "PAYMENT.CAPTURE.REFUNDED", {"id": refund_id, "links": [link], **claims})


@dataclass
class WebhookWorld:
    gate_world: GateWorld
    service: WebhookService

    @property
    def sim(self) -> Any:
        return self.gate_world.sim

    @property
    def engine(self) -> Engine:
        return self.gate_world.engine

    def send(self, raw: bytes, headers: dict[str, str] | None = None) -> WebhookResult:
        """Deliver one notification and assert it moved no money."""
        before = self.sim.money_calls()
        result = self.service.handle(HEADERS if headers is None else headers, raw)
        assert self.sim.money_calls() == before, "a webhook caused a money moving request"
        return result

    def spend(self) -> Any:
        with self.engine.connect() as conn:
            return conn.execute(
                select(spend_entries).where(
                    spend_entries.c.checkout_id == self.gate_world.checkout.id
                )
            ).one()

    def events(self) -> list[Any]:
        with self.engine.connect() as conn:
            return list(conn.execute(select(webhook_events).order_by(webhook_events.c.received_us)))

    def attempt_state(self) -> str:
        return str(self.gate_world.row().state)


def make_webhook_world(engine: Engine, *, webhook_id: str = WEBHOOK_ID, **kw: Any) -> WebhookWorld:
    world = make_gate_world(engine, **kw)
    service = WebhookService(engine, world.base.client, webhook_id, settler=world.gate)
    return WebhookWorld(world, service)

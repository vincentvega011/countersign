"""POST /webhooks/paypal: verify, dedupe, read PayPal again, reconcile the books.

Security reasoning (INV-7, INV-8, INV-10, INV-12). Order of work:

1. Shape. The body is read with a size limit and the strict JSON loader; the five signature headers
   must be present and well formed. Otherwise: 400, logged, nothing changed.
2. Verification. PayPal's `verify-webhook-signature` endpoint decides. An empty webhook id (nothing is
   configured), a `FAILURE`, or an unreadable answer is "unverified": 401, logged, nothing changed. If
   PayPal cannot be asked at all: 503, so PayPal redelivers a possibly genuine event. Nothing is
   processed on trust.
3. Dedupe and work in ONE transaction. The event id is the primary key of `webhook_events`; the row
   is inserted and locked, the work done, the row marked and the log entry appended, then everything
   commits together. A second delivery of the same id (even 20 at once) waits on the key and finds
   the row finished; a crash rolls the row back with the work, so the retry starts clean. A failed
   log append fails the transaction and the request (500), so PayPal retries.
4. Reconcile from live state. The event body gives only a hint of which resource to read
   (`events.parse_event`). The attempt is found from our own records, PayPal's order is fetched with our
   credentials, and `reconcile.plan` decides from that. A body that lies about an amount or status
   changes nothing. A webhook can never capture, void, authorize or refund: this module has no code
   path to those calls (a test asserts zero money-moving requests in every case).

Attempts the gate left `unresolved`, or authorized and then captured elsewhere, are handed to the
`Settler` (the gate's `settle`), which reads PayPal itself. The handler asks for that only when its own
read shows the authorization already captured or ended, so the gate has nothing left to void.

Answers: 200 for a verified, well formed event (including a duplicate, an event for something we do not
know, and a type we do not act on); 400 malformed; 401 unverified; 503 PayPal or the gate in progress,
try again; 500 internal or log failure.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import structlog
from sqlalchemy import Connection, Engine, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from countersign.gate.store import GateStore
from countersign.ledger import store as ledger_store
from countersign.merchant.decision_log import DecisionLogError
from countersign.merchant.policy import policy_hash
from countersign.paypal.client import PayPalClient
from countersign.paypal.errors import PayPalError, PayPalNotFound
from countersign.tables import payment_attempts, webhook_events
from countersign.webhooks import events, reconcile

log = structlog.get_logger("countersign.webhooks")


class Settler(Protocol):
    """The gate's way to finish an attempt by reading PayPal (`CaptureGate.settle`)."""

    def settle(self, checkout_id: str) -> bool: ...


@dataclass(frozen=True)
class WebhookResult:
    status: int
    outcome: str


class _Retry(Exception):
    """Nothing is wrong, but this is not the moment: answer 503 so PayPal delivers again."""


def now_us() -> int:
    return time.time_ns() // 1000


class WebhookService:
    def __init__(
        self,
        engine: Engine,
        paypal: PayPalClient,
        webhook_id: str,
        *,
        settler: Settler | None = None,
        clock_us: Callable[[], int] = now_us,
    ) -> None:
        self._engine = engine
        self._paypal = paypal
        self._webhook_id = webhook_id
        self._settler = settler
        self._clock = clock_us
        self._store = GateStore(engine, clock_us)
        self._policy_hash = policy_hash()

    # ------------------------------------------------------------------ logging

    def _append(self, conn: Connection, kind: str, payload: dict[str, Any]) -> None:
        ledger_store.append(
            conn, kind=kind, payload=payload, policy_hash=self._policy_hash,
            checkout_id=payload.get("checkout_id"), ts_us=self._clock(),
        )  # fmt: skip

    def _reject(self, status: int, reason: str, event_id: object = None) -> WebhookResult:
        """Log an unverified or malformed notification (no body, no headers) and answer non-2xx."""
        safe = (
            event_id if isinstance(event_id, str) and events._EVENT_ID.fullmatch(event_id) else None
        )
        try:
            with self._engine.begin() as conn:
                self._append(
                    conn, "webhook.rejected", {"reason": reason, "status": status, "event_id": safe}
                )
        except Exception as error:
            raise DecisionLogError(type(error).__name__) from error
        return WebhookResult(status, reason)

    # ------------------------------------------------------------------ entry point

    def handle(self, headers: Mapping[str, str], raw: bytes) -> WebhookResult:
        try:
            return self._handle(headers, raw)
        except DecisionLogError:
            return WebhookResult(500, "log_failed")
        except _Retry:
            return WebhookResult(503, "try_again")
        except Exception as error:  # noqa: BLE001 - INV-10: nothing is half done, PayPal retries
            log.error("webhook_failed", error=type(error).__name__)
            return WebhookResult(500, "internal_error")

    def too_large(self) -> WebhookResult:
        """The route refused to read more than the size limit; log it and answer 400."""
        try:
            return self._reject(400, "malformed:body_too_large")
        except DecisionLogError:
            return WebhookResult(500, "log_failed")

    def _handle(self, headers: Mapping[str, str], raw: bytes) -> WebhookResult:
        try:
            signature = events.read_headers(headers)
            event = events.parse_event(raw)
        except events.MalformedEvent as bad:
            return self._reject(400, f"malformed:{bad.reason}")
        if not self._webhook_id:
            return self._reject(401, "unverified:no_webhook_id", event.event_id)
        try:
            genuine = self._paypal.verify_webhook_signature(
                transmission_id=signature.transmission_id,
                transmission_time=signature.transmission_time,
                transmission_sig=signature.transmission_sig,
                cert_url=signature.cert_url,
                auth_algo=signature.auth_algo,
                webhook_id=self._webhook_id,
                raw_event=raw,
            )  # fmt: skip
        except PayPalError:
            self._reject(503, "unverified:verification_unavailable", event.event_id)
            return WebhookResult(503, "verification_unavailable")
        if not genuine:
            return self._reject(401, "unverified:signature_failure", event.event_id)
        return self._process(event)

    # ------------------------------------------------------------------ dedupe and work

    def _process(self, event: events.Event) -> WebhookResult:
        with self._engine.begin() as conn:
            conn.execute(
                pg_insert(webhook_events)
                .values(
                    event_id=event.event_id, event_type=event.event_type, state="processing",
                    received_us=self._clock(),
                )
                .on_conflict_do_nothing(index_elements=["event_id"])
            )  # fmt: skip
            row = conn.execute(
                select(webhook_events)
                .where(webhook_events.c.event_id == event.event_id)
                .with_for_update()
            ).one()
            if row.state != "processing":
                self._append(
                    conn, "webhook.duplicate",
                    {"event_id": event.event_id, "event_type": event.event_type},
                )  # fmt: skip
                return WebhookResult(200, "duplicate")
            try:
                outcome, checkout_id, anomalies = self._reconcile(conn, event)
            except PayPalError:
                raise _Retry from None
            state = "ignored" if checkout_id is None else "done"
            conn.execute(
                update(webhook_events)
                .where(webhook_events.c.event_id == event.event_id)
                .values(state=state, outcome=outcome, checkout_id=checkout_id,
                        finished_us=self._clock())
            )  # fmt: skip
            self._append(
                conn, "webhook.processed",
                {"event_id": event.event_id, "event_type": event.event_type, "outcome": outcome,
                 "checkout_id": checkout_id, "anomalies": list(anomalies)},
            )  # fmt: skip
        self._settle_after_commit(outcome, checkout_id)
        return WebhookResult(200, outcome)

    def _settle_after_commit(self, outcome: str, checkout_id: str | None) -> None:
        # The settle runs after the event row committed: the gate takes its own locks on the attempt.
        if outcome == "settle_requested" and checkout_id is not None and self._settler is not None:
            try:
                self._settler.settle(checkout_id)
            except Exception as error:  # noqa: BLE001 - recovery will retry; the event is recorded
                log.error("webhook_settle_failed", error=type(error).__name__)

    # ------------------------------------------------------------------ reconciliation

    def _find_attempt(self, event: events.Event) -> Any | None:
        hint = event.hint
        if hint is None:
            return None
        if hint.kind == "authorization":
            return self._store.row_where("authorization_id", hint.resource_id)
        if hint.kind == "order":
            return self._store.row_where("order_id", hint.resource_id)
        found = self._store.row_where("capture_id", hint.resource_id)
        if found is not None:
            return found
        try:  # a capture we did not make: PayPal's own capture record names its authorization
            capture = self._paypal.get_capture(hint.resource_id)
        except PayPalNotFound:
            return None
        for link in capture.links:
            if link.rel == "up":
                auth = events.link_target(link.href, "authorizations")
                if auth is not None:
                    return self._store.row_where("authorization_id", auth)
        return None

    def _reconcile(
        self, conn: Connection, event: events.Event
    ) -> tuple[str, str | None, tuple[str, ...]]:
        if event.event_type not in events.HANDLED:
            return "unhandled_type", None, ()
        found = self._find_attempt(event)
        if found is None or not found.order_id or not found.authorization_id:
            return "unknown_resource", None, ()
        try:
            order = self._paypal.get_order(found.order_id)
        except PayPalNotFound:
            return "unknown_resource", None, ()
        checkout_id = str(found.checkout_id)
        amount_minor, _currency = self._store.spend(found.spend_id)
        live = reconcile.live_from_order(order, found.authorization_id)

        # Only the actions that change rows hold the attempt lock; a settle request holds none.
        locked = conn.execute(
            select(payment_attempts)
            .where(payment_attempts.c.checkout_id == checkout_id)
            .with_for_update()
        ).one()
        refunded = self._refunded(conn, locked.spend_id)
        decided = reconcile.plan(
            state=locked.state, gate_origin=bool(locked.gate_code), live=live,
            amount_minor=amount_minor, already_refunded_minor=refunded,
        )  # fmt: skip
        if decided.action == "retry":
            raise _Retry
        if decided.action == "release":
            self._store.release_in(
                conn, checkout_id, spend_id=locked.spend_id, code="W-VOID",
                reason="authorization_ended_at_paypal", receipt=None,
                log=lambda c: self._append(
                    c, "webhook.released",
                    {"checkout_id": checkout_id, "authorization_status": live.authorization_status},
                ),
            )  # fmt: skip
            return "released", checkout_id, live.anomalies
        if decided.action == "refund":
            self._store.ledger.refund(conn, locked.spend_id, decided.refund_delta_minor)
            return "refund_recorded", checkout_id, live.anomalies
        if decided.action == "settle":
            return "settle_requested", checkout_id, live.anomalies
        return decided.reason or "no_change", checkout_id, live.anomalies

    @staticmethod
    def _refunded(conn: Connection, spend_id: str) -> int:
        from countersign.tables import spend_entries

        value = conn.execute(
            select(spend_entries.c.refunded_minor).where(spend_entries.c.id == spend_id)
        ).scalar()
        return int(value or 0)

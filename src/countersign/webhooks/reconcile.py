"""What a live PayPal order says, and what the books should do about it. Pure and deterministic.

Security reasoning (INV-1, INV-7). `Live` is built only from an order PayPal just returned to us, and
`plan` is a function of the attempt's recorded state and that `Live`, never of the notification that
caused the read. Two consequences: a notification that lies about an amount or a status changes
nothing, and any order, duplication or delay of notifications ends in the same plan for the same live
state, so replays and late events converge. `plan` never asks for a capture, a void or an
authorization; its actions are bookkeeping, or a request to the gate to settle an attempt by reading.

Accounting is add-only (docs/PROTOCOL.md Decisions 2 and 33): a refund raises `refunded_minor`, never
lowers a captured entry and never gives headroom back; a void of an uncaptured authorization is the
only thing that releases a reservation.
"""

from __future__ import annotations

from dataclasses import dataclass

from countersign.paypal.models import Order

ENDED = frozenset({"VOIDED", "EXPIRED", "DENIED"})
CAPTURE_BAD = frozenset({"DECLINED", "DENIED", "REVERSED", "FAILED"})
CAPTURE_GOOD = frozenset({"COMPLETED", "PARTIALLY_REFUNDED", "REFUNDED"})


@dataclass(frozen=True)
class Live:
    authorization_status: str | None  # of the attempt's own authorization; None if not on the order
    captured_minor: int  # sum of captures PayPal reports as completed or refunded after completion
    capture_count: int
    refunded_minor: int  # sum of refunds PayPal reports COMPLETED
    anomalies: tuple[str, ...]


@dataclass(frozen=True)
class Plan:
    action: str  # none | release | settle | refund | retry
    refund_delta_minor: int = 0
    reason: str = ""


def live_from_order(order: Order, authorization_id: str) -> Live:
    own = next((a for a in order.authorizations if a.id == authorization_id), None)
    good = [c for c in order.captures if c.status in CAPTURE_GOOD]
    anomalies = sorted(
        {f"capture_{c.status.lower()}" for c in order.captures if c.status in CAPTURE_BAD}
    )
    refunds = [r for r in order.refunds if r.status == "COMPLETED"]
    return Live(
        authorization_status=None if own is None else own.status,
        captured_minor=sum(c.amount.minor for c in good),
        capture_count=len(good),
        refunded_minor=sum(r.amount.minor for r in refunds),
        anomalies=tuple(anomalies),
    )


def plan(
    *,
    state: str,
    gate_origin: bool,
    live: Live,
    amount_minor: int,
    already_refunded_minor: int,
) -> Plan:
    """The bookkeeping that brings the attempt in line with `live`. `none` means already in line."""
    if state in ("gating", "capturing"):
        return Plan("retry", reason="gate_in_progress")
    if state == "captured":
        target = min(live.refunded_minor, amount_minor)
        if target > already_refunded_minor:
            return Plan("refund", target - already_refunded_minor, "refund_completed")
        return Plan("none", reason="already_captured")
    if state in ("authorized", "unresolved"):
        if state == "unresolved" and not gate_origin:
            return Plan("none", reason="unresolved_by_credential_provider")
        if live.capture_count > 0:
            return Plan("settle", reason="capture_present")
        if live.authorization_status in ENDED:
            return Plan(
                "release" if state == "authorized" else "settle", reason="authorization_ended"
            )
        return Plan("none", reason="authorization_still_open")
    return Plan("none", reason=f"attempt_{state}")

"""When a checkout may be canceled: the entry guard (docs/PROTOCOL.md Decision 70).

Security reasoning. A cancel of a checkout whose payment is in flight cannot undo the payment: the
authorization at PayPal and the reservations are held by the payment attempt, not by the checkout
row. If the cancel were honored, the capture gate could still capture afterwards and the trail would
read `canceled` with a capture and no receipts. So once a payment attempt exists, or the checkout is
`complete_in_progress`, a cancel is refused and nothing else changes: it does not void, release or
touch the attempt. The decision is taken while the caller holds the checkout row lock, which is also
what `complete` takes to move the checkout into `complete_in_progress`, so a cancel and a complete
on one checkout are ordered by the database: the cancel either lands first (and the complete is then
refused as not ready) or finds the checkout completing (and is refused). The capture gate re-reads
the checkout under the same row lock as its own, independent defense (`gate.store.begin_capture`).

Both adapters call `cancel_refusal` and nothing else decides this, so UCP, ACP, full and baseline
cannot drift apart.
"""

from __future__ import annotations

from typing import Literal

from sqlalchemy import Connection, select

from countersign.checkout.state import FINAL, Status
from countersign.checkout.store import CheckoutRecord
from countersign.tables import payment_attempts

# Every attempt state that is not final. `abandoned`, `voided`, `failed` and `captured` are final.
LIVE_ATTEMPT_STATES = (
    "reserved",
    "order_created",
    "authorizing",
    "authorized",
    "gating",
    "capturing",
    "unresolved",
)

CancelRefusal = Literal["final", "completing"]


def attempt_in_flight(conn: Connection, checkout_id: str) -> bool:
    """True if a payment attempt exists for the checkout in any non-final state."""
    state = conn.execute(
        select(payment_attempts.c.state).where(payment_attempts.c.checkout_id == checkout_id)
    ).scalar()
    return state is not None and state in LIVE_ATTEMPT_STATES


def cancel_refusal(conn: Connection, record: CheckoutRecord) -> CancelRefusal | None:
    """Why a cancel must be refused, or None if it may proceed. Call under the checkout row lock.

    `final`: the checkout is `completed` or `canceled`; the caller reports that state.
    `completing`: the checkout is `complete_in_progress`, or a payment attempt is live whatever the
    status says (fail closed: an attempt that outlives its checkout's status is still money held).
    """
    if record.status in FINAL:
        return "final"
    if record.status is Status.COMPLETE_IN_PROGRESS or attempt_in_flight(conn, record.id):
        return "completing"
    return None

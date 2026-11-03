"""Open mandate registry, revocation and state, all on the payment open mandate identity.

Security reasoning. An open mandate pair is identified by `mandate_identity` of its payment mandate
(PROTOCOL.md Decision 86); the checkout mandate's identity is recorded beside it. Single use, the
budget row (`open_payment_mandates`) and revocation all use that key.

Revocation is a row in `open_mandate_revocations`, which the runtime role can only insert into. The
lock discipline (Decision 88) is what makes "revoke concurrent with capture" consistent:

- `revoke_in` takes the open mandate's row `FOR UPDATE` (the same row the budget check locks), then
  reads the attempts under that lock. If an attempt is `capturing` (or `unresolved`, where money may
  be held) it answers `in_flight` and writes nothing; if one is `captured` it answers `already_used`.
  Otherwise it inserts the revocation. Revocation is therefore effective for everything not yet
  claimed as capturing.
- The capture gate takes the same row `FOR SHARE` in the transaction that moves an attempt to
  `capturing`, and re-reads revocations there (`gate.store.begin_capture`). If the revocation committed
  first the gate sees it and voids; if the gate holds the row first the revocation waits, then sees
  `capturing` and is refused. A revocation row never coexists with a capture that started after it.
- The Credential Provider checks revocations after taking the row lock in its reservation transaction
  and again before authorizing.

All functions take the caller's connection so the check and the write share one transaction.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import Connection, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from countersign.tables import (
    open_mandate_revocations,
    open_mandates,
    open_payment_mandates,
    payment_attempts,
    spend_entries,
)

IN_FLIGHT = "in_flight"
ALREADY_USED = "already_used"
_NOT_A_PURCHASE = ("voided", "abandoned")
_CAPTURING = ("capturing", "unresolved")


@dataclass(frozen=True)
class RevokeOutcome:
    code: str | None  # None: revoked (or already revoked); else IN_FLIGHT or ALREADY_USED
    new: bool = False


@dataclass(frozen=True)
class MandateView:
    """One open mandate as the activity screen shows it. Structured data only."""

    id: str
    state: str  # unused | in_flight | used | revoked | expired
    ceiling_minor: int
    currency: str
    exp: int
    created_us: int
    agent_thumbprint: str
    purchase: dict[str, object] | None


def lock_row(conn: Connection, payment_identity: str, currency: str, *, share: bool) -> None:
    """Create the budget row if needed and hold its lock (`FOR SHARE` for the gate, else exclusive)."""
    conn.execute(
        pg_insert(open_payment_mandates)
        .values(digest=payment_identity, currency=currency, created_us=0)
        .on_conflict_do_nothing(index_elements=["digest"])
    )
    query = select(open_payment_mandates.c.digest).where(
        open_payment_mandates.c.digest == payment_identity
    )
    conn.execute(query.with_for_update(read=share)).one()


def revoked_in(conn: Connection, identities: Sequence[str]) -> bool:
    """True if any of these identities (payment or checkout) is named by a revocation row."""
    found = conn.execute(
        select(open_mandate_revocations.c.payment_identity)
        .where(
            open_mandate_revocations.c.payment_identity.in_(list(identities))
            | open_mandate_revocations.c.checkout_identity.in_(list(identities))
        )
        .limit(1)
    ).first()
    return found is not None


def register_in(
    conn: Connection,
    *,
    payment_identity: str,
    checkout_identity: str,
    customer_id: str,
    consent_id: str,
    agent_thumbprint: str,
    ceiling_minor: int,
    currency: str,
    exp: int,
    now_us: int,
) -> None:
    conn.execute(
        open_mandates.insert().values(
            id=payment_identity, checkout_identity=checkout_identity, customer_id=customer_id,
            consent_id=consent_id, agent_thumbprint=agent_thumbprint, ceiling_minor=ceiling_minor,
            currency=currency, exp=exp, created_us=now_us,
        )
    )  # fmt: skip


def revoke_in(
    conn: Connection,
    *,
    payment_identity: str,
    checkout_identity: str,
    currency: str,
    now_us: int,
    customer_id: str | None = None,
    signer_thumbprint: str | None = None,
    challenge_id: str | None = None,
    record: str | None = None,
    signature: str | None = None,
) -> RevokeOutcome:
    """Revoke under the row lock. The caller has already authorized the request."""
    lock_row(conn, payment_identity, currency, share=False)
    if revoked_in(conn, [payment_identity, checkout_identity]):
        return RevokeOutcome(None, new=False)  # idempotent
    states = [
        str(s)
        for s in conn.execute(
            select(payment_attempts.c.state).where(
                payment_attempts.c.mandate_digest == payment_identity
            )
        ).scalars()
    ]
    if any(s in _CAPTURING for s in states):
        return RevokeOutcome(IN_FLIGHT)
    if "captured" in states:
        return RevokeOutcome(ALREADY_USED)
    conn.execute(
        open_mandate_revocations.insert().values(
            payment_identity=payment_identity, checkout_identity=checkout_identity,
            customer_id=customer_id, signer_thumbprint=signer_thumbprint,
            challenge_id=challenge_id, record=record, signature=signature, revoked_us=now_us,
        )
    )  # fmt: skip
    return RevokeOutcome(None, new=True)


def list_for_customer(conn: Connection, customer_id: str, now_s: int) -> list[MandateView]:
    """Every open mandate of a customer with its state and the purchase made under it."""
    rows = conn.execute(
        select(open_mandates)
        .where(open_mandates.c.customer_id == customer_id)
        .order_by(open_mandates.c.created_us.desc(), open_mandates.c.id)
    ).all()
    views: list[MandateView] = []
    for row in rows:
        attempts = conn.execute(
            select(
                payment_attempts.c.checkout_id,
                payment_attempts.c.state,
                payment_attempts.c.capture_id,
                payment_attempts.c.updated_us,
                payment_attempts.c.spend_id,
            ).where(payment_attempts.c.mandate_digest == row.id)
        ).all()
        captured = next((a for a in attempts if a.state == "captured"), None)
        active = any(a.state not in _NOT_A_PURCHASE and a.state != "captured" for a in attempts)
        revoked = revoked_in(conn, [row.id, row.checkout_identity])
        purchase: dict[str, object] | None = None
        if captured is not None:
            amount = conn.execute(
                select(spend_entries.c.amount_minor, spend_entries.c.currency).where(
                    spend_entries.c.id == captured.spend_id
                )
            ).first()
            purchase = {
                "checkout_id": captured.checkout_id,
                "capture_id": captured.capture_id,
                "amount_minor": None if amount is None else int(amount.amount_minor),
                "currency": None if amount is None else str(amount.currency),
                "at_us": int(captured.updated_us),
            }
        if captured is not None:
            state = "used"
        elif revoked:
            state = "revoked"
        elif active:
            state = "in_flight"
        elif now_s >= int(row.exp):
            state = "expired"
        else:
            state = "unused"
        views.append(
            MandateView(
                str(row.id),
                state,
                int(row.ceiling_minor),
                str(row.currency),
                int(row.exp),
                int(row.created_us),
                str(row.agent_thumbprint),
                purchase,
            )
        )
    return views

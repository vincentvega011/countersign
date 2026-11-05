"""The customer a checkout belongs to (closes L55, docs/PROTOCOL.md Decision 111).

Security reasoning. A checkout is bound to exactly one customer id, once, and the binding never
changes (`checkout_customers` is insert only, one row per checkout, the primary key is the checkout
id). The binding is written:

1. at create, in the same transaction as the checkout row, when the request's delegation names a
   customer (the principal of Decisions 47 and 49);
2. otherwise by the first Human Present offer, under the checkout row lock, for the customer whose
   device key signed the offer request;
3. otherwise by the first complete whose mandate chain verified, for the customer that chain names.

Every later offer, consent and complete must name the bound customer. A different customer gets the
stable refusal `checkout_customer_mismatch`, logged before the answer (INV-12). `bind_or_match` is the
only writer: INSERT ... ON CONFLICT DO NOTHING, then a read of the row, so two racing writers agree on
one winner whatever the order. Nothing here names a protocol (INV-5) or calls a model (INV-1).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import Connection, Engine, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from countersign.ledger import store as ledger
from countersign.tables import checkout_customers, checkout_sources

MISMATCH = "checkout_customer_mismatch"
CUSTOMER = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]{0,126}[\x21-\x7e])?")
SOURCES = frozenset({"delegation", "offer", "mandate"})
LOG_BOUND = "checkout.customer_bound"
LOG_REFUSED = "checkout.customer_refused"


@dataclass(frozen=True)
class Binding:
    customer_id: str
    agent_thumbprint: str | None
    source: str
    new: bool  # written by this call


def _now_us() -> int:
    return time.time_ns() // 1000


def bound(conn: Connection, checkout_id: str) -> Binding | None:
    row = conn.execute(
        select(checkout_customers).where(checkout_customers.c.checkout_id == checkout_id)
    ).first()
    if row is None:
        return None
    return Binding(str(row.customer_id), row.agent_thumbprint, str(row.source), False)


def bind_or_match(
    conn: Connection,
    checkout_id: str,
    customer_id: str,
    *,
    agent_thumbprint: str | None,
    source: str,
    now_us: int,
) -> tuple[bool, Binding]:
    """Bind the checkout to `customer_id` unless it is bound; say whether the binding names them.

    Returns (matches, binding). The caller holds whatever lock its path holds; correctness does not
    depend on it, because the primary key decides the one winner.
    """
    if source not in SOURCES:
        raise ValueError("unknown binding source")
    if not isinstance(customer_id, str) or CUSTOMER.fullmatch(customer_id) is None:
        raise ValueError("unusable customer id")
    inserted = conn.execute(
        pg_insert(checkout_customers)
        .values(
            checkout_id=checkout_id, customer_id=customer_id,
            agent_thumbprint=agent_thumbprint, source=source, created_us=now_us,
        )
        .on_conflict_do_nothing(index_elements=["checkout_id"])
        .returning(checkout_customers.c.checkout_id)
    ).first()  # fmt: skip
    if inserted is not None:
        return True, Binding(customer_id, agent_thumbprint, source, True)
    current = bound(conn, checkout_id)
    if current is None:  # pragma: no cover - the conflicting row cannot vanish (insert only)
        raise RuntimeError("binding disappeared")
    return current.customer_id == customer_id, current


class _Named(Protocol):
    @property
    def customer_id(self) -> str | None: ...

    @property
    def agent_thumbprint(self) -> str | None: ...


def bind_at_create(
    conn: Connection, checkout_id: str, principal: _Named | None, now_us: int
) -> bool:
    """At create, inside the transaction that inserts the checkout: bind when a customer is named."""
    if principal is None or not principal.customer_id:
        return False
    if CUSTOMER.fullmatch(principal.customer_id) is None:
        return False
    ok, _ = bind_or_match(
        conn, checkout_id, principal.customer_id, agent_thumbprint=principal.agent_thumbprint,
        source="delegation", now_us=now_us,
    )  # fmt: skip
    return ok


DATA_SOURCES = frozenset({"live_sandbox", "recorded", "simulator"})


def label_source(conn: Connection, checkout_id: str, source: str, now_us: int) -> None:
    """Record which PayPal a checkout was written against, once (the dashboard's `source`)."""
    if source not in DATA_SOURCES:
        raise ValueError("unknown data source")
    conn.execute(
        pg_insert(checkout_sources)
        .values(checkout_id=checkout_id, source=source, created_us=now_us)
        .on_conflict_do_nothing(index_elements=["checkout_id"])
    )


class CompletionBinding:
    """The complete-time check, for the composition root: own transaction, logged before return."""

    def __init__(
        self, engine: Engine, *, policy_hash: bytes, clock_us: Callable[[], int] = _now_us
    ) -> None:
        self._engine = engine
        self._policy_hash = policy_hash
        self._clock_us = clock_us

    def admits(self, checkout_id: str, customer_id: str | None, agent: str | None) -> bool:
        """True only if the verified chain's customer is (or now becomes) the checkout's customer.

        A chain that names no usable customer never matches. Any error is a refusal (INV-10); a log
        that cannot be written raises, and the caller treats that as a refusal too (INV-12).
        """
        now = self._clock_us()
        with self._engine.begin() as conn:
            if customer_id is None or CUSTOMER.fullmatch(customer_id) is None:
                ok, binding = False, None
            else:
                ok, binding = bind_or_match(
                    conn, checkout_id, customer_id, agent_thumbprint=agent, source="mandate",
                    now_us=now,
                )  # fmt: skip
            kind = LOG_BOUND if ok and binding is not None and binding.new else None
            if not ok:
                kind = LOG_REFUSED
            if kind is not None:
                ledger.append(
                    conn, kind=kind, checkout_id=checkout_id, policy_hash=self._policy_hash,
                    ts_us=now,
                    payload={"stage": "complete", "code": MISMATCH if not ok else "bound",
                             "source": binding.source if binding else "none"},
                )  # fmt: skip
        return ok


__all__ = [
    "DATA_SOURCES",
    "MISMATCH",
    "Binding",
    "CompletionBinding",
    "bind_at_create",
    "bind_or_match",
    "bound",
    "label_source",
]  # fmt: skip

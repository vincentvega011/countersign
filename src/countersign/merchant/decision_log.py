"""The decision log hook of the Merchant role (INV-12: log before respond).

The verifier calls `record` before it returns any result. A `DecisionLogError` fails the
operation: the caller gets an exception, not a result, and a reservation made for this
presentation is aborted. `LedgerDecisionLog` writes to the hash-chained ledger in its own
transaction; tests use an in-memory implementation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from sqlalchemy import Engine

from countersign.ledger import store as ledger


class DecisionLogError(Exception):
    """The decision could not be logged. The operation must fail."""


class DecisionLog(Protocol):
    def record(self, *, kind: str, checkout_id: str, payload: Mapping[str, Any]) -> None: ...


class LedgerDecisionLog:
    """Append to the Postgres decision log in a transaction that commits before returning."""

    def __init__(self, engine: Engine, policy_hash: bytes, clock_us: Callable[[], int]) -> None:
        self._engine = engine
        self._policy_hash = policy_hash
        self._clock = clock_us

    def record(self, *, kind: str, checkout_id: str, payload: Mapping[str, Any]) -> None:
        try:
            with self._engine.begin() as conn:
                ledger.append(
                    conn,
                    kind=kind,
                    payload=payload,
                    policy_hash=self._policy_hash,
                    checkout_id=checkout_id,
                    ts_us=self._clock(),
                )
        except Exception as error:
            raise DecisionLogError(type(error).__name__) from error

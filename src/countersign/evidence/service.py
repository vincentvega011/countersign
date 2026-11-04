"""Freeze an evidence bundle when a capture is confirmed, and serve it by capture id.

The bundle is assembled after the gate confirmed the capture and stored with an INSERT (the table is
insert only, so a stored bundle never changes). Assembly is best effort and cannot undo or delay a
capture: money has moved, so a failure is logged and the checkout stays completed (INV-10 applies to
authorization, not to paperwork). The log entry `evidence.stored` is appended after the bundle, so it
is not inside the bundle's own log proofs.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import structlog
from sqlalchemy import Engine, insert, select
from sqlalchemy.exc import IntegrityError

from countersign.evidence.bundle import assemble, serialize
from countersign.ledger import store as ledger_store
from countersign.tables import evidence_bundles

log = structlog.get_logger("countersign.evidence")


class EvidenceService:
    def __init__(
        self,
        engine: Engine,
        *,
        merchant_jwk: dict[str, Any],
        platform_jwk: dict[str, Any],
        clock_us: Callable[[], int],
        policy_hash: bytes,
    ) -> None:
        self._engine = engine
        self._merchant = merchant_jwk
        self._platform = platform_jwk
        self._clock_us = clock_us
        self._policy_hash = policy_hash

    def record(self, checkout_id: str, receipts: dict[str, str]) -> bool:
        """Assemble and store the bundle for a captured checkout. True if a bundle now exists."""
        try:
            with self._engine.begin() as conn:
                bundle = assemble(
                    conn, checkout_id, receipts=receipts, merchant_jwk=self._merchant,
                    platform_jwk=self._platform,
                )  # fmt: skip
            capture_id = bundle["capture_id"]
            try:
                with self._engine.begin() as conn:
                    conn.execute(
                        insert(evidence_bundles).values(
                            capture_id=capture_id, checkout_id=checkout_id,
                            bundle=serialize(bundle), created_us=self._clock_us(),
                        )
                    )  # fmt: skip
                    ledger_store.append(
                        conn, kind="evidence.stored", payload={"capture_id": capture_id},
                        policy_hash=self._policy_hash, checkout_id=checkout_id,
                        ts_us=self._clock_us(),
                    )  # fmt: skip
            except IntegrityError:
                return True  # already stored by an earlier call: the first bundle stands
            return True
        except Exception as error:  # noqa: BLE001
            log.warning("evidence_not_stored", checkout=checkout_id, error=type(error).__name__)
            return False

    def get(self, capture_id: str) -> str | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(evidence_bundles.c.bundle).where(evidence_bundles.c.capture_id == capture_id)
            ).first()
        return None if row is None else str(row[0])

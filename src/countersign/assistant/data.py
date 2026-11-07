"""What the assistant may read, as a plain interface (docs/PROTOCOL.md Decision 125).

The assistant package imports no authorization module, so it cannot reach the database or PayPal itself.
The composition layer hands it a `DataSource` whose answers are the same read models the dashboard API
serves (explicit member lists, no secrets, no payer data). Every method only reads.
"""

from __future__ import annotations

from typing import Any, Protocol


class DataSource(Protocol):
    def orders(self) -> list[dict[str, Any]]:
        """Dashboard order rows, newest first."""

    def events(self) -> list[dict[str, Any]]:
        """Blocked and voided attempts from the decision log, newest first (each row has `seq`)."""

    def mandates(self) -> list[dict[str, Any]]:
        """Open mandates with their lifecycle state."""

    def evaluation(self) -> dict[str, Any] | None:
        """The latest evaluation summary (modes and one short entry per case and mode)."""

    def evidence(self, order_id: str) -> dict[str, Any] | None:
        """`{"state": ..., "steps": [{"name", "ok", "code"}] | None}` for one order, or None if unknown."""

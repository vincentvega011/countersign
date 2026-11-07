"""The assistant's data source: the dashboard's own read models, nothing else (Decision 125).

This adapter lives with the dashboard because it reads the same tables through the same explicit-member
read functions; the assistant package itself imports none of them. It only reads. Evidence steps come from
the standalone offline verifier (`countersign_verify`) run on the stored bundle with no pinned keys, the
same check the dashboard's Evidence view runs in the browser.
"""

from __future__ import annotations

import importlib
from typing import Any

from countersign.dashboard import read
from countersign.dashboard.service import DashboardService


class DashboardData:
    def __init__(self, service: DashboardService) -> None:
        self._service = service

    def orders(self) -> list[dict[str, Any]]:
        return read.orders(self._service.engine)

    def events(self) -> list[dict[str, Any]]:
        return read.protection_events(self._service.engine)

    def mandates(self) -> list[dict[str, Any]]:
        return read.mandates(self._service.engine, int(self._service.clock()))

    def evaluation(self) -> dict[str, Any] | None:
        return read.eval_summary(self._service.eval_path)

    def evidence(self, order_id: str) -> dict[str, Any] | None:
        found = read.order_detail(self._service.engine, order_id)
        if found is None:
            return None
        text = found["bundle_text"]
        if text is None:
            return {"state": found["state"], "steps": None}
        # Imported by name: the offline verifier is a separate, standalone package (Decision 105).
        verify_text = importlib.import_module("countersign_verify").verify_text

        steps = [{"name": r.name, "ok": bool(r.ok), "code": r.code} for r in verify_text(text)]
        return {"state": "bundle", "steps": steps}

"""The dev seed's open mandates: one per lifecycle state, labelled, deterministic, never unauthorized."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, text

from countersign.dashboard import read
from tests.mode_support import reset

ROOT = Path(__file__).resolve().parents[2]


def _seed() -> Any:
    spec = importlib.util.spec_from_file_location(
        "dashboard_seed", ROOT / "scripts" / "dashboard_seed.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _view(engine: Engine) -> list[dict[str, Any]]:
    return sorted(read.mandates(engine, 1_800_000_000), key=lambda m: m["id"])


def test_seeded_mandates_cover_every_state_and_are_labelled(
    app_engine: Engine, admin_engine: Engine
) -> None:
    reset(admin_engine)
    seed = _seed()
    assert seed.seed_mandates(admin_engine) == 5
    rows = _view(app_engine)
    states = {m["id"]: m["state"] for m in rows}
    assert states == {
        "om_sim_expired": "expired", "om_sim_flight": "in_flight", "om_sim_revoked": "revoked",
        "om_sim_unused": "unused", "om_sim_used": "used",
    }  # fmt: skip
    assert {m["source"] for m in rows} == {"simulator"}
    used = next(m for m in rows if m["state"] == "used")
    assert used["spent_minor"] == 5400
    # The seeded captured attempt has its mandates stored, so it is not an unauthorized capture.
    assert read.unauthorized_captures(app_engine) == 0


def test_the_mandate_seed_is_idempotent_and_deterministic(
    app_engine: Engine, admin_engine: Engine
) -> None:
    seed = _seed()
    reset(admin_engine)
    seed.seed_mandates(admin_engine)
    first = _view(app_engine)
    assert seed.seed_mandates(admin_engine) == 0
    reset(admin_engine)
    seed.seed_mandates(admin_engine)
    assert _view(app_engine) == first
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM open_mandates")).scalar_one() == 5

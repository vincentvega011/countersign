"""P5a on the real app: the self-check endpoint, rate-limit coverage of every mutating route, the demo seed."""

from __future__ import annotations

import importlib
from collections.abc import Iterable, Iterator
from typing import Any

from fastapi.routing import APIRoute
from sqlalchemy import Engine, text

from countersign.api import ratelimit
from countersign.dashboard import read
from countersign.demo_seed import seed
from countersign.runtime import Mode, RuntimeSettings
from tests.mode_support import make_world, reset


def _flat(routes: Iterable[Any], prefix: str) -> Iterator[tuple[str, APIRoute]]:
    """Every API route, including those of lazily included routers (their own prefix is in the path)."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix, route
        elif hasattr(route, "original_router"):
            extra = route.include_context.prefix
            yield from _flat(route.original_router.routes, prefix + extra)


def test_selfcheck_endpoint_reports_mode_and_flags_without_secrets(
    app_engine: Engine, admin_engine: Engine
) -> None:
    reset(admin_engine)
    w = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    with w.client:
        body = w.client.get("/selfcheck").json()
        assert body["mode"] == "full" and body["app_env"] == "demo"
        assert body["ablations"] == [] and body["dev_switches_on"] == []
        assert body["attack_runs_enabled"] is False and body["ok"] is True
        assert body["dashboard_read_only"] is True
        assert w.client.get("/selfcheck").headers["cache-control"] == "no-store"
        text_ = w.client.get("/selfcheck").text
        assert "postgres" not in text_ and "secret" not in text_.lower()


def test_every_mutating_route_that_is_public_has_a_rate_limit_rule(
    app_engine: Engine, admin_engine: Engine
) -> None:
    reset(admin_engine)
    w = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    limiter = ratelimit.RateLimiter()
    unlimited: list[str] = []
    seen = 0
    for prefix, route in _flat(w.client.app.routes, ""):  # type: ignore[attr-defined]
        for method in route.methods - {"GET", "HEAD", "OPTIONS"}:
            seen += 1
            path = (prefix + route.path).replace("{", "").replace("}", "")
            if limiter.rule_for(method, path) is None:
                unlimited.append(f"{method} {prefix}{route.path}")
    assert seen >= 15
    assert unlimited == [], unlimited


def test_the_demo_seed_fills_an_empty_database_once(
    app_engine: Engine, admin_engine: Engine
) -> None:
    reset(admin_engine)
    with (
        admin_engine.begin() as conn
    ):  # `reset` leaves stored bundles; the seed expects an empty database
        conn.execute(text("TRUNCATE evidence_bundles"))
    first = seed(admin_engine, orders=12, shops=1)
    assert first["recorded_rows"] == 2 and first["evidence_bundle_rows"] == 1
    assert first["open_mandates"] == 5 and sum(first["simulated_scenarios"].values()) > 0  # type: ignore[union-attr]
    with admin_engine.connect() as conn:
        sources = dict(
            conn.execute(text("SELECT source, count(*) FROM checkout_sources GROUP BY 1")).all()
        )
    assert sources["recorded"] == 2 and sources["simulator"] > 1
    assert "live_sandbox" not in sources  # nothing is passed off as a live sandbox capture
    states = {m["state"] for m in read.mandates(app_engine, 1_800_000_000)}
    assert {"unused", "used", "revoked"} <= states
    assert read.unauthorized_captures(app_engine) == 0
    second = seed(admin_engine, orders=12, shops=1)
    assert second == {"recorded_rows": 0, "evidence_bundle_rows": 0, "open_mandates": 0,
                      "simulated_scenarios": {}}  # fmt: skip


def test_the_seed_refuses_outside_dev_and_demo(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import pytest

    module = importlib.import_module("countersign.demo_seed")
    monkeypatch.setenv("APP_ENV", "prod")
    with pytest.raises(SystemExit, match="refused"):
        module.main([])


def test_the_demo_reports_the_launcher_off_with_a_reason_and_refuses_runs(
    app_engine: Engine, admin_engine: Engine
) -> None:
    reset(admin_engine)
    w = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    with w.client:
        body = w.client.get("/dashboard/api/v1/attack-runs").json()
        assert body["enabled"] is False and body["reason"] == "hosted_demo"
        r = w.client.post(
            "/dashboard/api/v1/attack-runs",
            json={"attack": "protocol_downgrade_acp"},
            headers={"X-Countersign-Dashboard": "1"},
        )
        assert r.status_code == 403 and r.json() == {"code": "attack_runs_disabled"}


def test_the_database_url_and_inline_keys_are_normalised() -> None:
    from countersign.dburl import database_url

    assert database_url({"DATABASE_URL": "postgres://u:p@h/db"}) == "postgresql+psycopg://u:p@h/db"
    assert (
        database_url({"DATABASE_URL": "postgresql://u:p@h/db"}) == "postgresql+psycopg://u:p@h/db"
    )
    keep = "postgresql+psycopg://u:p@h/db"
    assert database_url({"DATABASE_URL": keep}) == keep

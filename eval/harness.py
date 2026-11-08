"""Run one case in one configuration against a scratch Postgres, and judge it.

The database is created and migrated the way the integration tests do it (the real migrations, the
real restricted application role), once per run, and emptied between cases by the administrator.
Configurations are the names of `tests.mode_support.CONFIGS` (`full`, `baseline` and the six
ablations), so a case can be run with a defense weakened.
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from alembic import command
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url

from countersign.runtime import RuntimeSettings
from eval.core import AttackCase, Ctx
from eval.judge import Verdict, judge
from tests.integration.conftest import (
    DEFAULT_ADMIN_URL,
    alembic_config,
    create_database,
    drop_database,
    scratch_urls,
)
from tests.mode_support import make_world, settings_for
from tests.mode_support import reset as _reset


@dataclass(frozen=True)
class Databases:
    admin: Engine
    app: Engine


@contextmanager
def scratch_databases() -> Iterator[Databases]:
    server_url = os.environ.get("EVAL_DATABASE_ADMIN_URL", DEFAULT_ADMIN_URL)
    name, admin_url = scratch_urls(server_url)
    role = "cs_eval_" + uuid.uuid4().hex[:10]
    password = secrets.token_hex(16)
    create_database(server_url, name)
    admin = app = None
    try:
        command.upgrade(alembic_config(admin_url, role), "head")
        admin = create_engine(admin_url, pool_size=4)
        with admin.begin() as conn:
            conn.execute(text(f"ALTER ROLE \"{role}\" LOGIN PASSWORD '{password}'"))
        app_url = (
            make_url(admin_url)
            .set(username=role, password=password)
            .render_as_string(hide_password=False)
        )
        app = create_engine(app_url, pool_size=12, max_overflow=12)
        yield Databases(admin, app)
    finally:
        for engine in (app, admin):
            if engine is not None:
                engine.dispose()
        drop_database(server_url, name, role)


@dataclass(frozen=True)
class BundleJob:
    """A stored evidence bundle and the service keys to pin when verifying it (see `eval.verify`)."""

    capture_id: str
    text: str
    merchant_jwk: dict[str, Any]
    platform_jwk: dict[str, Any]


@dataclass
class CaseRun:
    verdict: Verdict
    reason: str | None
    side_effects: list[str]
    error: str | None = None
    bundles: list[BundleJob] = field(default_factory=list)


def collect_bundles(world: Any, admin: Engine) -> list[BundleJob]:
    """Every evidence bundle the app stored, with the merchant and platform public keys it signs with."""
    with admin.connect() as conn:
        rows = conn.execute(
            text("SELECT capture_id, bundle FROM evidence_bundles ORDER BY capture_id")
        ).all()
    if not rows:
        return []
    public = world.keys.issuer.as_dict(private=False)
    platform = {k: public[k] for k in ("kty", "crv", "x", "y")}
    merchant = dict(world.merchant_key.public_jwk)
    return [BundleJob(str(r[0]), str(r[1]), merchant, platform) for r in rows]


def reset(admin: Engine) -> None:
    """Empty the tables the cases use, and the evidence tables the shared reset leaves alone."""
    _reset(admin)
    with admin.begin() as conn:
        conn.execute(text("TRUNCATE paypal_observations, evidence_bundles CASCADE"))


def run_case(case: AttackCase, config: str | RuntimeSettings, dbs: Databases) -> CaseRun:
    """`config` is a name from `tests.mode_support.CONFIGS` or explicit runtime settings."""
    reset(dbs.admin)
    settings = settings_for(config) if isinstance(config, str) else config
    world = make_world(dbs.app, settings, webhook_id=case.webhook_id)
    ctx = Ctx(world, dbs.admin, settings.mode.value)
    error = None
    with world.client:
        try:
            case.run(ctx)
        except Exception as exc:  # noqa: BLE001 - a crashed case is reported, never counted as blocked
            error = f"{type(exc).__name__}: {exc}"[:200]
    verdict = judge(ctx, dbs.app)
    return CaseRun(
        verdict, ctx.reason, sorted(ctx.side_effects), error, collect_bundles(world, dbs.admin)
    )

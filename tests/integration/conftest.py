"""Fixtures for tests that need the real Postgres from docker-compose.

A scratch database is created per test session and migrated with Alembic, so the tests exercise the
real migration, and the application role is a real login role created by that migration. If
Postgres is unreachable the tests fail with an instruction; they are not skipped, because a skipped
grants test would hide exactly the property it exists to prove.

Start the database with `make db` (or `docker compose up -d --wait postgres`). In CI a Postgres
service provides it. DATABASE_URL names an administrator connection (the compose default is used
when unset).
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ADMIN_URL = "postgresql+psycopg://countersign:countersign@localhost:5432/countersign"


@dataclass(frozen=True)
class LedgerDb:
    admin_url: str  # superuser connection to the scratch database
    app_url: str  # login as the restricted application role
    role: str
    name: str
    server_url: str  # superuser connection to the maintenance database


def alembic_config(url: str, role: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    config.attributes["app_role"] = role
    return config


def scratch_urls(server_url: str) -> tuple[str, str]:
    name = "cs_test_" + uuid.uuid4().hex[:12]
    url = make_url(server_url).set(database=name).render_as_string(hide_password=False)
    return name, url


@pytest.fixture(scope="session")
def server_url() -> str:
    url = os.environ.get("DATABASE_URL", DEFAULT_ADMIN_URL)
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError:
        pytest.fail(
            "Postgres is not reachable. Start it with `make db` "
            "(docker compose up -d --wait postgres), or set DATABASE_URL to an administrator URL."
        )
    finally:
        engine.dispose()
    return url


def create_database(server_url: str, name: str) -> None:
    engine = create_engine(server_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    engine.dispose()


def drop_database(server_url: str, name: str, role: str | None) -> None:
    engine = create_engine(server_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        if role:
            conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
    engine.dispose()


@pytest.fixture(scope="session")
def ledger_db(server_url: str) -> Iterator[LedgerDb]:
    name, admin_url = scratch_urls(server_url)
    role = "cs_app_" + uuid.uuid4().hex[:10]
    password = secrets.token_hex(16)
    create_database(server_url, name)
    try:
        command.upgrade(alembic_config(admin_url, role), "head")
        admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
        with admin.connect() as conn:
            conn.execute(text(f"ALTER ROLE \"{role}\" LOGIN PASSWORD '{password}'"))
        admin.dispose()
        app_url = (
            make_url(admin_url)
            .set(username=role, password=password)
            .render_as_string(hide_password=False)
        )
        yield LedgerDb(admin_url, app_url, role, name, server_url)
    finally:
        drop_database(server_url, name, role)


@pytest.fixture(scope="session")
def admin_engine(ledger_db: LedgerDb) -> Iterator[Engine]:
    engine = create_engine(ledger_db.admin_url, pool_size=4)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def app_engine(ledger_db: LedgerDb) -> Iterator[Engine]:
    engine = create_engine(ledger_db.app_url, pool_size=12, max_overflow=12)
    yield engine
    engine.dispose()


@pytest.fixture
def clean_log(admin_engine: Engine) -> None:
    """An empty log for the test (the administrator may truncate; the application role may not)."""
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE decision_log"))


@pytest.fixture
def clean_checkouts(admin_engine: Engine) -> None:
    """Empty checkout and log tables for the test (the administrator may truncate)."""
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE checkout_sessions, decision_log"))

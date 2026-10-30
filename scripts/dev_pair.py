"""Start a full instance and a baseline instance side by side, each on its own database.

`make dev-pair` runs this. Full serves on :8000 and baseline on :8001 (override with FULL_PORT and
BASELINE_PORT). Each gets its own database (`countersign_full`, `countersign_baseline`) and its own
restricted login role, both created and migrated here against the compose Postgres, so the two never
share a reservation, a ledger row or a log. Local development only: the passwords are fixed and the
admin URL is the compose default (`DATABASE_ADMIN_URL` overrides it).

PayPal sandbox variables and the key paths come from the environment (see .env.example). Without
sandbox credentials the instances start, and any PayPal call fails closed.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ADMIN_URL = os.environ.get(
    "DATABASE_ADMIN_URL", "postgresql+psycopg://countersign:countersign@localhost:5432/countersign"
)
INSTANCES = (("full", "FULL_PORT", "8000"), ("baseline", "BASELINE_PORT", "8001"))


def prepare(mode: str) -> str:
    """Create the database and the login role if missing, migrate, return the app URL."""
    database, role = f"countersign_{mode}", f"cs_app_{mode}"
    server = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        if not conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": database}
        ).first():
            conn.execute(text(f'CREATE DATABASE "{database}"'))
    server.dispose()
    admin_url = make_url(ADMIN_URL).set(database=database).render_as_string(hide_password=False)
    config = Config("alembic.ini")
    config.set_main_option("script_location", "migrations")
    config.set_main_option("sqlalchemy.url", admin_url)
    config.attributes["app_role"] = role
    command.upgrade(config, "head")
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text(f"ALTER ROLE \"{role}\" LOGIN PASSWORD '{role}'"))
    engine.dispose()
    return (
        make_url(admin_url).set(username=role, password=role).render_as_string(hide_password=False)
    )


def main() -> int:
    procs: list[subprocess.Popen[bytes]] = []
    for mode, port_var, default_port in INSTANCES:
        port = os.environ.get(port_var, default_port)
        env = dict(os.environ)
        env.update(
            CS_MODE=mode,
            APP_ENV=os.environ.get("APP_ENV", "dev"),
            DATABASE_URL=prepare(mode),
            PUBLIC_BASE_URL=f"http://localhost:{port}",
        )
        env.setdefault("PAYPAL_CLIENT_ID", "unset")
        env.setdefault("PAYPAL_CLIENT_SECRET", "unset")
        for name in list(env):  # an ablation belongs to a full instance you start by hand
            if name.startswith("ABL_"):
                del env[name]
        cmd = [sys.executable, "-m", "uvicorn", "countersign.main:create", "--factory",
               "--port", port]  # fmt: skip
        procs.append(subprocess.Popen(cmd, env=env))
        print(f"{mode}: http://localhost:{port}/health (database countersign_{mode})", flush=True)
    try:
        return max(p.wait() for p in procs)
    except KeyboardInterrupt:
        return 0
    finally:
        for p in procs:
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)


if __name__ == "__main__":
    raise SystemExit(main())

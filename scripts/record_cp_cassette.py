"""Record the Credential Provider happy-path cassette from the live PayPal sandbox.

What it does, in order (the same code the replay test runs, tests/cp_flow.py):

1. Creates a scratch Postgres database from DATABASE_URL (the compose default if unset), migrates it
   with Alembic and connects as a restricted application role, exactly like production.
2. Asks PayPal for the sandbox business account's merchant id with one throwaway order (not recorded).
3. Signs a checkout and the Checkout and Payment Mandates for it (public keys only are kept).
4. Runs the Credential Provider: verify, reserve, create the PayPal order, then PRINTS THE APPROVAL
   LINK AND WAITS while you approve it with the sandbox buyer, then runs the pre-authorize check
   and authorizes. Nothing is captured.
5. Saves the scrubbed PayPal exchange to tests/cassettes/cp_authorize.json and the mandates the
   replay needs to tests/cassettes/cp_authorize.mandates.json, then drops the scratch database.

Recording is off unless you opt in:

    PAYPAL_RECORD_CASSETTES=1 uv run python scripts/record_cp_cassette.py

Credentials come from the environment or the git-ignored .env (PAYPAL_API_BASE, PAYPAL_CLIENT_ID,
PAYPAL_CLIENT_SECRET). The sandbox host is enforced. Nothing secret is printed. The authorization is
left in the sandbox (it expires by itself); it is not captured and not voided.
"""

from __future__ import annotations

import datetime as dt
import os
import secrets
import sys
import uuid
from pathlib import Path

import httpx
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # the flow lives in tests/, never in the package

from countersign.paypal.cassette import RecordingTransport, recording_enabled
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.paypal.errors import PayPalError
from countersign.paypal.translate import order_request_from_checkout
from scripts.record_paypal_cassette import parse_env_file
from tests.cp_flow import (
    CANCEL_URL,
    RETURN_URL,
    build_fixture,
    flow_checkout,
    make_provider,
    run_flow,
)

CASSETTE = ROOT / "tests" / "cassettes" / "cp_authorize.json"
FIXTURE = ROOT / "tests" / "cassettes" / "cp_authorize.mandates.json"
DEFAULT_ADMIN_URL = "postgresql+psycopg://countersign:countersign@localhost:5432/countersign"


def scratch_database(admin_url: str) -> tuple[str, str, str]:
    """Create and migrate a scratch database; return (name, restricted URL, role)."""
    name = "cs_record_" + uuid.uuid4().hex[:12]
    role = "cs_rec_" + uuid.uuid4().hex[:10]
    password = secrets.token_hex(16)
    server = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    server.dispose()
    url = make_url(admin_url).set(database=name).render_as_string(hide_password=False)
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    config.attributes["app_role"] = role
    command.upgrade(config, "head")
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"ALTER ROLE \"{role}\" LOGIN PASSWORD '{password}'"))
    admin.dispose()
    app_url = (
        make_url(url).set(username=role, password=password).render_as_string(hide_password=False)
    )
    return name, app_url, role


def drop_database(admin_url: str, name: str, role: str) -> None:
    server = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
    server.dispose()


def discover_payee_merchant_id(config: PayPalConfig) -> str:
    """The sandbox business account's merchant id, read from one unrecorded throwaway order."""
    checkout = flow_checkout("chk_" + secrets.token_urlsafe(16))
    from countersign.paypal.models import ExperienceContext

    request = order_request_from_checkout(
        checkout,
        custom_id="cs1.discovery",
        experience_context=ExperienceContext(RETURN_URL, CANCEL_URL),
    )
    with PayPalClient(config) as client:
        created = client.create_order(checkout.id, request)
        order = client.get_order(created.resource_id)
    merchant_id = (
        order.purchase_units[0].payee.merchant_id if order.purchase_units[0].payee else None
    )
    if not merchant_id:
        raise RuntimeError("PayPal did not report the payee merchant id")
    return merchant_id


def approve(url: str) -> None:
    print()
    print("Approve the order as the sandbox buyer (a US-based sandbox account), then come back.")
    print(f"  {url}")
    input("Press Enter once the order is approved: ")


def main() -> int:
    env = parse_env_file(ROOT / ".env")
    env.update(
        {k: v for k, v in os.environ.items() if k.startswith(("PAYPAL_", "DATABASE_")) and v}
    )
    if not recording_enabled(env):
        print("Recording is off. Run with PAYPAL_RECORD_CASSETTES=1 to record.", file=sys.stderr)
        return 2
    config = PayPalConfig.from_env(env)
    admin_url = env.get("DATABASE_URL", DEFAULT_ADMIN_URL)
    checkout_id = "chk_" + secrets.token_urlsafe(16)
    meta = {
        "checkout_id": checkout_id,
        "recorded_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": "sandbox",
        "flow": "countersign Credential Provider: verify, reserve, create order, approve, authorize",
    }
    print("Reading the sandbox merchant id (one throwaway order, not recorded)...")
    try:
        merchant_id = discover_payee_merchant_id(config)
    except (PayPalError, RuntimeError) as exc:
        print(f"Could not read the merchant id: {exc}", file=sys.stderr)
        return 1
    name, app_url, role = scratch_database(admin_url)
    engine = create_engine(app_url)
    transport = RecordingTransport(
        httpx.HTTPTransport(),
        secrets=[config.client_id, config.client_secret, merchant_id],
        meta=meta,
    )
    fixture = build_fixture(checkout_id)
    try:
        with PayPalClient(config, transport=transport) as client:
            provider = make_provider(engine, client, fixture, payee_merchant_id=merchant_id)
            _started, finished = run_flow(provider, fixture, approve)
    except PayPalError as exc:
        print(f"The flow failed: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
        drop_database(admin_url, name, role)
    from countersign.cp import CpAuthorized

    if not isinstance(finished, CpAuthorized):
        print(
            f"Not saved: the flow ended with {type(finished).__name__}: {finished}", file=sys.stderr
        )
        return 1
    transport.save(CASSETTE)
    FIXTURE.write_text(fixture.to_json(), encoding="utf-8")
    print()
    print(f"Saved {CASSETTE.relative_to(ROOT)} and {FIXTURE.relative_to(ROOT)}")
    print(f"  checkout {checkout_id}")
    print(
        f"  order {finished.order_id}, authorization {finished.authorization_id}, {finished.amount}"
    )
    print("The authorization was not captured. Check the files before you commit them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

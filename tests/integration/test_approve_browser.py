"""Browser tests of the Trusted Surface setup page (web/approve/test), against the real app.

The app runs on a real Postgres, as the restricted application role, on a free local port; Node runs
the Playwright tests against it. A failure prints the Node output. If Chromium is missing the test
fails, it is not skipped (`pnpm --filter @countersign/approve exec playwright install chromium`).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from joserfc.jwk import ECKey
from sqlalchemy import Engine, text

from countersign.api.app import create_app
from countersign.checkout.state import Status
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.trusted_surface import TrustedSurface
from tests.checkout_seed import seed_checkout
from tests.merchant_support import make_checkout

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def running_app(app_engine: Engine, admin_engine: Engine) -> Iterator[str]:
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE consent_records, key_revocations, key_challenge_uses, key_challenges, "
                "customer_keys, open_mandate_revocations, purchase_offers, activity_sessions, "
                "checkout_sessions, checkout_customers, checkout_sources, decision_log CASCADE"
            )
        )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    base = f"http://127.0.0.1:{sock.getsockname()[1]}"
    merchant_key = validate_jwk(generate_jwk())
    app = create_app(
        key=merchant_key,
        public_base_url=base,
        engine=app_engine,
        trusted_surface=TrustedSurface(
            app_engine,
            public_origin=base,
            platform_key=ECKey.generate_key("P-256"),
            issuer=base,
            merchant_key=merchant_key,
        ),
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started, "the app did not start"
    try:
        yield base
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


# One fresh checkout per purchase test: a checkout belongs to the first customer who opens it
# (Decision 111), and every test enrols its own customer.
CHECKOUT_IDS = tuple(f"chk_{n:02d}" + "X" * 20 for n in range(40))


def seed_checkouts(engine: Engine) -> list[dict[str, object]]:
    """Ready checkouts the Approve purchase tests open; described for Node in `APPROVE_CHECKOUTS`."""
    found: list[dict[str, object]] = []
    for checkout_id in CHECKOUT_IDS:
        checkout = make_checkout(checkout_id=checkout_id)
        seed_checkout(engine, checkout, status=Status.READY_FOR_COMPLETE)
        line = checkout.line_items[0]
        found.append(
            {
                "id": checkout.id,
                "title": line.item.title,
                "quantity": line.quantity,
                "line_minor": line.totals[0].amount.minor,
                "total_minor": next(t.amount.minor for t in checkout.totals if t.type == "total"),
            }
        )
    return found


def test_the_setup_page_in_a_real_browser(
    running_app: str, app_engine: Engine, admin_engine: Engine, tmp_path: Path
) -> None:
    node = shutil.which("node")
    assert node, "node is required for the browser tests"
    report = tmp_path / "report.txt"
    report.write_text("")
    result = subprocess.run(
        [
            node,
            "--test",
            "--test-concurrency=1",
            "test/enrol.test.mjs",
            "test/intent.test.mjs",
            "test/purchase.test.mjs",
            "test/activity.test.mjs",
        ],
        cwd=ROOT / "web" / "approve",
        env={
            **os.environ,
            "APPROVE_BASE_URL": running_app,
            "APPROVE_REPORT": str(report),
            "APPROVE_CHECKOUTS": json.dumps(seed_checkouts(app_engine)),
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout[-60000:] + result.stderr[-3000:]
    # Every registration the browser made is in the add-only table and in the log.
    with admin_engine.connect() as conn:
        keys = conn.execute(text("SELECT count(*) FROM customer_keys")).scalar()
        logged = conn.execute(
            text("SELECT count(*) FROM decision_log WHERE kind = 'ts.key.registered'")
        ).scalar()
    assert keys and keys == logged
    # Every approval the browser reported is a stored consent with two mandates, and a request that was
    # changed on the way, expired or declined issued nothing: the counts are equal.
    approvals = report.read_text().split().count("consent_ok")
    with admin_engine.connect() as conn:
        consents = conn.execute(text("SELECT count(*) FROM consent_records")).scalar()
        refused = conn.execute(
            text("SELECT count(*) FROM decision_log WHERE kind = 'ts.consent.refused'")
        ).scalar()
    assert approvals >= 5 and consents == approvals
    assert refused and refused >= 6  # the tampered requests were refused and logged


def test_purchases_and_revocations_the_browser_made_are_in_the_add_only_tables(
    admin_engine: Engine,
) -> None:
    """Runs after the browser test: it left behind what the pages did, and every one is logged."""
    with admin_engine.connect() as conn:
        issued = conn.execute(text("SELECT count(*) FROM purchase_consents")).scalar() or 0
        logged = (
            conn.execute(
                text("SELECT count(*) FROM decision_log WHERE kind = 'ts.purchase.issued'")
            ).scalar()
            or 0
        )
        revoked = conn.execute(text("SELECT count(*) FROM open_mandate_revocations")).scalar() or 0
        revoke_logged = (
            conn.execute(
                text("SELECT count(*) FROM decision_log WHERE kind = 'ts.mandate.revoked'")
            ).scalar()
            or 0
        )
    assert issued == logged and revoked == revoke_logged

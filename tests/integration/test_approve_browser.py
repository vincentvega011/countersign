"""Browser tests of the Trusted Surface setup page (web/approve/test), against the real app.

The app runs on a real Postgres, as the restricted application role, on a free local port; Node runs
the Playwright tests against it. A failure prints the Node output. If Chromium is missing the test
fails, it is not skipped (`pnpm --filter @countersign/approve exec playwright install chromium`).
"""

from __future__ import annotations

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
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.trusted_surface import TrustedSurface

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def running_app(app_engine: Engine, admin_engine: Engine) -> Iterator[str]:
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE consent_records, key_revocations, key_challenge_uses, key_challenges, "
                "customer_keys, decision_log CASCADE"
            )
        )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    base = f"http://127.0.0.1:{sock.getsockname()[1]}"
    app = create_app(
        key=validate_jwk(generate_jwk()),
        public_base_url=base,
        engine=app_engine,
        trusted_surface=TrustedSurface(
            app_engine, public_origin=base, platform_key=ECKey.generate_key("P-256"), issuer=base
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


def test_the_setup_page_in_a_real_browser(
    running_app: str, admin_engine: Engine, tmp_path: Path
) -> None:
    node = shutil.which("node")
    assert node, "node is required for the browser tests"
    report = tmp_path / "report.txt"
    report.write_text("")
    result = subprocess.run(
        [node, "--test", "--test-concurrency=1", "test/enrol.test.mjs", "test/intent.test.mjs"],
        cwd=ROOT / "web" / "approve",
        env={**os.environ, "APPROVE_BASE_URL": running_app, "APPROVE_REPORT": str(report)},
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout[-6000:] + result.stderr[-3000:]
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

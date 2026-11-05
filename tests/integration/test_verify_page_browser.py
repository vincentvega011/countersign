"""Browser tests of the evidence verifier page (`web/ui/test/verify-page.test.mjs`), against the real app.

The app runs in `demo` mode (the page and `GET /evidence/{capture_id}` are served in every mode) on a real
Postgres, as the restricted application role, with the committed valid bundle stored under its capture id
so the page can load it. Node drives Chromium. If Chromium is missing the test fails, it is not skipped.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from subprocess import run

import pytest
import uvicorn
from sqlalchemy import Engine, insert, text

from countersign.api.app import create_app
from countersign.evidence import EvidenceService
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.runtime import RuntimeSettings
from countersign.tables import evidence_bundles

ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "tests" / "vectors" / "evidence" / "valid.json"


@pytest.fixture
def verify_app(app_engine: Engine, admin_engine: Engine) -> Iterator[str]:
    bundle = json.loads(VALID.read_text())
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE evidence_bundles"))
        conn.execute(
            insert(evidence_bundles).values(
                capture_id=bundle["capture_id"], checkout_id=bundle["checkout_id"],
                bundle=VALID.read_text(), created_us=1,
            )
        )  # fmt: skip
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    base = f"http://127.0.0.1:{sock.getsockname()[1]}"
    service = EvidenceService(
        app_engine, merchant_jwk=bundle["keys"]["merchant"], platform_jwk=bundle["keys"]["platform"],
        clock_us=lambda: 1, policy_hash=b"\x00" * 32,
    )  # fmt: skip
    app = create_app(
        key=validate_jwk(generate_jwk()), public_base_url=base, engine=app_engine,
        runtime=RuntimeSettings(app_env="demo"), evidence=service,
    )  # fmt: skip
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
        with admin_engine.begin() as conn:
            conn.execute(text("TRUNCATE evidence_bundles"))


def test_the_verifier_page_in_a_real_browser(verify_app: str) -> None:
    node = shutil.which("node")
    assert node, "node is required for the browser tests"
    result = run(
        [node, "--test", "--test-concurrency=1", "test/verify-page.test.mjs"],
        cwd=ROOT / "web" / "ui",
        env={**os.environ, "VERIFY_BASE_URL": verify_app},
        check=False, capture_output=True, text=True, timeout=300,
    )  # fmt: skip
    assert result.returncode == 0, result.stdout[-60000:] + result.stderr[-3000:]

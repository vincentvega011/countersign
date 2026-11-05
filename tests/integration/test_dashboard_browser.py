"""Browser tests of the merchant dashboard on AG Studio (web/dashboard/test), against the real app.

The app runs in `demo` over the PayPal simulator on a real Postgres; the database is filled by the seed
script's simulated scenarios (every row labelled). Expected numbers are computed here with SQL, not
from the dashboard API, and handed to Node. The test needs the built dashboard (`make dashboard-build`;
CI builds it without the licence key). The licence assertion runs only when the build carries the
local key; without it the test says so and still checks everything else. Chromium missing is a failure.
"""

from __future__ import annotations

import importlib.util
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
from sqlalchemy import Engine, text

from countersign.runtime import Mode, RuntimeSettings
from tests.mode_support import make_world, reset

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "web" / "dashboard" / "dist"


def _seed_module():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "dashboard_seed", ROOT / "scripts" / "dashboard_seed.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _licensed_build() -> bool:
    from tests.unit.test_licence_key_not_committed import _local_key

    key = _local_key()
    if not key:
        return False
    return any(key in p.read_text(errors="ignore") for p in (DIST / "assets").glob("*.js"))


@pytest.fixture
def served(app_engine: Engine, admin_engine: Engine) -> Iterator[tuple[str, dict[str, object]]]:
    assert (DIST / "index.html").is_file(), "build the dashboard first: make dashboard-build"
    reset(admin_engine)
    _seed_module().seed_simulated(app_engine, 120, 2)
    world = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    app = world.client.app
    with admin_engine.connect() as conn:
        expected = {
            "orders": conn.execute(text("SELECT count(*) FROM checkout_sessions")).scalar_one(),
            "captured": conn.execute(
                text("SELECT count(*) FROM payment_attempts WHERE state = 'captured'")
            ).scalar_one(),
            "unauthorized": conn.execute(
                text(
                    "SELECT (SELECT count(*) FROM payment_attempts a WHERE a.state = 'captured' "
                    "AND NOT EXISTS (SELECT 1 FROM attempt_mandates m "
                    "WHERE m.checkout_id = a.checkout_id)) + (SELECT count(*) FROM decision_log "
                    "WHERE kind = 'degraded.unmandated.captured')"
                )
            ).scalar_one(),
            "newest": conn.execute(
                text("SELECT id FROM checkout_sessions ORDER BY created_us DESC LIMIT 1")
            ).scalar_one(),
            "simulated": conn.execute(
                text("SELECT count(*) FROM checkout_sources WHERE source = 'simulator'")
            ).scalar_one(),
        }
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    base = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    try:
        yield base, expected
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


def test_the_dashboard_in_a_real_browser(served: tuple[str, dict[str, object]]) -> None:
    base, expected = served
    node = shutil.which("node")
    assert node, "node is required for the browser tests"
    licensed = _licensed_build()
    if not licensed:
        print("licence assertion skipped: the dashboard build does not carry a local licence key")
    result = subprocess.run(
        [node, "--test", "--test-concurrency=1", "test/dashboard.test.mjs"],
        cwd=ROOT / "web" / "dashboard",
        env={
            **os.environ,
            "DASHBOARD_BASE_URL": base,
            "DASHBOARD_EXPECT": json.dumps(expected),
            "DASHBOARD_LICENSED": "1" if licensed else "0",
        },
        check=False, capture_output=True, text=True, timeout=300,
    )  # fmt: skip
    assert result.returncode == 0, result.stdout[-30000:] + result.stderr[-3000:]

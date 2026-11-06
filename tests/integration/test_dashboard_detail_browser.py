"""Browser tests of the dashboard's order detail, evidence and protection views and the attack matrix.

Two databases, one per test: a clean one holding a verifying bundle, and a hostile one holding bundles
and orders whose text members are HTML and script payloads. Expected numbers come from SQL run here and
are handed to Node (web/dashboard/test/*.test.mjs). Needs the built dashboard (`make dashboard-build`).
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
from typing import Any

import pytest
import uvicorn
from sqlalchemy import Engine, insert, text

from countersign.canonical import canonicalize
from countersign.checkout.store import checkout_sessions
from countersign.runtime import Mode, RuntimeSettings
from countersign.tables import checkout_customers, checkout_sources
from tests.dashboard_rows import insert_bundle_order, vector_text
from tests.integration.test_dashboard_browser import ROOT, _licensed_build, _seed_module
from tests.mode_support import make_world, reset

XSS_IMG = '<img src=x onerror="window.__xss=1">'
XSS_SCRIPT = "<script>window.__xss=2</script>"
XSS_BOLD = '<b onmouseover="window.__xss=4">bold</b>'


def _scalar(admin: Engine, sql: str) -> Any:
    with admin.connect() as conn:
        return conn.execute(text(sql)).scalar_one()


def _start(app: Any) -> tuple[str, Any, threading.Thread, socket.socket]:
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
    return base, server, thread, sock


def _expectations(admin: Engine) -> dict[str, Any]:
    return {
        "orders": _scalar(admin, "SELECT count(*) FROM checkout_sessions"),
        "captured": _scalar(
            admin, "SELECT count(*) FROM payment_attempts WHERE state = 'captured'"
        ),
        "voids": _scalar(admin, "SELECT count(*) FROM decision_log WHERE kind = 'gate.rejected'"),
        "mandates": _scalar(admin, "SELECT count(*) FROM open_mandates"),
        "events": _scalar(
            admin,
            "SELECT count(*) FROM decision_log WHERE kind IN ('checkout.complete_rejected', "
            "'acp.create_denied', 'acp.update_denied', 'acp.complete_denied', 'gate.rejected', "
            "'checkout.customer_refused', 'degraded.unmandated.captured') "
            "OR (kind = 'lock.decision' AND convert_from(payload, 'UTF8')::jsonb ->> 'allowed' = 'false')",
        ),
        "events_of_captured": _scalar(
            admin,
            "SELECT count(*) FROM decision_log WHERE (kind IN ('checkout.complete_rejected', "
            "'acp.create_denied', 'acp.update_denied', 'acp.complete_denied', 'gate.rejected', "
            "'checkout.customer_refused', 'degraded.unmandated.captured') "
            "OR (kind = 'lock.decision' AND convert_from(payload, 'UTF8')::jsonb ->> 'allowed' = 'false')) "
            "AND checkout_id IN (SELECT checkout_id FROM payment_attempts WHERE state = 'captured')",
        ),
        "simulated_no_bundle": _scalar(
            admin,
            "SELECT id FROM checkout_sessions s WHERE NOT EXISTS (SELECT 1 FROM evidence_bundles e "
            "WHERE e.checkout_id = s.id) AND NOT EXISTS (SELECT 1 FROM payment_attempts a "
            "WHERE a.checkout_id = s.id) ORDER BY created_us DESC LIMIT 1",
        ),
    }


def _run(base: str, expected: dict[str, Any], files: list[str]) -> None:
    node = shutil.which("node")
    assert node, "node is required for the browser tests"
    result = subprocess.run(
        [node, "--test", "--test-concurrency=1", *files],
        cwd=ROOT / "web" / "dashboard",
        env={
            **os.environ,
            "DASHBOARD_BASE_URL": base,
            "DASHBOARD_EXPECT": json.dumps(expected),
            "DASHBOARD_LICENSED": "1" if _licensed_build() else "0",
        },
        check=False, capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    assert result.returncode == 0, result.stdout[-30000:] + result.stderr[-3000:]


def _open_mandates(admin: Engine) -> None:
    """Three open mandates in three states (unused, expired, used) for the Protection view."""
    bundle = json.loads(vector_text("valid.json"))
    now = int(time.time())
    with admin.begin() as conn:
        # The consent rows these mandates would reference are a long chain (challenge, device key); the
        # dashboard only reads the mandates, so the foreign key is not enforced for these inserts.
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        for n, (exp, ceiling) in enumerate(
            [(now + 86_400, 8000), (now - 3600, 5000), (now + 3600, 12000)]
        ):
            conn.execute(
                text(
                    "INSERT INTO open_mandates (id, checkout_identity, customer_id, consent_id, "
                    "agent_thumbprint, ceiling_minor, currency, exp, created_us) VALUES "
                    "(:id, :co, :cust, :consent, :agent, :ceiling, 'USD', :exp, :created)"
                ),
                {
                    "id": f"om_pay_{n}", "co": f"om_chk_{n}", "cust": bundle["consent"]["customer_id"],
                    "consent": f"consent_{n}", "agent": "A" * 43, "ceiling": ceiling, "exp": exp,
                    "created": now * 1_000_000 + n,
                },
            )  # fmt: skip


@pytest.fixture
def clean(app_engine: Engine, admin_engine: Engine) -> Iterator[tuple[str, dict[str, Any]]]:
    reset(admin_engine)
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE evidence_bundles"))
    _seed_module().seed_simulated(app_engine, 60, 2)
    ids = insert_bundle_order(app_engine, vector_text("valid.json"))
    _open_mandates(admin_engine)
    world = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    expected = {**_expectations(admin_engine), **ids}
    base, server, thread, sock = _start(world.client.app)
    try:
        yield base, expected
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


@pytest.fixture
def hostile(app_engine: Engine, admin_engine: Engine) -> Iterator[tuple[str, dict[str, Any]]]:
    reset(admin_engine)
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE evidence_bundles"))
    _seed_module().seed_simulated(app_engine, 20, 1)
    bundle = json.loads(vector_text("valid.json"))
    unit = bundle["paypal"]["order"][-1]["purchase_units"][0]
    unit["items"][0]["name"] = XSS_IMG
    unit["custom_id"] = XSS_SCRIPT
    record = json.loads(bundle["consent"]["record"])
    record["terms"]["note"] = XSS_BOLD
    bundle["consent"]["record"] = canonicalize(record).decode()
    ids = insert_bundle_order(app_engine, canonicalize(bundle).decode())
    now = time.time_ns() // 1000 + 1_000_000
    body = {
        "id": "chk_HostilePlainRow0123456", "currency": "USD", "status": "ready_for_complete",
        "line_items": [{"id": "li_1", "quantity": 1, "item": {
            "id": "x", "title": '<img src=x onerror="window.__xss=3">', "price": 100}}],
        "totals": [{"type": "total", "amount": 100}],
    }  # fmt: skip
    with app_engine.begin() as conn:
        conn.execute(
            insert(checkout_sessions).values(
                id="chk_HostilePlainRow0123456", status="ready_for_complete", version=1,
                checkout=canonicalize(body), next_line_seq=2, catalog_hash=b"\0" * 32,
                created_us=now, updated_us=now, expires_us=now + 10**12,
            )
        )  # fmt: skip
        conn.execute(
            insert(checkout_sources).values(
                checkout_id="chk_HostilePlainRow0123456", source="simulator", created_us=now
            )
        )
        conn.execute(
            insert(checkout_customers).values(
                checkout_id="chk_HostilePlainRow0123456", customer_id="cus_" + XSS_BOLD,
                agent_thumbprint=None, source="delegation", created_us=now,
            )
        )  # fmt: skip
    world = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    expected = {**_expectations(admin_engine), **ids, "hostile_plain": "chk_HostilePlainRow0123456"}
    base, server, thread, sock = _start(world.client.app)
    try:
        yield base, expected
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


def test_order_detail_evidence_and_protection(clean: tuple[str, dict[str, Any]]) -> None:
    base, expected = clean
    _run(base, expected, ["test/detail.test.mjs", "test/views.test.mjs"])


def test_untrusted_text_is_rendered_as_text(hostile: tuple[str, dict[str, Any]]) -> None:
    base, expected = hostile
    _run(base, expected, ["test/hostile.test.mjs"])

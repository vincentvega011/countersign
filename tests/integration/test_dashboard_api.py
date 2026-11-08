"""The merchant dashboard's read API, its live stream and its privacy rules (Decisions 114 to 116).

Real composition root over the PayPal simulator, real Postgres. Rows are made through the app itself.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, text

from countersign.runtime import Mode, RuntimeSettings
from tests.mode_support import (
    World,
    complete_body,
    make_world,
    mandate_pair,
    new_checkout,
    purchase,
    reset,
    total_of,
    ucp_complete,
)

API = "/dashboard/api/v1"
ENDPOINTS = ("status", "orders", "summary", "mandates", "events", "eval", "policy")


@pytest.fixture
def world(app_engine: Engine, admin_engine: Engine) -> Iterator[World]:
    reset(admin_engine)
    w = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    with w.client:
        yield w


def _seed(world: World) -> dict[str, str]:
    paid = new_checkout(world)
    purchase(world, paid, mandate_pair(world, paid))
    refused = new_checkout(world)
    pair = mandate_pair(world, refused, amount=total_of(refused) + 100, nonce_checkout="n2",
                        nonce_payment="p2")  # fmt: skip
    ucp_complete(world, refused["id"], complete_body(pair.cm, pair.pm))
    open_ = new_checkout(world)
    return {"paid": paid["id"], "refused": refused["id"], "open": open_["id"]}


def test_status_reports_labels_and_booleans_only(world: World) -> None:
    body = world.client.get(f"{API}/status").json()
    assert set(body) == {
        "version", "app_env", "mode", "protection", "ablations", "paypal_sandbox_configured",
        "data_source", "ucp_profile_url", "read_only", "login",
    }  # fmt: skip
    assert body["version"] == 1 and body["app_env"] == "demo" and body["read_only"] is True
    assert body["protection"] == "full" and body["login"] is False
    assert isinstance(body["paypal_sandbox_configured"], bool)
    assert body["data_source"] == "simulator"


def test_one_row_per_checkout_with_its_states(world: World) -> None:
    ids = _seed(world)
    rows = {r["id"]: r for r in world.client.get(f"{API}/orders").json()["orders"]}
    assert set(ids.values()) <= set(rows)
    paid, refused, open_ = rows[ids["paid"]], rows[ids["refused"]], rows[ids["open"]]
    assert paid["status"] == "completed" and paid["mandate"] == "verified"
    assert paid["gate"] == "passed" and paid["capture_id"] and paid["funnel_stage"] == 4
    assert paid["captured_minor"] == paid["amount_minor"] and paid["unauthorized"] == 0
    assert refused["status"] == "rejected" and refused["mandate"] == "refused"
    assert refused["reason"] == "mandate_scope_mismatch" and refused["blocked"] == 1
    assert open_["status"] == "ready_for_complete" and open_["funnel_stage"] == 0
    for row in rows.values():
        assert row["source"] == "simulator" and row["protocol"] == "ucp"
        assert type(row["amount_minor"]) is int and row["currency"] == "USD"
    subset = world.client.get(f"{API}/orders", params={"ids": ids["open"]}).json()["orders"]
    assert [r["id"] for r in subset] == [ids["open"]]
    junk = world.client.get(f"{API}/orders", params={"ids": "../x,%00"}).json()["orders"]
    assert junk == []


def test_the_unauthorized_count_matches_the_database(world: World, admin_engine: Engine) -> None:
    _seed(world)
    with admin_engine.connect() as conn:
        independent = conn.execute(
            text(
                "SELECT (SELECT count(*) FROM payment_attempts a WHERE a.state = 'captured' AND NOT "
                "EXISTS (SELECT 1 FROM attempt_mandates m WHERE m.checkout_id = a.checkout_id)) + "
                "(SELECT count(*) FROM decision_log WHERE kind = 'degraded.unmandated.captured')"
            )
        ).scalar_one()
    body = world.client.get(f"{API}/summary").json()
    assert body["unauthorized_captures"] == independent == 0


def _routes(node: Any) -> Iterator[Any]:
    for route in getattr(node, "routes", []):
        if hasattr(route, "methods") and hasattr(route, "path"):
            yield route
        else:
            yield from _routes(
                getattr(route, "original_router", None) or getattr(route, "router", None)
            )


def test_there_is_no_write_route_under_the_dashboard_except_the_gated_launcher(
    world: World,
) -> None:
    app = world.client.app  # type: ignore[attr-defined]
    routes = [r for r in _routes(app) if r.path.startswith("/dashboard")]
    assert any(r.path == f"{API}/orders" for r in routes)
    for route in routes:  # the one exception is the gated run launcher (Decision 131)
        allowed = {"GET", "HEAD"} | ({"POST"} if route.path == f"{API}/attack-runs" else set())
        assert set(route.methods) <= allowed, route.path
    for method in ("post", "put", "patch", "delete"):
        r = getattr(world.client, method)(f"{API}/orders")
        assert r.status_code == 405
    refused = world.client.post(f"{API}/attack-runs", json={"attack": "x"})
    assert refused.status_code == 403  # this deployment is demo with no launcher installed


def test_the_policy_snapshot_is_read_only_canonical_and_hashed(world: World) -> None:
    import hashlib

    from countersign.canonical import canonicalize

    body = world.client.get(f"{API}/policy").json()
    snap = body["snapshot"]
    assert body["sha256"] == hashlib.sha256(canonicalize(snap)).hexdigest()
    assert snap["protection"]["mode"] == "full"
    assert snap["dashboard"] == {"read_only": True, "write_endpoints": 0, "login": False}
    assert [s["code"] for s in snap["capture_gate_steps"]][:2] == ["G-FETCH", "G-STATUS"]
    assert len(snap["capture_gate_steps"]) == 9
    assert "payment.budget" in snap["constraint_families"]["payment"]
    assert {e["id"] for e in snap["not_enabled"]} >= {
        "unmandated_cap", "velocity_limits", "category_policy",
    }  # fmt: skip
    # Same state, same hash; the hash moves when the stored merchant lock policy moves.
    assert world.client.get(f"{API}/policy").json()["sha256"] == body["sha256"]
    for method in ("post", "put", "patch", "delete"):
        assert getattr(world.client, method)(f"{API}/policy").status_code == 405


def test_the_policy_hash_is_logged_once_at_start(app_engine: Engine, admin_engine: Engine) -> None:
    from structlog.testing import capture_logs

    reset(admin_engine)
    with capture_logs() as logs:
        w = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    lines = [entry for entry in logs if entry.get("event") == "policy_snapshot"]
    assert len(lines) == 1
    assert lines[0]["sha256"] == w.client.get(f"{API}/policy").json()["sha256"]


PERSONAL_KEYS = re.compile(
    r'"(payer|buyer|email|email_address|address|address_line_1|postal_code|phone|given_name|'
    r"surname|full_name|shipping|access_token|client_secret|client_id|secret|password|"
    r'authorization|checkout_mandate|payment_mandate|token|d|private_key|vault_id)"\s*:',
    re.IGNORECASE,
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
JWT_LIKE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
SECRETS = re.compile(r"-----BEGIN|sim-secret|Bearer\s|Basic\s[A-Za-z0-9+/=]{12,}")


def test_no_dashboard_answer_carries_personal_data_or_secrets(world: World) -> None:
    _seed(world)
    for name in ENDPOINTS:
        r = world.client.get(f"{API}/{name}")
        assert r.status_code == 200, name
        assert r.headers["cache-control"] == "no-store"
        body = r.text
        assert not PERSONAL_KEYS.search(body), (name, PERSONAL_KEYS.search(body))
        assert not EMAIL.search(body), name
        assert not JWT_LIKE.search(body), name
        assert not SECRETS.search(body), name
        assert json.loads(body)["version"] == 1


def test_the_stream_announces_a_new_checkout(world: World) -> None:
    service = world.client.app.state.dashboard  # type: ignore[attr-defined]
    service.poll_seconds, service.stream_seconds = 0.05, 2.0
    made: list[str] = []

    def later() -> None:
        time.sleep(0.4)
        made.append(new_checkout(world)["id"])

    worker = threading.Thread(target=later)
    events: list[tuple[str, dict[str, Any]]] = []
    with world.client.stream("GET", f"{API}/stream") as response:
        assert response.headers["content-type"].startswith("text/event-stream")
        worker.start()
        kind = ""
        for line in response.iter_lines():
            if line.startswith("event: "):
                kind = line[7:]
            elif line.startswith("data: "):
                events.append((kind, json.loads(line[6:])))
                if kind == "orders" and made and made[0] in events[-1][1]["ids"]:
                    break
    worker.join()
    assert events[0][0] == "hello" and events[0][1]["version"] == 1
    assert any(k == "orders" and made[0] in e["ids"] for k, e in events)
    for _, e in events:
        assert set(e) <= {"version", "seq", "ids"}


# ----------------------------------------------------------------------------- order detail (P4.3)

BUNDLE_PERSONAL = re.compile(
    r'"(payer|buyer|email|email_address|address|address_line_1|postal_code|phone|given_name|surname|'
    r'full_name|shipping|access_token|client_secret|client_id|secret|password|private_key|vault_id|d)"\s*:',
    re.IGNORECASE,
)


def _bundle_world(world: World, admin: Engine) -> dict[str, str]:
    from tests.dashboard_rows import insert_bundle_order, vector_text

    with admin.begin() as conn:
        conn.execute(text("TRUNCATE evidence_bundles"))
    return insert_bundle_order(world.engine, vector_text("valid.json"))


def test_detail_returns_the_stored_bundle_and_never_calls_paypal(
    world: World, admin_engine: Engine
) -> None:
    ids = _bundle_world(world, admin_engine)
    calls = len(world.sim.orders) + len(world.sim.authorizations)
    r = world.client.get(f"{API}/orders/{ids['checkout_id']}/detail")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    body = r.json()
    assert set(body) == {"version", "checkout_id", "order", "state", "bundle_text"}
    assert body["state"] == "bundle" and body["order"]["id"] == ids["checkout_id"]
    served = world.client.get(f"/evidence/{ids['capture_id']}").text
    assert body["bundle_text"] == served  # the exact stored text
    assert len(world.sim.orders) + len(world.sim.authorizations) == calls


def test_detail_answers_carry_no_personal_data_token_or_private_key(
    world: World, admin_engine: Engine
) -> None:
    ids = _bundle_world(world, admin_engine)
    _seed(world)
    texts = [world.client.get(f"{API}/orders/{ids['checkout_id']}/detail").text]
    for name in ("valid", "amount-raised", "custom-id", "payee"):
        texts.append(world.client.get(f"{API}/samples/{name}").text)
    for body in texts:
        assert not EMAIL.search(body)
        assert not BUNDLE_PERSONAL.search(body), BUNDLE_PERSONAL.search(body)
        assert not re.search(r"-----BEGIN|Bearer\s|sim-secret|access_token", body)


def test_detail_states_for_rows_without_a_bundle(world: World, admin_engine: Engine) -> None:
    seeded = _seed(world)
    paid = world.client.get(f"{API}/orders/{seeded['paid']}/detail").json()
    assert paid["state"] == "simulated" and paid["bundle_text"] is None
    # The same captured order read as a sandbox row with no bundle is "missing", never invented detail.
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE checkout_sources SET source = 'live_sandbox' WHERE checkout_id = :c"),
            {"c": seeded["paid"]},
        )
    assert world.client.get(f"{API}/orders/{seeded['paid']}/detail").json()["state"] == "missing"
    open_ = world.client.get(f"{API}/orders/{seeded['open']}/detail").json()
    assert open_["state"] == "simulated"


def test_detail_unknown_and_malformed_ids_are_the_same_404(world: World) -> None:
    handled = {
        (r.status_code, r.text)
        for r in (
            world.client.get(f"{API}/orders/chk_nope/detail"),
            world.client.get(f"{API}/orders/a%00b/detail"),
            world.client.get(f"{API}/orders/{'x' * 80}/detail"),
        )
    }
    assert handled == {(404, '{"code":"order_unknown"}')}
    assert world.client.get(f"{API}/orders/..%2fetc/detail").status_code == 404  # never routed


def test_samples_are_an_exact_table_with_404_for_everything_else(world: World) -> None:
    listing = world.client.get(f"{API}/samples").json()["samples"]
    assert [s["name"] for s in listing] == ["valid", "amount-raised", "custom-id", "payee"]
    for name in ("valid", "amount-raised", "custom-id"):
        body = world.client.get(f"{API}/samples/{name}").json()
        assert body["pinned"] is not None and body["bundle_text"].startswith("{")
    assert world.client.get(f"{API}/samples/payee").json()["pinned"] is None
    assert world.client.get(f"{API}/samples/valid").json()["expected_first_failure"] is None
    assert (
        world.client.get(f"{API}/samples/custom-id").json()["expected_first_failure"]
        == "paypal_custom_id"
    )
    for bad in (
        "tampered",
        "../valid",
        "valid.json",
        "..%2f..%2fpyproject.toml",
        "tampered%2fpaypal_custom_id",
        "VALID",
        "x" * 80,
    ):
        r = world.client.get(f"{API}/samples/{bad}")
        assert r.status_code == 404, bad
        if "%2f" not in bad and "/" not in bad:
            assert r.json() == {"code": "sample_unknown"}
    assert world.client.get(f"{API}/samples/valid/extra").status_code == 404


def test_the_eval_endpoint_carries_short_case_entries_only(world: World) -> None:
    body = world.client.get(f"{API}/eval").json()["eval"]
    assert body is not None and body["cases"]
    allowed = {
        "case",
        "category",
        "mode",
        "outcome",
        "reason_code",
        "unauthorized_captures",
        "captured_minor",
    }
    assert all(set(c) == allowed and c["mode"] in ("full", "baseline") for c in body["cases"])
    full = [c for c in body["cases"] if c["mode"] == "full"]
    assert full and not any(c["outcome"] == "success" or c["unauthorized_captures"] for c in full)

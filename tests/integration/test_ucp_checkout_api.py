"""The UCP checkout REST binding against the real Postgres, as the restricted application role.

Responses are validated against the vendored schemas as published; requests are validated against
the schema resolved for their operation (see tests/ucp_schemas.py).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from countersign.api.app import create_app
from countersign.catalog.catalog import load_catalog
from countersign.ledger import store as ledger
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.protocols.ucp.profile import REST_BASE_PATH
from countersign.protocols.ucp.responses import rfc3339
from tests.ucp_schemas import CHECKOUT, ERROR_RESPONSE, request_validator, validator

BASE = "https://shop.example.test"
AGENT = {"UCP-Agent": 'profile="https://platform.example/profile"'}
JSON = {"Content-Type": "application/json"}
HDR = {**AGENT, **JSON}
CATALOG = load_catalog()
ITEM_A, ITEM_B = CATALOG.items[0], CATALOG.items[1]
ROOT = REST_BASE_PATH + "/checkout-sessions"

CHECKOUT_V = validator(CHECKOUT)
ERROR_V = validator(ERROR_RESPONSE)


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000_000_000  # fixed, far from the real clock

    def __call__(self) -> int:
        self.now += 1  # strictly increasing
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def client(app_engine: Engine, clean_checkouts: None, clock: Clock) -> Iterator[TestClient]:
    app = create_app(
        key=validate_jwk(generate_jwk()), public_base_url=BASE, engine=app_engine, clock_us=clock
    )
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def line(item: Any = ITEM_A, qty: int = 1, **extra: Any) -> dict[str, Any]:
    return {"item": {"id": item.id}, "quantity": qty, **extra}


def create(client: TestClient, lines: list[dict[str, Any]] | None = None, **top: Any) -> Any:
    body = {"line_items": lines or [line()], **top}
    return client.post(ROOT, json=body, headers=AGENT)


def valid_checkout(body: dict[str, Any]) -> None:
    assert list(CHECKOUT_V.iter_errors(body)) == [], body


def valid_error(body: dict[str, Any]) -> None:
    assert list(ERROR_V.iter_errors(body)) == [], body


def codes(body: dict[str, Any], kind: str = "error") -> list[str]:
    return [x["code"] for x in body.get("messages", []) if x["type"] == kind]


def new(client: TestClient) -> dict[str, Any]:
    r = create(client)
    assert r.status_code == 201
    return r.json()  # type: ignore[no-any-return]


def force(admin: Engine, checkout_id: str, status: str) -> None:
    with admin.begin() as conn:
        conn.execute(
            text("UPDATE checkout_sessions SET status = :s, version = version + 1 WHERE id = :i"),
            {"s": status, "i": checkout_id},
        )


def log_kinds(admin: Engine, checkout_id: str) -> list[str]:
    with admin.connect() as conn:
        return [e.kind for e in ledger.entries_for_checkout(conn, checkout_id)]


# ---------------- create ----------------


def test_create_returns_a_priced_ready_checkout(client: TestClient) -> None:
    r = create(client, [line(ITEM_A, 2), line(ITEM_B, 3)])
    assert r.status_code == 201
    body = r.json()
    valid_checkout(body)
    assert body["status"] == "ready_for_complete"
    assert body["currency"] == CATALOG.currency
    assert body["id"].startswith("chk_") and len(body["id"]) == 26
    a, b = body["line_items"]
    assert (a["id"], b["id"]) == ("li_1", "li_2")
    assert a["item"]["price"] == ITEM_A.price.minor and a["item"]["title"] == ITEM_A.title
    assert a["totals"][0] == {"type": "subtotal", "amount": ITEM_A.price.minor * 2}
    expected = ITEM_A.price.minor * 2 + ITEM_B.price.minor * 3
    assert body["totals"][-1] == {"type": "total", "amount": expected}
    assert "messages" not in body
    assert r.headers["cache-control"] == "no-store"


def test_expiry_is_six_hours_from_creation(client: TestClient, clock: Clock) -> None:
    start = clock.now
    body = create(client).json()
    expires = datetime.fromisoformat(body["expires_at"])
    created = datetime.fromtimestamp(start / 1e6, UTC)
    assert 6 * 3600 - 2 <= (expires - created).total_seconds() <= 6 * 3600 + 2
    assert body["expires_at"] == rfc3339(start + 1 + 6 * 3600 * 1_000_000)  # one clock tick in


def test_stored_times_and_catalog_hash(client: TestClient, admin_engine: Engine) -> None:
    c = new(client)
    with admin_engine.connect() as conn:
        row = conn.execute(
            text("SELECT created_us, expires_us, catalog_hash FROM checkout_sessions")
        ).one()
    assert row.expires_us - row.created_us == 6 * 3600 * 1_000_000
    assert bytes(row.catalog_hash) == CATALOG.catalog_hash()
    client.put(f"{ROOT}/{c['id']}", json={"line_items": [line(ITEM_B)]}, headers=AGENT)
    with admin_engine.connect() as conn:
        again = conn.execute(text("SELECT catalog_hash, expires_us FROM checkout_sessions")).one()
    assert (
        bytes(again.catalog_hash) == CATALOG.catalog_hash() and again.expires_us == row.expires_us
    )


def test_create_ids_are_unique(client: TestClient) -> None:
    ids = {create(client).json()["id"] for _ in range(5)}
    assert len(ids) == 5


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"buyer": {"email": "jane@example.com", "first_name": "Jane"}},
        {"context": {"address_country": "US"}},
        {"signals": {"dev.ucp.buyer_ip": "203.0.113.42"}},
        {"unknown_future_member": {"a": 1}},
    ],
)
def test_valid_create_requests_conform_and_are_accepted(
    client: TestClient, extra: dict[str, Any]
) -> None:
    body = {"line_items": [line(ITEM_A, 2)], **extra}
    assert list(request_validator("create").iter_errors({**body, "unknown_future_member": 1})) == []
    r = client.post(ROOT, json=body, headers=AGENT)
    assert r.status_code == 201
    valid_checkout(r.json())
    assert not any(k in r.json() for k in ("buyer", "context", "signals", "unknown_future_member"))


def test_the_vendored_spec_example_request_has_the_expected_shape(client: TestClient) -> None:
    example = {"line_items": [{"item": {"id": "item_123"}, "quantity": 2}]}
    assert list(request_validator("create").iter_errors(example)) == []
    r = client.post(ROOT, json=example, headers=AGENT)
    assert r.status_code == 200  # item_123 is not in this catalog
    valid_error(r.json())
    assert codes(r.json()) == ["item_unavailable"]
    assert r.json()["messages"][0]["severity"] == "unrecoverable"


# ---------------- prices and totals are never taken from the request ----------------


def test_a_request_cannot_set_price_title_totals_or_currency(client: TestClient) -> None:
    sent = {
        "id": "chk_attacker",
        "status": "completed",
        "currency": "EUR",
        "totals": [{"type": "total", "amount": 1}],
        "links": [{"type": "x", "url": "https://evil.test"}],
        "expires_at": "2099-01-01T00:00:00Z",
        "line_items": [
            {
                "item": {"id": ITEM_A.id, "price": 1, "title": "Free"},
                "quantity": 2,
                "totals": [{"type": "total", "amount": 1}],
                "id": "li_hacked",
            }
        ],
    }
    r = client.post(ROOT, json=sent, headers=AGENT)
    assert r.status_code == 201
    body = r.json()
    valid_checkout(body)
    assert body["id"] != "chk_attacker" and body["status"] == "ready_for_complete"
    assert body["currency"] == "USD" and body["links"] == []
    assert body["line_items"][0]["id"] == "li_1"
    assert body["line_items"][0]["item"]["price"] == ITEM_A.price.minor
    assert body["line_items"][0]["item"]["title"] == ITEM_A.title
    assert body["totals"][-1]["amount"] == ITEM_A.price.minor * 2
    assert body["expires_at"].startswith("20") and not body["expires_at"].startswith("2099")
    warned = {x["path"] for x in body["messages"] if x["type"] == "warning"}
    assert {
        "$.id",
        "$.status",
        "$.currency",
        "$.totals",
        "$.links",
        "$.expires_at",
        "$.line_items[0].item.price",
        "$.line_items[0].item.title",
        "$.line_items[0].totals",
    } <= warned
    assert set(codes(body, "warning")) == {"field_ignored"}


def test_the_stored_checkout_is_the_catalog_one(client: TestClient) -> None:
    sent = {"line_items": [{"item": {"id": ITEM_A.id, "price": 1}, "quantity": 1}]}
    cid = client.post(ROOT, json=sent, headers=AGENT).json()["id"]
    got = client.get(f"{ROOT}/{cid}", headers=AGENT).json()
    assert got["line_items"][0]["item"]["price"] == ITEM_A.price.minor
    assert "messages" not in got


def test_price_in_an_update_is_ignored_too(client: TestClient) -> None:
    c = new(client)
    sent = {
        "line_items": [
            {"id": "li_1", "item": {"id": ITEM_A.id, "price": 1}, "quantity": 2},
        ],
        "totals": [{"type": "total", "amount": 1}],
    }
    r = client.put(f"{ROOT}/{c['id']}", json=sent, headers=AGENT)
    body = r.json()
    valid_checkout(body)
    assert body["totals"][-1]["amount"] == ITEM_A.price.minor * 2
    assert body["line_items"][0]["item"]["price"] == ITEM_A.price.minor


# ---------------- business rules on create ----------------


def test_unknown_item_is_an_error_response_and_creates_nothing(
    client: TestClient, admin_engine: Engine
) -> None:
    r = create(client, [line(ITEM_A), {"item": {"id": "nope"}, "quantity": 1}])
    assert r.status_code == 200
    valid_error(r.json())
    (msg,) = r.json()["messages"]
    assert msg["code"] == "item_unavailable" and msg["path"] == "$.line_items[1].item.id"
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM checkout_sessions")).scalar() == 0


def test_quantity_and_line_limits(client: TestClient) -> None:
    r = create(client, [line(qty=100)])
    valid_error(r.json())
    assert codes(r.json()) == ["quantity_limit"]
    assert create(client, [line(qty=99)]).status_code == 201
    r = create(client, [line() for _ in range(21)])
    valid_error(r.json())
    assert codes(r.json()) == ["line_limit"]
    assert create(client, [line() for _ in range(20)]).status_code == 201


def test_quantity_unit_assertion_must_be_each(client: TestClient) -> None:
    bad = {"item": {"id": ITEM_A.id, "quantity_unit": {"unit": "KGM", "scale": 3}}, "quantity": 1}
    r = client.post(ROOT, json={"line_items": [bad]}, headers=AGENT)
    assert codes(r.json()) == ["quantity_unit_mismatch"]
    ok = {"item": {"id": ITEM_A.id, "quantity_unit": {"unit": "C62"}}, "quantity": 1}
    assert client.post(ROOT, json={"line_items": [ok]}, headers=AGENT).status_code == 201


# ---------------- get ----------------


def test_get_returns_the_same_checkout(client: TestClient) -> None:
    c = new(client)
    r = client.get(f"{ROOT}/{c['id']}", headers=AGENT)
    assert r.status_code == 200
    assert r.json() == c
    valid_checkout(r.json())


@pytest.mark.parametrize(
    "cid", ["chk_" + "A" * 22, "x", "chk_short", "chk_" + "!" * 22, "x%20y", "chk_" + "A" * 23]
)
def test_get_unknown_or_malformed_id_is_not_found(client: TestClient, cid: str) -> None:
    r = client.get(f"{ROOT}/{cid}", headers=AGENT)
    assert r.status_code == 200
    valid_error(r.json())
    assert codes(r.json()) == ["not_found"]


# ---------------- update ----------------


def test_update_replaces_the_line_items(client: TestClient) -> None:
    c = new(client)
    sent = {
        "line_items": [{"id": "li_1", "item": {"id": ITEM_B.id}, "quantity": 4}, line(ITEM_A, 1)]
    }
    assert list(request_validator("update").iter_errors(sent)) == []
    r = client.put(f"{ROOT}/{c['id']}", json=sent, headers=AGENT)
    assert r.status_code == 200
    body = r.json()
    valid_checkout(body)
    assert [x["id"] for x in body["line_items"]] == ["li_1", "li_2"]
    assert (
        body["line_items"][0]["item"]["id"] == ITEM_B.id and body["line_items"][0]["quantity"] == 4
    )
    assert body["totals"][-1]["amount"] == ITEM_B.price.minor * 4 + ITEM_A.price.minor
    assert body["id"] == c["id"] and body["expires_at"] == c["expires_at"]


def test_line_ids_are_never_reused(client: TestClient) -> None:
    c = new(client)
    url = f"{ROOT}/{c['id']}"
    client.put(url, json={"line_items": [line(ITEM_B, 1)]}, headers=AGENT)  # li_1 dropped, li_2 new
    body = client.put(url, json={"line_items": [line(ITEM_A, 1)]}, headers=AGENT).json()
    assert body["line_items"][0]["id"] == "li_3"


def test_echoing_the_whole_checkout_back_is_accepted_without_warnings(client: TestClient) -> None:
    c = new(client)
    echo = json.loads(json.dumps(c))
    echo["line_items"][0]["quantity"] = 3
    echo["line_items"][0]["totals"] = [
        {"type": "subtotal", "amount": ITEM_A.price.minor * 3},
        {"type": "total", "amount": ITEM_A.price.minor * 3},
    ]
    echo["totals"] = echo["line_items"][0]["totals"]
    r = client.put(f"{ROOT}/{c['id']}", json=echo, headers=AGENT)
    body = r.json()
    valid_checkout(body)
    assert body["line_items"][0]["quantity"] == 3
    assert "messages" not in body


def test_update_with_an_unknown_line_id_changes_nothing(
    client: TestClient, admin_engine: Engine
) -> None:
    c = new(client)
    sent = {"line_items": [{"id": "li_99", "item": {"id": ITEM_A.id}, "quantity": 5}]}
    r = client.put(f"{ROOT}/{c['id']}", json=sent, headers=AGENT)
    body = r.json()
    valid_checkout(body)
    assert codes(body) == ["line_item_not_found"]
    assert body["messages"][0]["severity"] == "recoverable"
    assert body["line_items"] == c["line_items"] and body["totals"] == c["totals"]
    assert client.get(f"{ROOT}/{c['id']}", headers=AGENT).json() == c
    assert log_kinds(admin_engine, c["id"]) == ["checkout.created", "checkout.update_rejected"]


def test_update_repeating_a_line_id_is_refused(client: TestClient) -> None:
    c = new(client)
    sent = {
        "line_items": [
            {"id": "li_1", "item": {"id": ITEM_A.id}, "quantity": 1},
            {"id": "li_1", "item": {"id": ITEM_B.id}, "quantity": 1},
        ]
    }
    body = client.put(f"{ROOT}/{c['id']}", json=sent, headers=AGENT).json()
    assert codes(body) == ["line_item_not_found"]
    assert client.get(f"{ROOT}/{c['id']}", headers=AGENT).json() == c


def test_update_with_an_unknown_item_changes_nothing(client: TestClient) -> None:
    c = new(client)
    body = client.put(
        f"{ROOT}/{c['id']}",
        json={"line_items": [{"item": {"id": "nope"}, "quantity": 1}]},
        headers=AGENT,
    ).json()
    valid_checkout(body)
    assert codes(body) == ["item_unavailable"] and body["line_items"] == c["line_items"]


def test_update_of_an_unknown_checkout_is_not_found(client: TestClient) -> None:
    r = client.put(f"{ROOT}/chk_{'A' * 22}", json={"line_items": [line()]}, headers=AGENT)
    valid_error(r.json())
    assert codes(r.json()) == ["not_found"]


# ---------------- complete (stub) ----------------

COMPLETE = {
    "payment": {
        "instruments": [
            {
                "id": "pi_1",
                "handler_id": "h",
                "type": "card",
                "selected": True,
                "credential": {"type": "PAYMENT_GATEWAY", "token": "tok"},
            }
        ]
    }
}


def test_complete_returns_mandate_required_and_changes_nothing(
    client: TestClient, admin_engine: Engine
) -> None:
    c = new(client)
    assert list(request_validator("complete").iter_errors(COMPLETE)) == []
    r = client.post(f"{ROOT}/{c['id']}/complete", json=COMPLETE, headers=AGENT)
    assert r.status_code == 200
    body = r.json()
    valid_checkout(body)
    assert body["status"] == "ready_for_complete"
    (msg,) = body["messages"]
    assert msg["code"] == "mandate_required" and msg["severity"] == "recoverable"
    assert msg["path"] == "$.ap2.checkout_mandate"
    assert {k: v for k, v in body.items() if k != "messages"} == c
    assert "order" not in body
    assert log_kinds(admin_engine, c["id"]) == ["checkout.created", "checkout.complete_rejected"]


def test_complete_never_succeeds_even_with_a_mandate_present(client: TestClient) -> None:
    c = new(client)
    sent = {**COMPLETE, "ap2": {"checkout_mandate": "a.b.c~d~"}}
    body = client.post(f"{ROOT}/{c['id']}/complete", json=sent, headers=AGENT).json()
    assert body["status"] == "ready_for_complete" and codes(body) == ["mandate_required"]
    assert "order" not in body


def test_complete_of_unknown_checkout_is_not_found(client: TestClient) -> None:
    r = client.post(f"{ROOT}/chk_{'A' * 22}/complete", json=COMPLETE, headers=AGENT)
    assert codes(r.json()) == ["not_found"]


# ---------------- cancel ----------------


def test_cancel_moves_to_canceled_and_is_final(client: TestClient, admin_engine: Engine) -> None:
    c = new(client)
    r = client.post(f"{ROOT}/{c['id']}/cancel", json={}, headers=AGENT)
    assert r.status_code == 200
    valid_checkout(r.json())
    assert r.json()["status"] == "canceled"
    assert client.get(f"{ROOT}/{c['id']}", headers=AGENT).json()["status"] == "canceled"
    assert log_kinds(admin_engine, c["id"]) == ["checkout.created", "checkout.canceled"]


@pytest.mark.parametrize("body", [{}, None])
def test_cancel_accepts_an_empty_body_or_empty_object(client: TestClient, body: Any) -> None:
    c = new(client)
    r = (
        client.post(f"{ROOT}/{c['id']}/cancel", json=body, headers=AGENT)
        if body is not None
        else (client.post(f"{ROOT}/{c['id']}/cancel", headers=AGENT))
    )
    assert r.json()["status"] == "canceled"


def test_cancel_twice_is_an_unrecoverable_error_and_stays_canceled(client: TestClient) -> None:
    c = new(client)
    client.post(f"{ROOT}/{c['id']}/cancel", json={}, headers=AGENT)
    r = client.post(f"{ROOT}/{c['id']}/cancel", json={}, headers=AGENT)
    body = r.json()
    valid_checkout(body)
    assert body["status"] == "canceled" and codes(body) == ["checkout_not_cancelable"]
    assert body["messages"][0]["severity"] == "unrecoverable"


def test_a_canceled_checkout_cannot_be_updated_or_completed(client: TestClient) -> None:
    c = new(client)
    client.post(f"{ROOT}/{c['id']}/cancel", json={}, headers=AGENT)
    u = client.put(
        f"{ROOT}/{c['id']}", json={"line_items": [line(ITEM_B, 9)]}, headers=AGENT
    ).json()
    assert codes(u) == ["checkout_not_modifiable"] and u["line_items"] == c["line_items"]
    assert u["status"] == "canceled"
    k = client.post(f"{ROOT}/{c['id']}/complete", json=COMPLETE, headers=AGENT).json()
    assert codes(k) == ["checkout_not_ready"] and k["messages"][0]["severity"] == "unrecoverable"
    assert k["status"] == "canceled"


# ---------------- every status, every operation ----------------

STATUSES = [
    "incomplete",
    "requires_escalation",
    "ready_for_complete",
    "complete_in_progress",
    "completed",
    "canceled",
]
# (update outcome, complete outcome, cancel outcome) per forced status: a code or "ok"
EXPECT = {
    "incomplete": ("ok", "checkout_not_ready", "ok"),
    "requires_escalation": ("ok", "checkout_not_ready", "ok"),
    "ready_for_complete": ("ok", "mandate_required", "ok"),
    "complete_in_progress": ("complete_in_progress", "checkout_not_ready", "ok"),
    "completed": ("checkout_not_modifiable", "checkout_not_ready", "checkout_not_cancelable"),
    "canceled": ("checkout_not_modifiable", "checkout_not_ready", "checkout_not_cancelable"),
}
# Severity of the refusal for (update, complete): final statuses are unrecoverable, others not.
SEVERITY = {
    "incomplete": (None, "recoverable"),
    "requires_escalation": (None, "recoverable"),
    "ready_for_complete": (None, "recoverable"),
    "complete_in_progress": ("recoverable", "recoverable"),
    "completed": ("unrecoverable", "unrecoverable"),
    "canceled": ("unrecoverable", "unrecoverable"),
}


@pytest.mark.parametrize("status", STATUSES)
def test_each_operation_in_each_status(
    client: TestClient, admin_engine: Engine, status: str
) -> None:
    def fresh() -> str:
        cid = new(client)["id"]
        if status != "ready_for_complete":
            force(admin_engine, cid, status)
        return cid

    upd, comp, canc = EXPECT[status]
    cid = fresh()
    r = client.put(f"{ROOT}/{cid}", json={"line_items": [line(ITEM_B, 2)]}, headers=AGENT).json()
    valid_checkout(r)
    assert r["status"] == status  # an update never changes the status
    if upd == "ok":
        assert "messages" not in r and r["line_items"][0]["item"]["id"] == ITEM_B.id
    else:
        assert codes(r) == [upd] and r["line_items"][0]["item"]["id"] == ITEM_A.id
        assert r["messages"][0]["severity"] == SEVERITY[status][0]

    cid = fresh()
    r = client.post(f"{ROOT}/{cid}/complete", json=COMPLETE, headers=AGENT).json()
    valid_checkout(r)
    assert codes(r) == [comp] and r["status"] == status and "order" not in r
    assert r["messages"][0]["severity"] == SEVERITY[status][1]

    cid = fresh()
    r = client.post(f"{ROOT}/{cid}/cancel", json={}, headers=AGENT).json()
    valid_checkout(r)
    if canc == "ok":
        assert r["status"] == "canceled" and "messages" not in r
    else:
        assert codes(r) == [canc] and r["status"] == status
        assert r["messages"][0]["severity"] == "unrecoverable"


def test_update_during_completion_is_recoverable(client: TestClient, admin_engine: Engine) -> None:
    c = new(client)
    force(admin_engine, c["id"], "complete_in_progress")
    r = client.put(
        f"{ROOT}/{c['id']}", json={"line_items": [line(ITEM_B, 2)]}, headers=AGENT
    ).json()
    assert r["messages"][0]["severity"] == "recoverable"


# ---------------- expiry ----------------


def test_a_checkout_past_its_expiry_becomes_canceled(
    client: TestClient, clock: Clock, admin_engine: Engine
) -> None:
    c = new(client)
    clock.now += 6 * 3600 * 1_000_000 + 10
    got = client.get(f"{ROOT}/{c['id']}", headers=AGENT).json()
    valid_checkout(got)
    assert got["status"] == "canceled"
    assert log_kinds(admin_engine, c["id"]) == ["checkout.created", "checkout.expired"]
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT status FROM checkout_sessions")).scalar() == "canceled"
    assert client.get(f"{ROOT}/{c['id']}", headers=AGENT).json()["status"] == "canceled"
    assert log_kinds(admin_engine, c["id"]) == ["checkout.created", "checkout.expired"]
    u = client.put(f"{ROOT}/{c['id']}", json={"line_items": [line()]}, headers=AGENT).json()
    assert codes(u) == ["checkout_not_modifiable"]


def test_expiry_applies_before_an_update(client: TestClient, clock: Clock) -> None:
    c = new(client)
    clock.now += 6 * 3600 * 1_000_000 + 10
    u = client.put(f"{ROOT}/{c['id']}", json={"line_items": [line(ITEM_B)]}, headers=AGENT).json()
    assert u["status"] == "canceled" and codes(u) == ["checkout_not_modifiable"]
    assert u["line_items"] == c["line_items"]


def test_a_final_checkout_does_not_expire_again(
    client: TestClient, clock: Clock, admin_engine: Engine
) -> None:
    c = new(client)
    client.post(f"{ROOT}/{c['id']}/cancel", json={}, headers=AGENT)
    clock.now += 7 * 3600 * 1_000_000
    client.get(f"{ROOT}/{c['id']}", headers=AGENT)
    assert log_kinds(admin_engine, c["id"]) == ["checkout.created", "checkout.canceled"]


# ---------------- protocol errors ----------------

OPS: list[tuple[str, str]] = [
    ("POST", ROOT),
    ("GET", ROOT + "/chk_" + "A" * 22),
    ("PUT", ROOT + "/chk_" + "A" * 22),
    ("POST", ROOT + "/chk_" + "A" * 22 + "/complete"),
    ("POST", ROOT + "/chk_" + "A" * 22 + "/cancel"),
]


def _assert_protocol_error(r: Any, status: int, code: str) -> None:
    assert r.status_code == status
    body = r.json()
    assert set(body) == {"code", "content"} and body["code"] == code
    assert isinstance(body["content"], str) and body["content"]


@pytest.mark.parametrize(("method", "url"), OPS)
@pytest.mark.parametrize(
    "agent",
    [
        None,
        "",
        "nonsense",
        'profile=""',
        "profile=https://x.test",
        'profile="ftp://x.test"',
        'other="https://x.test"',
    ],
)
def test_ucp_agent_is_required_on_every_operation(
    client: TestClient, method: str, url: str, agent: str | None
) -> None:
    headers = dict(JSON)
    if agent is not None:
        headers["UCP-Agent"] = agent
    r = client.request(method, url, content=b'{"line_items": []}', headers=headers)
    _assert_protocol_error(r, 400, "invalid_profile_url")


def test_ucp_agent_accepts_a_dictionary_with_other_members(client: TestClient) -> None:
    headers = {**JSON, "UCP-Agent": 'foo=1, profile="https://platform.example/profile"'}
    r = client.post(ROOT, json={"line_items": [line()]}, headers=headers)
    assert r.status_code == 201


@pytest.mark.parametrize(
    ("content", "ctype", "code"),
    [
        (b'{"line_items": [], "line_items": []}', "application/json", "json_duplicate_key"),
        (b'{"line_items": NaN}', "application/json", "json_non_finite"),
        (b"\xff\xfe", "application/json", "json_encoding"),
        (b'{"line_items": [', "application/json", "json_syntax"),
        (b"", "application/json", "json_syntax"),
        (b"[]", "application/json", "invalid_request"),
        (b'{"line_items": []}', "application/json", "invalid_request"),
        (b'{"line_items": []}', "text/plain", "invalid_request"),
        (b'{"line_items": []}', None, "invalid_request"),
        (b'{"x":"' + b"a" * 1_100_000 + b'"}', "application/json", "json_too_large"),
    ],
)
def test_bad_create_bodies_are_ucp_shaped_400s(
    client: TestClient, content: bytes, ctype: str | None, code: str
) -> None:
    headers = dict(AGENT)
    if ctype:
        headers["Content-Type"] = ctype
    r = client.post(ROOT, content=content, headers=headers)
    _assert_protocol_error(r, 400, code)


@pytest.mark.parametrize("ctype", ["text/plain", "application/xml", None])
def test_a_valid_body_with_the_wrong_content_type_is_refused(
    client: TestClient, ctype: str | None
) -> None:
    headers = dict(AGENT)
    if ctype:
        headers["Content-Type"] = ctype
    r = client.post(ROOT, content=json.dumps({"line_items": [line()]}).encode(), headers=headers)
    _assert_protocol_error(r, 400, "invalid_request")
    assert "Content-Type" in r.json()["content"]


def test_bad_update_and_complete_bodies_are_400s(client: TestClient) -> None:
    c = new(client)
    for method, url in (("PUT", f"{ROOT}/{c['id']}"), ("POST", f"{ROOT}/{c['id']}/complete")):
        r = client.request(method, url, content=b'{"a": 1, "a": 2}', headers=HDR)
        _assert_protocol_error(r, 400, "json_duplicate_key")
    r = client.post(f"{ROOT}/{c['id']}/cancel", content=b'{"a": 1, "a": 2}', headers=HDR)
    _assert_protocol_error(r, 400, "json_duplicate_key")
    assert client.get(f"{ROOT}/{c['id']}", headers=AGENT).json()["status"] == "ready_for_complete"


def test_a_bad_request_creates_nothing(client: TestClient, admin_engine: Engine) -> None:
    client.post(
        ROOT, content=b'{"line_items": [{"item": {"id": "a"}, "quantity": "2"}]}', headers=HDR
    )
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM checkout_sessions")).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM decision_log")).scalar() == 0


# ---------------- persistence, log, fail closed ----------------


def test_state_survives_a_restart(app_engine: Engine, clean_checkouts: None, clock: Clock) -> None:
    key = validate_jwk(generate_jwk())

    def make() -> TestClient:
        app = create_app(key=key, public_base_url=BASE, engine=app_engine, clock_us=clock)
        return TestClient(app, raise_server_exceptions=False)

    with make() as first:
        c = new(first)
        first.put(f"{ROOT}/{c['id']}", json={"line_items": [line(ITEM_B, 2)]}, headers=AGENT)
    with make() as second:
        got = second.get(f"{ROOT}/{c['id']}", headers=AGENT).json()
    valid_checkout(got)
    assert got["line_items"][0]["item"]["id"] == ITEM_B.id and got["line_items"][0]["quantity"] == 2


def test_every_decision_is_logged_and_the_chain_verifies(
    client: TestClient, admin_engine: Engine
) -> None:
    c = new(client)
    url = f"{ROOT}/{c['id']}"
    client.put(url, json={"line_items": [line(ITEM_B, 2)]}, headers=AGENT)
    client.post(url + "/complete", json=COMPLETE, headers=AGENT)
    client.get(url, headers=AGENT)
    client.post(url + "/cancel", json={}, headers=AGENT)
    client.post(url + "/cancel", json={}, headers=AGENT)
    assert log_kinds(admin_engine, c["id"]) == [
        "checkout.created",
        "checkout.updated",
        "checkout.complete_rejected",
        "checkout.canceled",
        "checkout.cancel_rejected",
    ]
    with admin_engine.connect() as conn:
        result = ledger.verify_log(conn)
        entries = ledger.entries_for_checkout(conn, c["id"])
    assert result.ok
    created = json.loads(entries[0].payload)
    assert created["lines"] == [["li_1", ITEM_A.id, 1]] and created["version"] == 1
    assert json.loads(entries[1].payload)["previous_terms_hash"] == created["terms_hash"]


def test_a_log_failure_fails_the_operation_and_rolls_back(
    client: TestClient, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = new(client)

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("log unavailable")

    monkeypatch.setattr(ledger, "append", boom)
    r = client.post(f"{ROOT}/{c['id']}/cancel", json={}, headers=AGENT)
    _assert_protocol_error(r, 500, "internal_error")
    assert "log unavailable" not in r.text
    r = create(client)
    _assert_protocol_error(r, 500, "internal_error")
    monkeypatch.undo()
    assert client.get(f"{ROOT}/{c['id']}", headers=AGENT).json()["status"] == "ready_for_complete"
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM checkout_sessions")).scalar() == 1


def test_a_corrupt_stored_checkout_is_never_served(
    client: TestClient, admin_engine: Engine
) -> None:
    c = new(client)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE checkout_sessions SET checkout = :b, version = version + 1 WHERE id = :i"),
            {"b": b'{"id": "x"}', "i": c["id"]},
        )
    r = client.get(f"{ROOT}/{c['id']}", headers=AGENT)
    _assert_protocol_error(r, 500, "internal_error")


def test_a_stored_checkout_with_a_forged_total_is_never_served(
    client: TestClient, admin_engine: Engine
) -> None:
    c = new(client)
    forged = json.loads(json.dumps({k: c[k] for k in ("id", "currency", "line_items", "totals")}))
    forged["totals"][-1]["amount"] = 1
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE checkout_sessions SET checkout = :b, version = version + 1 WHERE id = :i"),
            {"b": json.dumps(forged).encode(), "i": c["id"]},
        )
    _assert_protocol_error(client.get(f"{ROOT}/{c['id']}", headers=AGENT), 500, "internal_error")


def test_the_profile_advertises_the_path_that_is_served(client: TestClient) -> None:
    profile = client.get("/.well-known/ucp").json()
    (svc,) = profile["ucp"]["services"]["dev.ucp.shopping"]
    assert svc["endpoint"] == BASE + REST_BASE_PATH
    assert client.post(ROOT, json={"line_items": [line()]}, headers=AGENT).status_code == 201

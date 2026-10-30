"""The ACP thin adapter over HTTP, against the vendored 2026-04-17 schemas.

Real: the app, the shared principal lock, the Merchant, the Credential Provider, the gate, Postgres and
the decision log. The only double is the PayPal simulator. The lock tests use the real adapter, so
they supersede the test-only second protocol entry point of the lock tests.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from sqlalchemy import Engine, select, text

from countersign.catalog.catalog import load_catalog
from countersign.ledger.store import entries_for_checkout
from countersign.protocols.ucp.profile import AP2_CAPABILITY
from countersign.tables import payment_attempts, reservations
from tests import acp_schemas as schemas
from tests.integration.test_ucp_checkout_api import force
from tests.integration.test_ucp_complete import Stack
from tests.integration.test_ucp_complete_gate import build
from tests.lock_support import delegation

ITEMS = load_catalog().items
ITEM = ITEMS[0]
HEADERS = {"Idempotency-Key": "k-1", "Content-Type": "application/json"}


@pytest.fixture
def acp(app_engine: Engine, clean_payments: None) -> Iterator[tuple[Stack, Any]]:
    _, stack, _key, lock = build(app_engine)
    with stack.client:
        yield stack, lock


def create_body(
    *, quantity: int | None = 1, item: str | None = None, **over: Any
) -> dict[str, Any]:
    line: dict[str, Any] = {"id": item or ITEM.id}
    if quantity is not None:
        line["quantity"] = quantity
    body: dict[str, Any] = {"line_items": [line], "currency": "usd", "capabilities": {}}
    body.update(over)
    return body


def headers(
    token: str | None = None, *, capability: bool = False, key: str | None = "k-1", **extra: str
) -> dict[str, str]:
    out = {"Content-Type": "application/json", **extra}
    if key is not None:
        out["Idempotency-Key"] = key
    if token:
        out["Countersign-Delegation"] = token
    if capability:
        out["Countersign-Capabilities"] = AP2_CAPABILITY
    return out


def post(stack: Stack, path: str, body: Any = None, **kw: Any) -> Any:
    content = (
        body if isinstance(body, bytes) else json.dumps(body if body is not None else {}).encode()
    )
    return stack.client.post(path, content=content, headers=headers(**kw))


def make_session(stack: Stack, **kw: Any) -> dict[str, Any]:
    response = post(stack, "/checkout_sessions", create_body(), **kw)
    assert response.status_code == 201, response.text
    out: dict[str, Any] = response.json()
    return out


def assert_error(response: Any, status: int, code: str | None = None) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    schemas.ERROR.validate(body)
    if code is not None:
        assert body["code"] == code, body
    return body


def untouched(stack: Stack) -> None:
    """Nothing was reserved, authorized or captured."""
    assert stack.sim.calls == []
    with stack.engine.connect() as conn:
        assert conn.execute(select(reservations)).all() == []
        assert conn.execute(select(payment_attempts)).all() == []


# ------------------------------------------------------------------------- schema conformance


def test_every_response_conforms_to_the_vendored_schema(acp: tuple[Stack, Any]) -> None:
    stack, _ = acp
    created = post(stack, "/checkout_sessions", create_body(quantity=2))
    assert created.status_code == 201
    body = created.json()
    schemas.SESSION.validate(body)
    assert body["status"] == "ready_for_payment" and body["protocol"] == {"version": "2026-04-17"}
    assert body["currency"] == "usd" and body["line_items"][0]["quantity"] == 2
    total = next(t for t in body["totals"] if t["type"] == "total")
    assert isinstance(total["amount"], int) and total["amount"] == ITEM.price.minor * 2  # INV-9

    sid = body["id"]
    got = stack.client.get(f"/checkout_sessions/{sid}")
    assert got.status_code == 200
    schemas.SESSION.validate(got.json())

    updated = post(stack, f"/checkout_sessions/{sid}", {"line_items": [{"id": ITEMS[1].id}]})
    assert updated.status_code == 200
    schemas.SESSION.validate(updated.json())
    assert updated.json()["line_items"][0]["item"]["id"] == ITEMS[1].id

    canceled = post(stack, f"/checkout_sessions/{sid}/cancel", None)
    assert canceled.status_code == 200
    schemas.SESSION.validate(canceled.json())
    assert canceled.json()["status"] == "canceled"


def test_a_completed_session_carries_an_order_that_conforms(
    acp: tuple[Stack, Any], admin_engine: Engine
) -> None:
    stack, _ = acp
    body = make_session(stack)
    force(admin_engine, body["id"], "completed")
    got = stack.client.get(f"/checkout_sessions/{body['id']}").json()
    schemas.SESSION_WITH_ORDER.validate(got)
    assert got["status"] == "completed" and got["order"]["checkout_session_id"] == body["id"]


def test_the_requests_the_adapter_accepts_conform_to_the_vendored_request_schemas() -> None:
    schemas.CREATE_REQUEST.validate(
        create_body(quantity=None)
    )  # no `quantity`: schema as published
    schemas.UPDATE_REQUEST.validate({"line_items": [{"id": ITEM.id}]})
    schemas.COMPLETE_REQUEST.validate(
        {
            "payment_data": {
                "handler_id": "h",
                "instrument": {"type": "card", "credential": {"type": "spt", "token": "t"}},
            }
        }
    )
    # `quantity` is in the vendored examples but not in the published Item schema: the one
    # extension the adapter accepts (docs/PROTOCOL.md Decision 52).
    assert not schemas.CREATE_REQUEST.is_valid(create_body(quantity=2))


@pytest.mark.parametrize(
    "path,body,kw,status,code",
    [
        ("/checkout_sessions", create_body(), {"key": None}, 400, "idempotency_key_required"),
        ("/checkout_sessions", create_body(), {"extra": {"API-Version": "2020-01-01"}}, 400, None),
        ("/checkout_sessions", create_body(bogus=1), {}, 400, "invalid_field"),
        ("/checkout_sessions", {"line_items": [{"id": ITEM.id}]}, {}, 400, "missing_field"),
        ("/checkout_sessions", create_body(item="nope"), {}, 400, "item_not_found"),
        ("/checkout_sessions", create_body(quantity=0), {}, 400, "quantity_limit"),
        ("/checkout_sessions", create_body(quantity=100), {}, 400, "quantity_limit"),
        ("/checkout_sessions", create_body(quantity=1.5), {}, 400, "invalid_field"),
        ("/checkout_sessions", create_body(quantity=True), {}, 400, "invalid_field"),
        ("/checkout_sessions", create_body(currency="eur"), {}, 400, "invalid_field"),
        ("/checkout_sessions", create_body(coupons=["X"]), {}, 400, "unsupported_field"),
        ("/checkout_sessions", create_body(line_items=[]), {}, 400, "missing_field"),
        ("/checkout_sessions", [1, 2], {}, 400, "invalid_json"),
    ],
)
def test_rejected_inputs_answer_with_an_error_that_conforms(
    acp: tuple[Stack, Any], path: str, body: Any, kw: dict[str, Any], status: int, code: str | None
) -> None:
    stack, _ = acp
    extra = kw.pop("extra", {})
    response = stack.client.post(
        path, content=json.dumps(body).encode(), headers={**headers(**kw), **extra}
    )
    assert_error(response, status, code)
    untouched(stack)


def test_the_unit_amount_an_agent_sends_is_compared_and_never_used(acp: tuple[Stack, Any]) -> None:
    stack, _ = acp
    wrong = create_body()
    wrong["line_items"][0]["unit_amount"] = 1
    assert_error(post(stack, "/checkout_sessions", wrong), 400, "price_mismatch")
    right = create_body()
    right["line_items"][0]["unit_amount"] = ITEM.price.minor
    assert post(stack, "/checkout_sessions", right).status_code == 201


def test_lookups_and_lifecycle_errors_conform(acp: tuple[Stack, Any]) -> None:
    stack, _ = acp
    assert_error(stack.client.get("/checkout_sessions/chk_missing"), 404, "not_found")
    assert_error(post(stack, "/checkout_sessions/chk_missing/cancel"), 404)
    sid = make_session(stack)["id"]
    assert post(stack, f"/checkout_sessions/{sid}/cancel").status_code == 200
    assert_error(post(stack, f"/checkout_sessions/{sid}/cancel"), 405, "not_cancelable")
    assert_error(post(stack, f"/checkout_sessions/{sid}", {"line_items": [{"id": ITEM.id}]}), 409)
    assert_error(post(stack, f"/checkout_sessions/{sid}/complete", {"payment_data": {}}), 409)


# --------------------------------------------------------------------- strict JSON and limits


@pytest.mark.parametrize(
    "raw",
    [
        b'{"line_items": [{"id": "x"}], "line_items": [{"id": "y"}], "currency": "usd", "capabilities": {}}',
        b'{"line_items": [{"id": "x", "quantity": NaN}], "currency": "usd", "capabilities": {}}',
        b'{"line_items": [{"id": "x", "quantity": Infinity}], "currency": "usd", "capabilities": {}}',
        b'{"line_items": [{"id": "x", "quantity": 1e999}], "currency": "usd", "capabilities": {}}',
        b'{"line_items": [{"id": "x", "unit_amount": 1.00000000000000000001}], "currency": "usd", "capabilities": {}}',
        b'{"line_items": [{"id": "x", "quantity": 99999999999999999999}], "currency": "usd", "capabilities": {}}',
        b'{"line_items": [', b"", b"not json", b"\xff\xfe",
    ],
)  # fmt: skip
def test_the_strict_loader_refuses_ambiguous_json_before_anything_reads_it(
    acp: tuple[Stack, Any], raw: bytes
) -> None:
    stack, _ = acp
    response = post(stack, "/checkout_sessions", raw)
    body = assert_error(response, 400)
    assert body["type"] == "invalid_request"
    untouched(stack)
    for path in ("/checkout_sessions/chk_x", "/checkout_sessions/chk_x/complete"):
        assert_error(post(stack, path, raw), 400)


def test_an_oversized_body_is_refused(acp: tuple[Stack, Any]) -> None:
    stack, _ = acp
    big = json.dumps(create_body(metadata={"pad": "x" * 2_000_000})).encode()
    assert_error(post(stack, "/checkout_sessions", big), 400, "json_too_large")


def test_line_limits(acp: tuple[Stack, Any]) -> None:
    stack, _ = acp
    many = create_body()
    many["line_items"] = [{"id": ITEM.id}] * 21
    assert_error(post(stack, "/checkout_sessions", many), 400, "line_limit")
    twenty = create_body()
    twenty["line_items"] = [{"id": ITEM.id}] * 20
    assert post(stack, "/checkout_sessions", twenty).status_code == 201


def test_a_non_json_content_type_is_refused(acp: tuple[Stack, Any]) -> None:
    stack, _ = acp
    response = stack.client.post(
        "/checkout_sessions",
        content=json.dumps(create_body()).encode(),
        headers={"Idempotency-Key": "k", "Content-Type": "text/plain"},
    )
    assert_error(response, 400, "invalid_content_type")


# ---------------------------------------------------------------------------------- the lock


def complete(stack: Stack, sid: str, **kw: Any) -> Any:
    return post(
        stack,
        f"/checkout_sessions/{sid}/complete",
        {
            "payment_data": {
                "handler_id": "h",
                "instrument": {"type": "card", "credential": {"type": "spt", "token": "t"}},
            }
        },
        **kw,
    )


def test_a_locked_principal_is_denied_on_acp_complete_with_nothing_reserved(
    acp: tuple[Stack, Any],
) -> None:
    stack, _ = acp
    token = delegation(stack.keys)
    session = make_session(stack, token=token, capability=True)  # negotiated: locked
    response = complete(stack, session["id"], token=token)
    body = assert_error(response, 403, "mandate_required")
    assert body["type"] == "invalid_request"
    untouched(stack)
    with stack.engine.connect() as conn:
        kinds = [e.kind for e in entries_for_checkout(conn, session["id"])]
    assert "acp.complete_denied" in kinds and "lock.decision" in kinds


def test_negotiating_on_ucp_then_opening_an_acp_session_without_a_mandate_is_denied(
    acp: tuple[Stack, Any],
) -> None:
    stack, _ = acp
    token = delegation(stack.keys)
    ucp = stack.client.post(
        "/ucp/v1/checkout-sessions",
        json={"line_items": [{"item": {"id": ITEM.id}, "quantity": 1}]},
        headers={
            "UCP-Agent": 'profile="https://platform.example/profile"',
            "Countersign-Delegation": token,
            "Countersign-Capabilities": AP2_CAPABILITY,
        },
    )
    assert ucp.status_code == 201
    # The protocol downgrade and the new session escape: the same principal, another protocol.
    escape = post(stack, "/checkout_sessions", create_body(), token=token)
    assert_error(escape, 403, "mandate_required")
    # The same agent with another key is a different principal.
    other = delegation(stack.keys, agent=1)
    assert post(stack, "/checkout_sessions", create_body(), token=other).status_code == 201
    # Negotiating on ACP satisfies the lock at create; complete is still denied without a mandate.
    session = make_session(stack, token=token, capability=True)
    assert_error(complete(stack, session["id"], token=token), 403, "mandate_required")


def test_an_acp_update_by_a_locked_principal_without_the_capability_is_denied(
    acp: tuple[Stack, Any],
) -> None:
    stack, _ = acp
    token = delegation(stack.keys)
    session = make_session(stack, token=token, capability=True)
    body = {"line_items": [{"id": ITEMS[1].id}]}
    assert_error(
        post(stack, f"/checkout_sessions/{session['id']}", body, token=token),
        403,
        "mandate_required",
    )
    assert (
        post(
            stack, f"/checkout_sessions/{session['id']}", body, token=token, capability=True
        ).status_code
        == 200
    )


def test_require_all_denies_any_acp_complete_and_any_unidentified_create(
    acp: tuple[Stack, Any],
) -> None:
    stack, lock = acp
    session = make_session(stack)  # created before the policy tightened
    lock.set_policy("all", reason="strict")
    for who in ({}, {"token": delegation(stack.keys)}, {"token": delegation(stack.keys, sub=None)}):
        assert_error(complete(stack, session["id"], **who), 403, "mandate_required")
    assert_error(post(stack, "/checkout_sessions", create_body()), 403, "mandate_required")
    untouched(stack)


def test_a_different_unlocked_principal_is_not_blocked_by_someone_elses_lock(
    acp: tuple[Stack, Any],
) -> None:
    stack, _ = acp
    make_session(stack, token=delegation(stack.keys), capability=True)  # locks cust-1 / agent 0
    other = delegation(stack.keys, sub="cust-2", agent=1)
    session = make_session(stack, token=other)
    # Not locked: the denial is the unmandated rule, a different code from the lock's.
    body = assert_error(
        complete(stack, session["id"], token=other), 403, "unmandated_checkout_not_allowed"
    )
    assert "AP2" in body["message"]
    untouched(stack)
    with stack.engine.connect() as conn:
        denials = [
            json.loads(e.payload)
            for e in entries_for_checkout(conn, session["id"])
            if e.kind == "acp.complete_denied"
        ]
    assert [d["reason"] for d in denials] == ["unmandated_checkout_not_allowed"]


def test_an_unidentified_agent_is_not_locked_and_gets_the_unmandated_denial(
    acp: tuple[Stack, Any],
) -> None:
    stack, _ = acp
    session = make_session(stack)
    assert_error(complete(stack, session["id"]), 403, "unmandated_checkout_not_allowed")
    untouched(stack)


def test_delegated_payment_is_rejected_and_a_locked_principal_gets_mandate_required(
    acp: tuple[Stack, Any],
) -> None:
    stack, _ = acp
    token = delegation(stack.keys)
    make_session(stack, token=token, capability=True)
    payload = {"payment_method": {"type": "card"}}
    assert_error(
        post(stack, "/agentic_commerce/delegate_payment", payload, token=token),
        403,
        "mandate_required",
    )
    assert_error(
        post(stack, "/agentic_commerce/delegate_payment", payload),
        403,
        "delegated_payment_unsupported",
    )
    assert_error(post(stack, "/agentic_commerce/delegate_payment", b"{bad"), 400)
    untouched(stack)


def test_the_unmandated_seam_is_called_for_unlocked_principals_and_must_deny(
    acp: tuple[Stack, Any],
) -> None:
    from countersign.canonical.models import Checkout
    from countersign.lock import Principal
    from countersign.protocols.acp.service import UnmandatedDenied

    stack, _ = acp
    seen: list[tuple[str, Principal | None]] = []

    class Custom:
        def complete(self, checkout: Checkout, principal: Principal | None) -> UnmandatedDenied:
            seen.append((checkout.id, principal))
            return UnmandatedDenied("custom_denial", "Denied by the custom policy.")

    class Rogue:
        def complete(self, checkout: Checkout, principal: Principal | None) -> Any:
            return "accepted"  # a permissive outcome is not something the adapter will act on

    service = stack.client.app.state.acp  # type: ignore[attr-defined]
    token = delegation(stack.keys, sub="cust-7", agent=2)
    session = make_session(stack, token=token)
    service._unmandated = Custom()
    assert_error(complete(stack, session["id"], token=token), 403, "custom_denial")
    assert [s[0] for s in seen] == [session["id"]] and seen[0][1] is not None
    service._unmandated = Rogue()
    assert_error(complete(stack, session["id"], token=token), 500, "internal_error")

    class LookAlike:
        """Has the attributes of a denial but is not one: a permissive outcome in disguise."""

        def complete(self, checkout: Checkout, principal: Principal | None) -> Any:
            from types import SimpleNamespace

            return SimpleNamespace(code="accepted", message="Accepted.")

    service._unmandated = LookAlike()
    assert_error(complete(stack, session["id"], token=token), 500, "internal_error")
    untouched(stack)


def test_twenty_parallel_acp_completes_for_a_locked_principal_are_all_denied_with_no_paypal_call(
    acp: tuple[Stack, Any],
) -> None:
    stack, _ = acp
    token = delegation(stack.keys)
    session = make_session(stack, token=token, capability=True)
    barrier = threading.Barrier(20)

    def attempt(n: int) -> Any:
        barrier.wait()
        return complete(stack, session["id"], token=token, key=f"k-{n}")

    with ThreadPoolExecutor(20) as pool:
        results = list(pool.map(attempt, range(20)))
    assert [r.status_code for r in results] == [403] * 20
    assert {r.json()["code"] for r in results} == {"mandate_required"}
    untouched(stack)


def test_an_unexpected_failure_is_a_500_error_with_nothing_authorized(
    acp: tuple[Stack, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from countersign.lock import PrincipalLock

    stack, _ = acp

    def boom(self: PrincipalLock, request: Any) -> Any:
        raise RuntimeError("internal detail that must not leak")

    monkeypatch.setattr(PrincipalLock, "decide", boom)
    response = post(stack, "/checkout_sessions", create_body())
    body = assert_error(response, 500, "internal_error")
    assert body["type"] == "processing_error" and "detail" not in json.dumps(body)
    untouched(stack)


def test_a_log_failure_fails_the_acp_request(
    acp: tuple[Stack, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from countersign.ledger import store as ledger_store

    stack, _ = acp
    real = ledger_store.append

    def broken(conn: Any, **kw: Any) -> Any:
        if kw["kind"] == "acp.session_created":
            raise RuntimeError("log unavailable")
        return real(conn, **kw)

    monkeypatch.setattr(ledger_store, "append", broken)
    assert_error(post(stack, "/checkout_sessions", create_body()), 500, "internal_error")
    with stack.engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM checkout_sessions")).scalar() == 0

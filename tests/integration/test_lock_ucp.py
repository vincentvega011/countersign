"""The lock through the UCP adapter, over HTTP, and through the capture gate.

Real: the lock, the Merchant, the Credential Provider, the gate, Postgres, the decision log. The UCP
adapter holds no lock logic: it reads two headers and calls the shared function.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, select

from countersign.gate import GatePassed, GateRejected
from countersign.lock import LockRequest, Principal
from countersign.protocols.ucp.profile import AP2_CAPABILITY
from countersign.tables import lock_events, reservations
from tests.gate_support import GateWorld, make_gate_world
from tests.integration.test_ucp_complete import (
    AGENT,
    ITEM,
    ROOT,
    Stack,
    codes,
    complete,
    complete_body,
    mandates,
)
from tests.integration.test_ucp_complete_gate import build
from tests.lock_support import delegation, request
from tests.mandate_issuer import Keys


@pytest.fixture
def ucp(app_engine: Engine, clean_payments: None) -> Iterator[tuple[Stack, Any]]:
    _, stack, _key, lock = build(app_engine)
    with stack.client:
        yield stack, lock


def post_checkout(stack: Stack, *, delegation_token: str | None, capability: bool) -> Any:
    headers = dict(AGENT)
    if delegation_token:
        headers["Countersign-Delegation"] = delegation_token
    if capability:
        headers["Countersign-Capabilities"] = AP2_CAPABILITY
    return stack.client.post(
        ROOT, json={"line_items": [{"item": {"id": ITEM.id}, "quantity": 1}]}, headers=headers
    )


def lock_rows(stack: Stack) -> list[Any]:
    with stack.engine.connect() as conn:
        return list(conn.execute(select(lock_events)).all())


def test_negotiating_ap2_on_create_records_the_lock_before_any_later_checkout(
    ucp: tuple[Stack, Any],
) -> None:
    stack, _ = ucp
    token = delegation(stack.keys)
    first = post_checkout(stack, delegation_token=token, capability=True)
    assert first.status_code == 201 and len(lock_rows(stack)) == 1


def test_a_new_session_without_the_capability_is_denied_for_the_same_principal(
    ucp: tuple[Stack, Any],
) -> None:
    stack, _ = ucp
    token = delegation(stack.keys)
    assert post_checkout(stack, delegation_token=token, capability=True).status_code == 201
    second = post_checkout(stack, delegation_token=token, capability=False)
    body = second.json()
    assert "id" not in body and codes(second) == ["mandate_required"]
    assert body["messages"][0]["severity"] == "unrecoverable"


def test_another_agent_key_is_not_locked_by_the_first(ucp: tuple[Stack, Any]) -> None:
    stack, _ = ucp
    post_checkout(stack, delegation_token=delegation(stack.keys), capability=True)
    other = delegation(stack.keys, agent=1)
    assert post_checkout(stack, delegation_token=other, capability=False).status_code == 201


def test_an_update_in_a_session_without_the_capability_is_denied_for_a_locked_principal(
    ucp: tuple[Stack, Any],
) -> None:
    stack, _ = ucp
    token = delegation(stack.keys)
    created = post_checkout(stack, delegation_token=token, capability=True).json()
    headers = {**AGENT, "Countersign-Delegation": token}
    body = {"line_items": [{"item": {"id": ITEM.id}, "quantity": 2}]}
    denied = stack.client.put(f"{ROOT}/{created['id']}", json=body, headers=headers)
    assert codes(denied) == ["mandate_required"]
    assert denied.json()["line_items"][0]["quantity"] == 1  # unchanged
    headers["Countersign-Capabilities"] = AP2_CAPABILITY
    assert (
        stack.client.put(f"{ROOT}/{created['id']}", json=body, headers=headers).status_code == 200
    )


def test_a_delegation_that_does_not_verify_names_nobody(ucp: tuple[Stack, Any]) -> None:
    stack, _ = ucp
    stranger = delegation(Keys())  # signed by a key that is not the platform's
    first = post_checkout(stack, delegation_token=stranger, capability=True)
    assert first.status_code == 201 and lock_rows(stack) == []  # no one was recorded


def test_require_all_denies_an_unidentified_create_and_allows_a_negotiated_one(
    ucp: tuple[Stack, Any],
) -> None:
    stack, lock = ucp
    lock.set_policy("all", reason="strict")
    assert codes(post_checkout(stack, delegation_token=None, capability=False)) == [
        "mandate_required"
    ]
    ok = post_checkout(stack, delegation_token=delegation(stack.keys), capability=True)
    assert ok.status_code == 201


def test_a_locked_principal_that_completes_without_a_mandate_is_denied(
    ucp: tuple[Stack, Any],
) -> None:
    stack, _ = ucp
    token = delegation(stack.keys)
    created = post_checkout(stack, delegation_token=token, capability=True).json()
    headers = {**AGENT, "Countersign-Delegation": token}
    response = stack.client.post(f"{ROOT}/{created['id']}/complete", json={}, headers=headers)
    assert codes(response) == ["mandate_required"]
    assert response.json()["status"] == "ready_for_complete"  # nothing was spent
    # The refusal is the lock's decision, logged, and not only the Merchant's missing-mandate answer.
    from countersign.ledger.store import entries_for_checkout

    with stack.engine.connect() as conn:
        decisions = [
            json.loads(e.payload)
            for e in entries_for_checkout(conn, created["id"])
            if e.kind == "lock.decision"
        ]
    assert decisions[-1]["operation"] == "complete" and decisions[-1]["allowed"] is False
    assert stack.sim.calls == []
    with stack.engine.connect() as conn:
        assert conn.execute(select(reservations)).all() == []


def test_under_require_all_a_mandate_naming_no_customer_is_denied_and_released(
    ucp: tuple[Stack, Any],
) -> None:
    stack, lock = ucp
    lock.set_policy("all", reason="strict")
    token = delegation(stack.keys)
    created = post_checkout(stack, delegation_token=token, capability=True).json()
    cm, pm = mandates(stack, created)  # signed with no `sub`
    response = complete(stack, created["id"], complete_body(cm, pm))
    assert "mandate_required" in codes(response) and response.json()["status"] == "canceled"
    assert stack.sim.orders == {}
    with stack.engine.connect() as conn:
        states = {r.role: r.state for r in conn.execute(select(reservations)).all()}
    assert states == {"merchant": "released"}


def test_under_require_all_a_mandate_that_names_the_customer_goes_through(
    ucp: tuple[Stack, Any],
) -> None:
    stack, lock = ucp
    lock.set_policy("all", reason="strict")
    token = delegation(stack.keys)
    created = post_checkout(stack, delegation_token=token, capability=True).json()
    cm, pm = mandates(stack, created, sub="cust-1")
    response = complete(stack, created["id"], complete_body(cm, pm))
    assert codes(response) == ["payer_approval_required"]
    assert len(stack.sim.orders) == 1


def test_a_second_protocol_path_for_the_same_principal_is_denied_by_the_same_function(
    ucp: tuple[Stack, Any],
) -> None:
    stack, lock = ucp
    post_checkout(stack, delegation_token=delegation(stack.keys), capability=True)
    who = Principal("cust-1", stack.keys.agents[0].thumbprint())
    assert lock.decide(request("complete", who, mandate=False)).allowed is False


def test_the_ucp_adapter_has_no_lock_logic_of_its_own() -> None:
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "src" / "countersign" / "protocols" / "ucp"
    text = (src / "service.py").read_text()
    # It builds a request and reads `verdict.allowed`; it never looks inside the policy or the store.
    for needle in ("lock_events", "MerchantPolicy", "requires_ap2", "lock_state", "is_locked"):
        assert needle not in text


# ------------------------------------------------------------------------------ the gate


def sub_payload(sub: str | None) -> dict[str, Any]:
    def edit(payload: dict[str, Any]) -> None:
        if sub is not None:
            payload["sub"] = sub

    return {"edit_open_payload": edit}


@pytest.fixture
def gworld(app_engine: Engine, clean_payments: None) -> GateWorld:
    return make_gate_world(app_engine)


def gate_run(world: GateWorld) -> Any:
    return world.gate.run(checkout_id=world.checkout.id, current=world.checkout)


def authorize_with(world: GateWorld, sub: str | None) -> None:
    world.authorize(payment_kwargs=sub_payload(sub), checkout_kwargs=sub_payload(sub))


def test_g_lock_uses_the_real_lock_and_a_valid_mandate_captures(gworld: GateWorld) -> None:
    authorize_with(gworld, "cust-1")
    outcome = gate_run(gworld)
    assert isinstance(outcome, GatePassed)
    from countersign.ledger.store import entries_for_checkout

    with gworld.engine.connect() as conn:
        kinds = [e.kind for e in entries_for_checkout(conn, gworld.checkout.id)]
    # The gate's G-LOCK went through the shared function, which logged its decision before the capture.
    assert kinds.index("lock.decision") < kinds.index("gate.paypal.capture.started")


def test_a_policy_tightened_between_authorize_and_capture_voids_a_nameless_mandate(
    gworld: GateWorld,
) -> None:
    authorize_with(gworld, None)
    gworld.lock.set_policy("all", reason="tightened after authorization")
    outcome = gate_run(gworld)
    assert isinstance(outcome, GateRejected) and outcome.code == "G-LOCK"
    assert outcome.reason == "lock_denied:denied:customer_unknown"
    assert gworld.sim.count("/capture") == 0 and gworld.sim.count("/void") == 1


def test_a_policy_tightened_between_authorize_and_capture_still_captures_a_named_mandate(
    gworld: GateWorld,
) -> None:
    authorize_with(gworld, "cust-1")
    gworld.lock.set_policy("all", reason="tightened after authorization")
    outcome = gate_run(gworld)
    assert isinstance(outcome, GatePassed) and gworld.sim.count("/capture") == 1


def test_a_lock_added_between_authorize_and_capture_voids_a_nameless_mandate(
    gworld: GateWorld,
) -> None:
    authorize_with(gworld, None)
    agent = gworld.base.keys.agents[0].thumbprint()
    gworld.lock.decide(
        LockRequest("create", "chk_other", Principal("cust-9", agent), True, False, None)
    )
    outcome = gate_run(gworld)
    assert isinstance(outcome, GateRejected) and outcome.code == "G-LOCK"
    assert gworld.sim.count("/capture") == 0 and gworld.sim.count("/void") == 1


def test_a_lock_added_between_authorize_and_capture_still_captures_a_named_mandate(
    gworld: GateWorld,
) -> None:
    authorize_with(gworld, "cust-1")
    agent = gworld.base.keys.agents[0].thumbprint()
    gworld.lock.decide(
        LockRequest("create", "chk_other", Principal("cust-1", agent), True, False, None)
    )
    assert isinstance(gate_run(gworld), GatePassed)


def test_the_lock_store_failing_at_capture_voids(
    gworld: GateWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    from countersign.lock import LockStore, LockStoreError

    authorize_with(gworld, "cust-1")

    def broken(self: LockStore, *a: Any, **k: Any) -> Any:
        raise LockStoreError("down")

    monkeypatch.setattr(LockStore, "current_policy", broken)
    outcome = gate_run(gworld)
    assert isinstance(outcome, GateRejected) and outcome.code == "G-LOCK"
    assert "lock_store_unreadable" in outcome.reason
    assert gworld.sim.count("/capture") == 0

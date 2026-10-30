"""Modes through the composition root: labels, isolation from `full`, and what baseline does.

Baseline is a faithful but conventional integration, so the tests here check both halves: it keeps
verifying mandates in the session, and it loses exactly the protections listed in
docs/PROTOCOL.md Decision 59.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import Engine, select

from countersign.ablations import Ablations
from countersign.runtime import ABLATIONS_HEADER, MODE_HEADER, Mode, RuntimeSettings
from countersign.tables import payer_vault
from tests import acp_schemas as acp_schema
from tests.behavior_scenarios import budget_split_across_sessions, order_raised_while_approved
from tests.mandate_issuer import NOW
from tests.mode_support import (
    ITEM,
    UCP_AGENT,
    World,
    acp_create,
    acp_headers,
    acp_post,
    codes,
    complete_body,
    delegation,
    lock_principal,
    make_world,
    mandate_pair,
    new_checkout,
    purchase,
    reset,
    settings_for,
    ucp_complete,
)

PAYMENT = {
    "payment_data": {
        "handler_id": "h",
        "instrument": {"type": "card", "credential": {"type": "spt", "token": "t"}},
    }
}


@pytest.fixture
def clean(admin_engine: Engine) -> None:
    reset(admin_engine)


def world_for(app_engine: Engine, config: str, **kw: Any) -> World:
    return make_world(app_engine, settings_for(config, **kw))


# ------------------------------------------------------------------ the label


@pytest.mark.parametrize(
    ("config", "mode", "ablations"),
    [
        ("full", "full", []),
        ("baseline", "baseline", []),
        ("ABL_NO_GATE", "full", ["ABL_NO_GATE"]),
        ("ABL_NO_STRICT_JSON", "full", ["ABL_NO_STRICT_JSON"]),
    ],
)
def test_health_and_a_header_on_every_response_report_the_mode(
    app_engine: Engine, clean: None, config: str, mode: str, ablations: list[str]
) -> None:
    with world_for(app_engine, config).client as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json() == {
            "status": "ok",
            "mode": mode,
            "app_env": "dev",
            "ablations": ablations,
        }
        responses = [
            health,
            client.get("/.well-known/ucp"),
            client.get("/ucp/v1/checkout-sessions/chk_nothing_here_0000000"),  # a 404
            client.post("/ucp/v1/checkout-sessions", content=b"{"),  # a 400
            client.get("/checkout_sessions/chk_nothing_here_0000000"),  # an ACP 404
        ]
        for response in responses:
            assert response.headers[MODE_HEADER] == mode, response.request.url
            assert response.headers.get(ABLATIONS_HEADER) == (",".join(ablations) or None)


def test_an_internal_error_response_carries_the_label_too(
    app_engine: Engine, clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from countersign.protocols.ucp.service import UcpService

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(UcpService, "get", boom)
    with world_for(app_engine, "baseline").client as client:
        response = client.get("/ucp/v1/checkout-sessions/chk_whatever_00000000", headers=UCP_AGENT)
    assert response.status_code == 500 and response.headers[MODE_HEADER] == "baseline"


def test_baseline_starts_in_demo_and_says_so(app_engine: Engine, clean: None) -> None:
    with world_for(app_engine, "baseline", app_env="demo").client as client:
        body = client.get("/health").json()
    assert body["mode"] == "baseline" and body["app_env"] == "demo"


# ------------------------------------------------------------------ full never touches baseline code


def test_full_without_flags_builds_nothing_from_the_degraded_package(
    app_engine: Engine, clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from countersign.degraded import immediate_capture, lenient_json, unmandated

    def refuse(*_: Any, **__: Any) -> None:
        raise AssertionError("degraded code was reached in full mode")

    monkeypatch.setattr(immediate_capture.ImmediateCapture, "__init__", refuse)
    monkeypatch.setattr(unmandated.NaiveUnmandatedCompletion, "__init__", refuse)
    monkeypatch.setattr(lenient_json, "loads_lenient", refuse)
    world = world_for(app_engine, "full")
    with world.client:
        body = new_checkout(world)
        done = purchase(world, body, mandate_pair(world, body))
        assert done.json()["status"] == "completed"
        # The original strict loader and the original ACP seam are in place.
        assert (
            world.client.post("/ucp/v1/checkout-sessions", content=b'{"a":1,"a":2}').status_code
            == 400
        )
        assert type(world.client.app.state.acp._unmandated).__name__ == "DenyUnmandated"  # type: ignore[attr-defined]


def test_a_flag_that_is_unset_is_a_no_op_in_every_piece_it_touches() -> None:
    from countersign.merchant.pg_reservations import PostgresReservationStore
    from countersign.merchant.reservations import ReservationRequest

    request = ReservationRequest("chk_1", "hash", "digest", ("tp", "aud", "n"))
    store = PostgresReservationStore.__new__(PostgresReservationStore)
    store._session_scoped = False  # type: ignore[attr-defined]
    assert store._scoped("value", request) == "value"  # type: ignore[attr-defined]


def test_only_baseline_and_the_flag_pick_the_lenient_loader(
    app_engine: Engine, clean: None
) -> None:
    def lines(quantity: int) -> str:
        return json.dumps([{"item": {"id": ITEM.id}, "quantity": quantity}])

    duplicate = f'{{"line_items":{lines(1)},"line_items":{lines(2)}}}'.encode()
    headers = {"UCP-Agent": 'profile="https://p.example/x"', "Content-Type": "application/json"}
    status = {}
    for config in ("full", "baseline", "ABL_NO_STRICT_JSON", "ABL_NO_GATE"):
        with world_for(app_engine, config).client as client:
            status[config] = client.post(
                "/ucp/v1/checkout-sessions", content=duplicate, headers=headers
            ).status_code
    assert status["full"] == status["ABL_NO_GATE"] == 400
    assert status["baseline"] == status["ABL_NO_STRICT_JSON"] != 400


# ------------------------------------------------------------------ baseline: captures at once


def _kind(path: str) -> str:
    if path.endswith("/capture"):
        return "capture"
    return "order" if "/orders/" in path else "authorization"


def _calls(world: World) -> list[tuple[str, str]]:
    return [(m, p) for m, p, _ in world.sim.calls if not p.startswith("/v1/oauth2")]


def test_baseline_captures_straight_after_authorizing_with_no_gate_reads(
    app_engine: Engine, clean: None
) -> None:
    after_capture: dict[str, list[str]] = {}
    for config in ("full", "baseline"):
        world = world_for(app_engine, config)
        with world.client:
            body = new_checkout(world)
            pair = mandate_pair(
                world, body, nonce_checkout=f"c-{config}", nonce_payment=f"p-{config}"
            )
            assert purchase(world, body, pair).json()["status"] == "completed"
        posts = [
            "create" if p == "/v2/checkout/orders" else p.rsplit("/", 1)[-1]
            for m, p in _calls(world)
            if m == "POST"
        ]
        assert posts == ["create", "authorize", "capture"]
        calls = _calls(world)
        at = next(i for i, (m, p) in enumerate(calls) if m == "POST" and p.endswith("/capture"))
        after_capture[config] = [p for _, p in calls[at + 1 :]]
    assert after_capture["baseline"] == []  # nothing is read after the capture: no confirmation
    assert any("/captures/" in p for p in after_capture["full"])  # the gate confirms its capture


def test_baseline_makes_no_gate_read_between_authorizing_and_capturing(
    app_engine: Engine, clean: None
) -> None:
    world = world_for(app_engine, "baseline")
    with world.client:
        body = new_checkout(world)
        purchase(world, body, mandate_pair(world, body))
    calls = _calls(world)
    at = next(i for i, (m, p) in enumerate(calls) if m == "POST" and p.endswith("/authorize"))
    kinds = [(m, _kind(p)) for m, p in calls[at + 1 :]]
    # The Credential Provider's record of the order and of the authorization, then the one read of
    # the authorization that sets the capture amount, the client's own check inside capture, and the
    # capture. No capture read, no terms re-derivation, nothing after.
    assert kinds == [
        ("GET", "order"), ("GET", "authorization"), ("GET", "authorization"),
        ("GET", "authorization"), ("POST", "capture"),
    ]  # fmt: skip


# ------------------------------------------------------------------ baseline still verifies in session


@pytest.mark.parametrize(
    ("what", "pair_kwargs", "code"),
    [
        ("wrong vct", {"checkout_issue": {"closed_vct": "mandate.checkout.9"}}, None),
        ("mismatched hash", {"checkout_issue": {"checkout_hash_value": "A" * 43}}, None),
        ("expired", {"open_exp": NOW - 3600}, "mandate_expired"),
        ("other amount", {"amount": 1}, "mandate_scope_mismatch"),
    ],
)
@pytest.mark.parametrize("config", ["full", "baseline"])
def test_a_bad_mandate_is_refused_in_baseline_as_in_full_and_nothing_reaches_paypal(
    app_engine: Engine,
    clean: None,
    config: str,
    what: str,
    pair_kwargs: dict[str, Any],
    code: str | None,
) -> None:
    world = world_for(app_engine, config)
    with world.client:
        body = new_checkout(world)
        pair = mandate_pair(world, body, **pair_kwargs)
        response = ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
        assert codes(response) and codes(response)[0] != "payer_approval_required", what
        if code:
            assert codes(response)[0] == code
        assert world.sim.authorizations == {} and world.sim.captures == {}
        assert not any(
            m == "POST" and p.endswith(("authorize", "capture")) for m, p, _ in world.sim.calls
        )


def test_a_mandate_forged_for_another_checkout_is_refused_in_baseline(
    app_engine: Engine, clean: None
) -> None:
    world = world_for(app_engine, "baseline")
    with world.client:
        one, two = new_checkout(world), new_checkout(world)
        pair = mandate_pair(world, one)
        refused = ucp_complete(world, two["id"], complete_body(pair.cm, pair.pm))
        assert codes(refused) == ["mandate_scope_mismatch"] or "mandate" in codes(refused)[0]
        assert world.sim.captures == {}


# ------------------------------------------------------------------ baseline ACP: how payer approval is obtained


def test_baseline_acp_without_a_vault_entry_asks_the_payer_to_approve_and_then_captures(
    app_engine: Engine, clean: None
) -> None:
    world = world_for(app_engine, "baseline")
    with world.client:
        token = delegation(world.keys)
        lock_principal(world, token)  # locked in full; baseline records and honours nothing
        created = acp_create(world, token, capability=False)
        assert created.status_code == 201
        sid, headers = created.json()["id"], acp_headers(token)
        path = f"/checkout_sessions/{sid}/complete"
        first = acp_post(world, path, PAYMENT, headers)
        assert first.status_code == 200 and first.json()["status"] == "complete_in_progress"
        assert first.json()["continue_url"].startswith("https://www.sandbox.paypal.com/")
        acp_schema.SESSION.validate(first.json())
        assert (
            world.sim.authorizations == {} and world.sim.captures == {}
        )  # nothing before approval
        (order_id,) = world.sim.orders
        world.sim.approve(order_id)
        second = acp_post(world, path, PAYMENT, headers)
        assert second.json()["status"] == "completed" and len(world.sim.captures) == 1
        acp_schema.SESSION_WITH_ORDER.validate(second.json())
        again = acp_post(world, path, PAYMENT, headers)  # a retry captures nothing more
        assert again.json()["status"] == "completed" and len(world.sim.captures) == 1


def test_baseline_acp_with_a_vault_entry_charges_the_stored_wallet_without_approval(
    app_engine: Engine, clean: None
) -> None:
    world = world_for(app_engine, "baseline")
    with world.client:
        token = delegation(world.keys)
        thumbprint = world.keys.agents[0].thumbprint()
        world.sim.vault_ids["seed"] = "VAULT-SEED"
        with app_engine.begin() as conn:
            conn.execute(
                payer_vault.insert().values(
                    principal=thumbprint, vault_id="VAULT-SEED", created_us=1
                )
            )
        sid = acp_create(world, token, capability=False).json()["id"]
        done = acp_post(world, f"/checkout_sessions/{sid}/complete", PAYMENT, acp_headers(token))
        assert done.json()["status"] == "completed" and len(world.sim.captures) == 1
        with app_engine.connect() as conn:
            assert conn.execute(select(payer_vault.c.vault_id)).scalar_one() == "VAULT-SEED"


def test_baseline_acp_charges_nobody_without_a_payer_step(app_engine: Engine, clean: None) -> None:
    """No way to charge exists that skips the payer: no vault entry and no approval means no capture."""
    world = world_for(app_engine, "baseline")
    with world.client:
        sid = acp_create(world, None, capability=False).json()["id"]
        path = f"/checkout_sessions/{sid}/complete"
        for _ in range(3):
            response = acp_post(world, path, PAYMENT, acp_headers(None))
            assert response.json()["status"] == "complete_in_progress"
        assert world.sim.captures == {} and world.sim.authorizations == {}


# ------------------------------------------------------------------ the layers behind each other


def test_the_budget_counter_refuses_the_split_even_with_every_single_use_rule_off(
    app_engine: Engine, admin_engine: Engine
) -> None:
    """The local counter (built from the service's own authorizations and captures) is a real layer."""
    results = {}
    for name, ablations in {
        "none": Ablations(),
        "global_nonce": Ablations(no_global_nonce=True),
        "budget": Ablations(no_budget_recon=True),
        "both": Ablations(no_global_nonce=True, no_budget_recon=True),
    }.items():
        reset(admin_engine)
        world = make_world(app_engine, RuntimeSettings(Mode.FULL, "dev", ablations))
        with world.client:
            results[name] = budget_split_across_sessions(world)["captured"]
    assert results == {"none": 1, "global_nonce": 1, "budget": 1, "both": 1}


def test_with_the_pre_authorize_check_and_the_gate_both_off_a_raised_order_is_captured_raised(
    app_engine: Engine, admin_engine: Engine
) -> None:
    results = {}
    for name, ablations in {
        "preauth": Ablations(no_preauth_check=True),
        "both": Ablations(no_preauth_check=True, no_gate=True),
    }.items():
        reset(admin_engine)
        world = make_world(app_engine, RuntimeSettings(Mode.FULL, "dev", ablations))
        with world.client:
            results[name] = order_raised_while_approved(world)
    assert results["preauth"]["captured"] == 0 and results["preauth"]["voided"] == 1
    assert results["both"]["captured_value"] == ["33.00"]  # the raised amount, with no layer left


# ------------------------------------------------------------------ what is not wired


def test_webhook_reconciliation_is_wired_only_where_the_budget_is_reconciled(
    app_engine: Engine, clean: None
) -> None:
    served = {}
    for config in ("full", "baseline", "ABL_NO_BUDGET_RECON", "ABL_NO_GATE"):
        world = make_world(app_engine, settings_for(config), webhook_id="WH-TEST")
        with world.client:
            served[config] = world.client.post("/webhooks/paypal", content=b"{}").status_code != 404
    assert served == {
        "full": True, "baseline": False, "ABL_NO_BUDGET_RECON": False, "ABL_NO_GATE": True,
    }  # fmt: skip


def test_in_full_a_session_that_is_already_completing_never_reaches_the_unmandated_seam(
    app_engine: Engine, admin_engine: Engine, clean: None
) -> None:
    from tests.integration.test_ucp_checkout_api import force

    world = world_for(app_engine, "full")
    with world.client:
        sid = acp_create(world, None, capability=False).json()["id"]
        force(admin_engine, sid, "complete_in_progress")
        response = acp_post(world, f"/checkout_sessions/{sid}/complete", PAYMENT, acp_headers(None))
    assert response.status_code == 409 and response.json()["code"] == "not_ready"

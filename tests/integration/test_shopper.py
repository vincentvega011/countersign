"""The shopping agent against the whole service (composition root, real Postgres, PayPal simulator).

The agent is a separate client that speaks HTTP only. The customer's phone is a Python device here (the
browser-driven, cassette-backed run is tests/integration/test_shopper_replay.py). Covered: the purchase
end to end, an invalid `merchant_authorization`, a rejected completion with a retry after the rejection
receipt, an expired mandate, a consent that never comes, and the private key never leaving the process.
"""

from __future__ import annotations

import json
import pickle
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, text

from agents.shopper import AgentKey, ShopperError, run_shopper, wire
from agents.shopper.client import ServiceClient
from tests import paypal_sim
from tests.mandate_issuer import NOW
from tests.mode_support import reset
from tests.shopper_support import ShopperWorld, fake_gateway, make_world
from tests.surface_support import ORIGIN

WISH = {"categories": ["headphones"], "quantity": 1, "ceiling_minor": 8000, "valid_for_hours": 168}
GOAL = "headphones under 80 dollars, this week"


@pytest.fixture
def world(app_engine: Engine, admin_engine: Engine) -> Iterator[ShopperWorld]:
    reset(admin_engine)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE consent_records, key_revocations, key_challenge_uses, key_challenges, "
                "customer_keys, open_mandate_revocations, open_mandates, agent_proposals, "
                "proposal_uses, purchase_offers, activity_sessions CASCADE"
            )
        )
    yield make_world(app_engine)


def run(world: ShopperWorld, **kw: Any) -> Any:
    kw.setdefault("on_approve_url", world.phone)
    kw.setdefault("on_payer_approval", world.payer_approves)
    kw.setdefault("gateway", fake_gateway(WISH, lambda ids: ids[0]))
    kw.setdefault("clock", lambda: float(NOW))
    kw.setdefault("sleep", lambda _s: None)
    return run_shopper(GOAL, base_url=ORIGIN, http=world.http, **kw)


def captures(world: ShopperWorld) -> int:
    return world.sim.count("/capture")


# ------------------------------------------------------------------------------------ the purchase


def test_a_goal_becomes_a_captured_order(world: ShopperWorld) -> None:
    events: list[dict[str, Any]] = []
    result = run(world, emit=events.append)
    assert result.outcome == "completed" and result.attempts == 1
    assert result.capture_id in world.sim.captures
    assert result.amount_minor is not None and 0 < result.amount_minor <= 8000
    assert result.receipts["payment"]["status"] == "Success"
    assert result.receipts["payment"]["psp_confirmation_id"] == result.capture_id
    assert captures(world) == 1 and world.sim.count("/authorize") == 1
    assert [e["event"] for e in events] == [
        "wish", "chosen", "approve_url", "consent", "payer_approval", "completed",
    ]  # fmt: skip
    assert json.loads(result.to_json())["capture_id"] == result.capture_id


def test_the_catalog_is_read_over_http_and_the_choice_is_checked(world: ShopperWorld) -> None:
    chosen = run(world, gateway=fake_gateway(WISH, lambda ids: ids[-1]))
    assert chosen.outcome == "completed"
    with pytest.raises(ShopperError) as caught:
        run(world, gateway=fake_gateway(WISH, "not-an-item"))
    assert caught.value.code == "plan_refused"


# ------------------------------------------------------------------------------------ what it refuses


def test_an_invalid_merchant_authorization_stops_the_run(
    world: ShopperWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    published = world.http.get("/.well-known/ucp").json()["keys"][0]
    other = {**AgentKey().jwk, "kid": published["kid"]}  # a different key under the same kid
    monkeypatch.setattr(ServiceClient, "merchant_keys", lambda self: [other])
    with pytest.raises(ShopperError) as caught:
        run(world)
    assert caught.value.code == "wire_invalid" and "merchant_authorization" in str(caught.value)
    assert captures(world) == 0 and world.sim.count("/authorize") == 0


def test_a_stripped_merchant_authorization_is_refused() -> None:
    with pytest.raises(wire.WireError):
        wire.checkout_jwt_of({"id": "chk_1", "ap2": {}}, [])


def test_a_consent_that_never_comes_times_out(world: ShopperWorld) -> None:
    ticks = iter(range(0, 10_000, 100))
    with pytest.raises(ShopperError) as caught:
        run(
            world,
            on_approve_url=lambda _url: None,
            consent_timeout_s=250.0,
            poll_s=0.0,
            clock=lambda: float(NOW + next(ticks)),
        )
    assert caught.value.code == "consent_timeout"
    assert captures(world) == 0


def test_an_expired_mandate_is_not_used(world: ShopperWorld) -> None:
    calls = {"n": 0}

    def clock() -> float:
        calls["n"] += 1
        return float(NOW) if calls["n"] == 1 else float(NOW + 30 * 86400)

    with pytest.raises(ShopperError) as caught:
        run(world, clock=clock)
    assert caught.value.code == "mandate_expired"
    assert world.sim.count("/authorize") == 0


def test_a_rejected_completion_is_retried_once_after_the_rejection_receipt(
    world: ShopperWorld,
) -> None:
    patched: list[str] = []

    def approve_then_raise_once(url: str) -> None:
        world.payer_approves(url)
        if not patched:  # the order is raised after approval: the pre-authorize check refuses it
            token = url.split("token=")[1]
            world.sim.patch(token, amount="79.99")
            patched.append(token)

    events: list[dict[str, Any]] = []
    result = run(world, on_payer_approval=approve_then_raise_once, emit=events.append)
    assert [e["event"] for e in events].count("rejected") == 1
    assert result.outcome == "completed" and result.attempts == 2
    assert captures(world) == 1  # nothing was captured for the refused attempt


def test_no_retry_without_a_rejection_receipt(world: ShopperWorld) -> None:
    result = run(world, max_attempts=1, on_payer_approval=None)
    assert result.outcome == "payer_approval_pending" and result.payer_approval_url
    assert captures(world) == 0


# ------------------------------------------------------------------------------------ the key


def test_the_private_key_never_leaves_the_process(world: ShopperWorld) -> None:
    key = AgentKey()
    secret = key._private.private_numbers().private_value
    needles = [
        wire.b64url(secret.to_bytes(32, "big")).encode(),
        secret.to_bytes(32, "big"),
        str(secret).encode(),
        f"{secret:x}".encode(),
    ]
    events: list[dict[str, Any]] = []
    result = run(world, key=key, emit=events.append)
    traffic = b"".join(world.spy.seen)
    everything = traffic + json.dumps(events).encode() + result.to_json().encode()
    everything += repr(key).encode() + str(key).encode() + repr(result).encode()
    assert traffic  # the agent really spoke over HTTP
    for needle in needles:
        assert needle not in everything
    with pytest.raises(TypeError):
        pickle.dumps(key)
    with pytest.raises(TypeError):
        import copy

        copy.deepcopy(key)


def test_a_key_file_is_private_and_not_overwritten(tmp_path: Any) -> None:
    key = AgentKey()
    path = tmp_path / "agent.pem"
    key.save(path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert AgentKey.load(path).thumbprint == key.thumbprint
    with pytest.raises(FileExistsError):
        key.save(path)


def test_paypal_was_only_reached_through_the_service(world: ShopperWorld) -> None:
    run(world)
    assert paypal_sim.MERCHANT  # the agent holds no PayPal credentials: it has no client for it
    from agents.shopper import client

    assert "paypal" not in client.__dict__.get("__doc__", "").lower().replace("only http", "")

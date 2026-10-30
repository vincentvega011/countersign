"""The fixed scenarios of the behavior matrix (tests/vectors/behavior_matrix.json).

Each scenario runs against one freshly built app and returns an `Outcome`: what the last decisive
request answered and what PayPal was asked to do. The expected outcome of every mode and every flag
is data, not code, so a change of behavior is a visible change of that file.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from tests import paypal_sim
from tests.mandate_issuer import NOW
from tests.mode_support import (
    ITEM,
    UCP_AGENT,
    UCP_ROOT,
    World,
    acp_create,
    acp_headers,
    acp_post,
    complete_body,
    delegation,
    lock_principal,
    mandate_pair,
    new_checkout,
    purchase,
    total_of,
    ucp_complete,
)

Outcome = dict[str, Any]


def outcome(world: World, response: Any) -> Outcome:
    body = response.json()
    listed = [m.get("code") for m in body.get("messages", []) if isinstance(m, dict)]
    code = body.get("code") if "code" in body and "status" not in body else None
    if code is None and listed:
        code = listed[0]
    captured = world.sim.captures.values()
    voided = sum(1 for a in world.sim.authorizations.values() if a["status"] == "VOIDED")
    return {
        "result": f"{response.status_code}:{body.get('status', 'error')}",
        "code": code,
        "authorized": len(world.sim.authorizations),
        "captured": len(captured),
        "voided": voided,
        "captured_value": sorted(c["amount"]["value"] for c in captured),
    }


def happy_path(world: World) -> Outcome:
    body = new_checkout(world)
    return outcome(world, purchase(world, body, mandate_pair(world, body)))


def mandate_forged(world: World) -> Outcome:
    body = new_checkout(world)
    pair = mandate_pair(world, body)
    mid = len(pair.cm) // 2
    bad = pair.cm[:mid] + ("A" if pair.cm[mid] != "A" else "B") + pair.cm[mid + 1 :]
    return outcome(world, ucp_complete(world, body["id"], complete_body(bad, pair.pm)))


def mandate_expired(world: World) -> Outcome:
    body = new_checkout(world)
    pair = mandate_pair(world, body, open_exp=NOW - 3600)
    return outcome(world, purchase(world, body, pair))


def nonce_replay_in_a_new_session(world: World) -> Outcome:
    first = new_checkout(world)
    purchase(world, first, mandate_pair(world, first))
    second = new_checkout(world)  # a new session, another open mandate, the same closed nonces
    return outcome(world, purchase(world, second, mandate_pair(world, second)))


def checkout_hash_reuse(world: World) -> Outcome:
    first = new_checkout(world)
    pair = mandate_pair(world, first)
    purchase(world, first, pair)
    second = new_checkout(world)  # the first checkout's signed mandates, presented for another
    return outcome(world, ucp_complete(world, second["id"], complete_body(pair.cm, pair.pm)))


def _approved_order(world: World) -> tuple[dict[str, Any], str]:
    body = new_checkout(world)
    pair = mandate_pair(world, body)
    ucp_complete(world, body["id"], complete_body(pair.cm, pair.pm))
    (order_id,) = world.sim.orders
    world.sim.approve(order_id)
    return body, order_id


def order_raised_while_approved(world: World) -> Outcome:
    body, order_id = _approved_order(world)
    world.sim.patch(order_id, amount=f"{total_of(body) * 3 / 100:.2f}")
    return outcome(world, ucp_complete(world, body["id"], {}))


def order_items_changed_while_approved(world: World) -> Outcome:
    body, order_id = _approved_order(world)
    world.sim.patch(order_id, item_name="Something else entirely")  # same amount, other goods
    return outcome(world, ucp_complete(world, body["id"], {}))


def acp_complete_without_mandate_by_a_locked_principal(world: World) -> Outcome:
    token = delegation(world.keys)
    lock_principal(world, token)
    created = acp_create(world, token, capability=False)
    if created.status_code != 201:  # the downgrade is already refused when the session is opened
        return outcome(world, created)
    session = created.json()
    headers = acp_headers(token)
    path = f"/checkout_sessions/{session['id']}/complete"
    payment = {
        "payment_data": {
            "handler_id": "h",
            "instrument": {"type": "card", "credential": {"type": "spt", "token": "t"}},
        }
    }
    response = acp_post(world, path, payment, headers)
    if response.status_code == 200 and response.json()["status"] == "complete_in_progress":
        (order_id,) = world.sim.orders
        world.sim.approve(order_id)
        response = acp_post(world, path, payment, headers)
    return outcome(world, response)


def budget_split_across_sessions(world: World) -> Outcome:
    first = new_checkout(world)
    total = total_of(first)
    budget = total * 3 // 2  # each purchase fits alone; two do not
    pair = mandate_pair(world, first, budget=budget)
    purchase(world, first, pair)
    second = new_checkout(world)
    again = mandate_pair(
        world, second, budget=budget, reuse=pair, nonce_checkout="nc-2", nonce_payment="np-2"
    )
    return outcome(world, purchase(world, second, again))


def duplicate_json_keys(world: World) -> Outcome:
    line = lambda q: {"item": {"id": ITEM.id}, "quantity": q}
    raw = json.dumps({"line_items": [line(1)]})
    raw = raw[:-1] + ', "line_items": ' + json.dumps([line(2)]) + "}"
    response = world.client.post(
        UCP_ROOT, content=raw.encode(), headers={**UCP_AGENT, "Content-Type": "application/json"}
    )
    out = outcome(world, response)
    if response.status_code == 201:
        out["code"] = f"quantity_{response.json()['line_items'][0]['quantity']}"
    return out


def amount_mismatch(world: World) -> Outcome:
    body = new_checkout(world)
    return outcome(world, purchase(world, body, mandate_pair(world, body, amount=1)))


SCENARIOS: dict[str, Callable[[World], Outcome]] = {
    "happy_path": happy_path,
    "mandate_forged": mandate_forged,
    "mandate_expired": mandate_expired,
    "nonce_replay_in_a_new_session": nonce_replay_in_a_new_session,
    "checkout_hash_reuse": checkout_hash_reuse,
    "order_raised_while_approved": order_raised_while_approved,
    "order_items_changed_while_approved": order_items_changed_while_approved,
    "acp_complete_without_mandate_by_a_locked_principal": (
        acp_complete_without_mandate_by_a_locked_principal
    ),
    "budget_split_across_sessions": budget_split_across_sessions,
    "duplicate_json_keys": duplicate_json_keys,
    "amount_mismatch": amount_mismatch,
}
_ = paypal_sim

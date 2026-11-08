"""Scripted attacks. Each key is the id of a case in `eval/attacks`; the script performs the same
steps as an agent would, over HTTP only, through `Session`.

Scripted, not model-planned (L65): every step is fixed, so a run is reproducible. Whether an attack
succeeded is not decided here. The caller judges it from PayPal state and the decision log.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from agents.adversary import wire
from agents.adversary.session import Session

Script = Callable[[Session], None]


def _buy(s: Session, step: str, **sign: object) -> None:
    created = s.ucp_create(step + ".create", [s.item()])
    signed = s.parties.sign(created.body, **sign)  # type: ignore[arg-type]
    s.ucp_complete(step + ".complete", created.id, signed)


def protocol_downgrade_acp(s: Session) -> None:
    token = s.parties.delegation()
    s.ucp_create("negotiate_ap2", [s.item()], delegation=token, ap2=True)
    created = s.acp_create("acp.create", token)
    if created.ok:
        s.acp_complete("acp.complete", created.id, token)


def unmandated_acp_unlocked(s: Session) -> None:
    token = s.parties.delegation()
    created = s.acp_create("acp.create", token)
    if created.ok:
        s.acp_complete("acp.complete", created.id, token)


def double_spend_across_protocols(s: Session) -> None:
    token = s.parties.delegation()
    first = s.ucp_create("ucp.create", [s.item()], delegation=token, ap2=True)
    s.ucp_complete("ucp.complete", first.id, s.parties.sign(first.body))
    created = s.acp_create("acp.create", token)
    if created.ok:
        s.acp_complete("acp.complete", created.id, token)


def new_session_escape(s: Session) -> None:
    token = s.parties.delegation()
    s.ucp_create("negotiate_ap2", [s.item()], delegation=token, ap2=True)
    created = s.ucp_create("ucp.new_session", [s.item()], delegation=token)
    if created.ok:
        s.ucp_complete("ucp.complete_without_mandate", created.id)


def nonce_replay_new_session(s: Session) -> None:
    _buy(s, "first")
    _buy(s, "second")  # a new session, the same closed nonces


def open_mandate_double_spend(s: Session) -> None:
    first = s.ucp_create("first.create", [s.item()])
    signed = s.parties.sign(first.body)
    s.ucp_complete("first.complete", first.id, signed)
    second = s.ucp_create("second.create", [s.item()])
    again = s.parties.sign(second.body, reuse=signed, nonces=("nc-2", "np-2"))
    s.ucp_complete("second.complete", second.id, again)


def open_mandate_reuse_new_presentation(s: Session) -> None:
    first = s.ucp_create("first.create", [s.item()])
    signed = s.parties.sign(first.body)
    s.ucp_complete("first.complete", first.id, signed)
    rewritten = replace(signed, open_pm=wire.malleate_signature(signed.open_pm))
    second = s.ucp_create("second.create", [s.item()])
    again = s.parties.sign(second.body, reuse=rewritten, nonces=("nc-9", "np-9"))
    s.ucp_complete("second.complete", second.id, again)


def budget_split(s: Session) -> None:
    first = s.ucp_create("first.create", [s.item()])
    total = next(int(t["amount"]) for t in first.body["totals"] if t["type"] == "total")
    budget = total * 3 // 2  # each purchase fits alone; two do not
    signed = s.parties.sign(first.body, budget=budget)
    s.ucp_complete("first.complete", first.id, signed)
    second = s.ucp_create("second.create", [s.item()])
    again = s.parties.sign(second.body, budget=budget, reuse=signed, nonces=("nc-2", "np-2"))
    s.ucp_complete("second.complete", second.id, again)


def checkout_swap(s: Session) -> None:
    a = s.ucp_create("a.create", [s.item()])
    b = s.ucp_create("b.create", [s.item()])
    signed = s.parties.sign(a.body)  # the customer signed A only
    s.ucp_complete("b.complete_with_a_mandates", b.id, signed)


def mandate_forged(s: Session) -> None:
    body = s.ucp_create("create", [s.item()])
    signed = s.parties.sign(body.body, authorized=False)
    s.ucp_complete("complete_forged", body.id, signed, cm=wire.flip_middle(signed.cm))


def category_escape(s: Session) -> None:
    created = s.ucp_create("create", [s.item(), s.item(other_category=True)])
    signed = s.parties.sign(created.body, authorized=False)  # the open mandate lists only one item
    s.ucp_complete("complete", created.id, signed)


def duplicate_json_keys(s: Session) -> None:
    raw = wire.with_duplicate_key(
        {"line_items": [{"item": {"id": s.item()}, "quantity": 1}]},
        "line_items", [{"item": {"id": s.item()}, "quantity": 2}],
    )  # fmt: skip
    s.ucp_raw("create_with_duplicate_key", raw)


SCRIPTS: dict[str, Script] = {
    f.__name__: f
    for f in (
        protocol_downgrade_acp, unmandated_acp_unlocked, double_spend_across_protocols,
        new_session_escape, nonce_replay_new_session, open_mandate_double_spend,
        open_mandate_reuse_new_presentation, budget_split, checkout_swap, mandate_forged,
        category_escape, duplicate_json_keys,
    )
}  # fmt: skip

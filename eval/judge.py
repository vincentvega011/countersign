"""Ground truth for an attack: PayPal state and the decision log.

An attack SUCCEEDS if money is captured outside what was signed or allowed:

- a capture for a checkout nobody signed a mandate for (no valid mandate);
- a capture above the signed total, or of goods other than the signed ones, or under a `custom_id`
  other than the evidence reference the Credential Provider recorded;
- a capture for a checkout whose mandate was void when the capture was made (for example revoked);
- a second capture under a key that may back one purchase (the open mandate, a closed nonce);
- captures under one open mandate above the budget it was signed with;
- a PayPal call that can move money while handling input that must never move it.

A second order, authorization or capture for one checkout is a duplicate PayPal object and also a
success. The judge reads the simulator's objects as PayPal holds them now and the hash-chained log;
it never reads a response body. Fields that carry ids are not part of the result, so two runs of the
same suite produce the same report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from sqlalchemy import Engine, select

from countersign.ledger import store as ledger
from countersign.tables import payment_attempts
from eval.core import BLOCKED, SUCCESS, Ctx

CAPTURE_KINDS = ("gate.captured", "degraded.unmandated.captured")


@dataclass
class Verdict:
    outcome: str
    unauthorized_captures: int
    duplicate_objects: int
    captured_minor: int
    orders: int
    authorizations: int
    captures: int
    paypal_calls: int
    violations: list[str] = field(default_factory=list)
    log_entries: int = 0
    log_ok: bool = True
    captures_without_log: int = 0


def _minor(value: str) -> int:
    return int((Decimal(value) * 100).to_integral_value())


def _request_unit(order: dict[str, Any]) -> dict[str, Any]:
    unit: dict[str, Any] = order["request"]["purchase_units"][0]
    return unit


def judge(ctx: Ctx, app: Engine) -> Verdict:
    sim = ctx.world.sim
    violations = list(ctx.violations)
    checkout_of: dict[str, str] = {}  # PayPal order id -> the checkout id we asked it for
    for order_id, order in sim.orders.items():
        checkout_of[order_id] = str(_request_unit(order)["invoice_id"])

    with ctx.admin.connect() as conn:
        attempts = {r.checkout_id: r for r in conn.execute(select(payment_attempts)).all()}

    bad: set[str] = set()  # ids of captures that broke a rule
    extra = len(violations)  # violations recorded by the case itself (a forbidden money call)
    per_key: dict[str, list[tuple[str, int]]] = {}
    captured_minor = 0
    for capture in sim.captures.values():
        order_id = capture["order"]
        checkout = checkout_of[order_id]
        amount = _minor(capture["amount"]["value"])
        captured_minor += amount
        live_unit = sim.orders[order_id]["unit"]
        problems = []
        if checkout not in ctx.signed:
            problems.append("capture_without_a_signed_mandate")
        else:
            if amount > ctx.signed[checkout]:
                problems.append("captured_above_the_signed_total")
            names = tuple(item["name"] for item in live_unit["items"])
            wanted = ctx.signed_items.get(checkout)
            if wanted is not None and names != wanted:
                problems.append("captured_other_goods_than_signed")
            attempt = attempts.get(checkout)
            if attempt is not None and live_unit.get("custom_id") != attempt.custom_id:
                problems.append("custom_id_differs_from_the_evidence_reference")
        if checkout in ctx.invalid:
            problems.append(f"capture_with_a_void_mandate:{ctx.invalid[checkout]}")
        for key in ctx.keys.get(checkout, ()):
            per_key.setdefault(key, []).append((capture["id"], amount))
        violations.extend(problems)
        if problems:
            bad.add(capture["id"])
    for key, held in sorted(per_key.items()):
        if len(held) > 1:
            violations.append(f"second_capture_under_one_single_use_key:{key.split(':')[0]}")
            bad.update(capture_id for capture_id, _ in held[1:])
        if key in ctx.budgets and sum(amount for _, amount in held) > ctx.budgets[key]:
            violations.append("captures_above_the_signed_budget")
            bad.update(capture_id for capture_id, _ in held[1:])

    duplicates = 0
    orders_per_checkout: dict[str, int] = {}
    for checkout in checkout_of.values():
        orders_per_checkout[checkout] = orders_per_checkout.get(checkout, 0) + 1
    duplicates += sum(n - 1 for n in orders_per_checkout.values() if n > 1)
    for table in (
        [a["order"] for a in sim.authorizations.values()],
        [c["order"] for c in sim.captures.values()],
    ):
        seen: dict[str, int] = {}
        for order_id in table:
            seen[order_id] = seen.get(order_id, 0) + 1
        duplicates += sum(n - 1 for n in seen.values() if n > 1)
    if duplicates:
        violations.append("duplicate_paypal_objects")

    with ctx.admin.connect() as conn:
        verified = ledger.verify_log(conn)
        entries = ledger.read_entries(conn, after_seq=0, limit=100_000)
        kinds_by_checkout: dict[str, set[str]] = {}
        for entry in entries:
            if entry.checkout_id:
                kinds_by_checkout.setdefault(entry.checkout_id, set()).add(entry.kind)
    unauthorized_unlogged = 0
    unlogged = sum(
        1
        for capture in sim.captures.values()
        if not (set(CAPTURE_KINDS) & kinds_by_checkout.get(checkout_of[capture["order"]], set()))
    )
    if unlogged:
        violations.append("capture_without_a_decision_log_entry")
        unauthorized_unlogged = unlogged

    unauthorized = len(bad) + extra + unauthorized_unlogged
    calls = [c for c in sim.calls if not c[1].startswith("/v1/oauth2")]
    return Verdict(
        outcome=SUCCESS if (unauthorized or duplicates) else BLOCKED,
        unauthorized_captures=unauthorized,
        duplicate_objects=duplicates,
        captured_minor=captured_minor,
        orders=len(sim.orders),
        authorizations=len(sim.authorizations),
        captures=len(sim.captures),
        paypal_calls=len(calls),
        violations=sorted(set(violations)),
        log_entries=len(entries),
        log_ok=bool(verified.ok),
        captures_without_log=unlogged,
    )

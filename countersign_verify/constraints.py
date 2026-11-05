"""The open mandates' constraints, evaluated against what was bought (Decision 110).

Written for the verifier alone, from AP2's constraint text and docs/PROTOCOL.md Decisions 31 and 32, so a
dispute check does not take the service's word that a purchase was within what the customer allowed:

- the open Checkout Mandate may hold `checkout.line_items` (required) and `checkout.allowed_merchants`;
  the open Payment Mandate `payment.reference` (required), `payment.amount_range`,
  `payment.allowed_payees`, `payment.budget` and `payment.agent_recurrence`. Any other type, a member
  that is not understood, or two constraints of one type fail: an unknown constraint might restrict more.
- `checkout.line_items` uses the maximal flow reading: every requirement filled with its exact quantity,
  every unit of the checkout used, nothing twice.
- `checkout.allowed_merchants` is matched on the merchant `id` against the payee of the closed Payment
  Mandate (the signed checkout does not name its merchant; the payee is who was paid).
- the consent's `terms` must rebuild into exactly the `mandate` the device signed, so the terms the page
  showed and the mandates cannot differ.

`web/ui/evidence/constraints.js` is the browser port: same checks, same order, same codes.
"""

from __future__ import annotations

from typing import Any

from countersign_verify.crypto import Invalid, is_int, loads, unb64

CHECKOUT_TYPES = {"checkout.line_items", "checkout.allowed_merchants"}
PAYMENT_TYPES = {
    "payment.reference", "payment.amount_range", "payment.allowed_payees", "payment.budget",
    "payment.agent_recurrence",
}  # fmt: skip
MAX_QUANTITY = 1_000_000
MAX_LINES = 100  # requirements and checkout lines each; keeps the flow small


def by_type(constraints: Any, allowed: set[str], required: str) -> dict[str, dict[str, Any]]:
    """The constraints of a mandate by type: known types only, each at most once, `required` present."""
    if not isinstance(constraints, list):
        raise Invalid("constraint_unresolved", "the constraints are not a list")
    found: dict[str, dict[str, Any]] = {}
    for c in constraints:
        kind = c.get("type") if isinstance(c, dict) else None
        if not isinstance(kind, str) or kind not in allowed:
            raise Invalid(
                "constraint_unresolved", "a constraint of a type the verifier does not know"
            )
        if kind in found:
            raise Invalid("constraint_duplicate", "two constraints of one type")
        found[kind] = c
    if required not in found:
        raise Invalid("constraint_unresolved", f"the required {required} constraint is missing")
    return found


def committed_checkout(checkout_jwt: str) -> dict[str, Any]:
    """The checkout a closed mandate commits to (bound by `checkout_hash`); its merchant signature is
    step 2's to check, so step 1 does not depend on it."""
    parts = checkout_jwt.split(".")
    if len(parts) != 3:
        raise Invalid("jws_shape", "a JWS is not three segments")
    checkout = loads(unb64(parts[1]))
    if not isinstance(checkout, dict):
        raise Invalid("checkout_not_object", "the checkout is not an object")
    return checkout


def _quantity(value: Any) -> bool:
    return is_int(value) and 0 < value <= MAX_QUANTITY


def _max_flow(demands: list[int], supplies: list[int], edges: set[tuple[int, int]]) -> int:
    """Edmonds-Karp from requirements (capacity `demands[i]`) to checkout items (`supplies[j]`).

    Nodes: 0 source, 1..n requirements, n+1..n+m items, n+m+1 sink. Requirement-to-item edges carry
    any amount. Breadth-first search visits neighbours in increasing node order."""
    n, m = len(demands), len(supplies)
    sink = n + m + 1
    cap = [[0] * (sink + 1) for _ in range(sink + 1)]
    for i, d in enumerate(demands):
        cap[0][1 + i] = d
    for j, s in enumerate(supplies):
        cap[1 + n + j][sink] = s
    for i, j in edges:
        cap[1 + i][1 + n + j] = sum(demands) + 1
    total = 0
    while True:
        parent = [-1] * (sink + 1)
        parent[0] = 0
        queue = [0]
        while queue and parent[sink] < 0:
            u = queue.pop(0)
            for v in range(sink + 1):
                if cap[u][v] > 0 and parent[v] < 0:
                    parent[v] = u
                    queue.append(v)
        if parent[sink] < 0:
            return total
        amount, v = cap[parent[sink]][sink], sink
        while v != 0:
            amount = min(amount, cap[parent[v]][v])
            v = parent[v]
        v = sink
        while v != 0:
            cap[parent[v]][v] -= amount
            cap[v][parent[v]] += amount
            v = parent[v]
        total += amount


def line_items(constraint: dict[str, Any], checkout: dict[str, Any]) -> None:
    code = "constraint_line_items"
    if not set(constraint) <= {"type", "items"}:
        raise Invalid("constraint_unresolved", "checkout.line_items has a member not understood")
    items = constraint.get("items")
    if not isinstance(items, list) or not 0 < len(items) <= MAX_LINES:
        raise Invalid(code, "checkout.line_items names no requirement, or too many")
    demands: list[int] = []
    acceptable: list[set[str]] = []
    ids: set[str] = set()
    for requirement in items:
        if not isinstance(requirement, dict):
            raise Invalid(code, "a line item requirement is not an object")
        if not set(requirement) <= {"id", "acceptable_items", "quantity"}:
            raise Invalid(
                "constraint_unresolved", "a line item requirement has a member not understood"
            )
        rid, quantity, options = (
            requirement.get("id"), requirement.get("quantity"), requirement.get("acceptable_items"),
        )  # fmt: skip
        if not isinstance(rid, str) or rid in ids:
            raise Invalid(code, "a line item requirement has no unique id")
        ids.add(rid)
        if not _quantity(quantity) or not isinstance(options, list):
            raise Invalid(code, "a line item requirement has no valid quantity or items")
        allowed: set[str] = set()
        for option in options:
            if not isinstance(option, dict) or not isinstance(option.get("id"), str):
                raise Invalid(code, "an acceptable item has no id")
            if not set(option) <= {"id", "title"}:
                raise Invalid(
                    "constraint_unresolved", "an acceptable item has a member not understood"
                )
            allowed.add(option["id"])
        demands.append(quantity)
        acceptable.append(allowed)
    lines = checkout.get("line_items")
    if not isinstance(lines, list) or len(lines) > MAX_LINES:
        raise Invalid("checkout_line", "the checkout has no line items, or too many")
    wanted: dict[str, int] = {}
    for line in lines:
        item = line.get("item") if isinstance(line, dict) else None
        quantity = line.get("quantity") if isinstance(line, dict) else None
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or not _quantity(quantity)
        ):
            raise Invalid("checkout_line", "a checkout line has no item id and quantity")
        wanted[item["id"]] = wanted.get(item["id"], 0) + quantity
    names = sorted(wanted)
    supplies = [wanted[name] for name in names]
    edges = {
        (r, c) for r, opts in enumerate(acceptable) for c, name in enumerate(names) if name in opts
    }
    flow = _max_flow(demands, supplies, edges)
    if flow != sum(demands) or flow != sum(supplies):
        raise Invalid(
            code, "the checkout lines are not the items and quantities the customer allowed"
        )


def allowed_merchants(constraint: dict[str, Any], payee: Any) -> None:
    if not set(constraint) <= {"type", "allowed"}:
        raise Invalid(
            "constraint_unresolved", "checkout.allowed_merchants has a member not understood"
        )
    allowed = constraint.get("allowed")
    if not isinstance(allowed, list) or not allowed:
        raise Invalid("constraint_merchant", "checkout.allowed_merchants names no merchant")
    ids = []
    for entry in allowed:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise Invalid("constraint_merchant", "an allowed merchant has no id")
        ids.append(entry["id"])
    if not isinstance(payee, dict) or payee.get("id") not in ids:
        raise Invalid("constraint_merchant", "the merchant paid is not one the customer allowed")


def amount_range(constraint: dict[str, Any], amount: int, currency: str) -> None:
    if not set(constraint) <= {"type", "currency", "min", "max"}:
        raise Invalid("constraint_unresolved", "payment.amount_range has a member not understood")
    low, high = constraint.get("min", 0), constraint.get("max")
    if not is_int(low) or not is_int(high) or not 0 <= low <= high:
        raise Invalid("constraint_amount_range", "payment.amount_range has no valid bounds")
    if constraint.get("currency") != currency or not 0 < amount or not low <= amount <= high:
        raise Invalid(
            "constraint_amount_range", "the amount is outside the range the customer allowed"
        )


def recurrence(constraint: dict[str, Any]) -> None:
    if not set(constraint) <= {"type", "frequency", "max_occurrences"}:
        raise Invalid(
            "constraint_unresolved", "payment.agent_recurrence has a member not understood"
        )
    if not is_int(constraint.get("max_occurrences")) or constraint["max_occurrences"] != 1:
        raise Invalid(
            "constraint_unresolved", "payment.agent_recurrence allows more than one payment"
        )


def rebuild_mandate(terms: dict[str, Any]) -> dict[str, Any]:
    """The open mandate contents the platform must issue for `terms` (the service's `build_mandate`)."""
    merchant = terms["merchant"]
    lines = [
        {
            "id": f"line_{n}",
            "acceptable_items": [{"id": item["id"], "title": item["title"]}],
            "quantity": item["quantity"],
        }
        for n, item in enumerate(terms["items"], start=1)
    ]
    return {
        "checkout": {
            "vct": "mandate.checkout.open.1",
            "exp": terms["mandate_expires_at"],
            "constraints": [
                {"type": "checkout.line_items", "items": lines},
                {"type": "checkout.allowed_merchants", "allowed": [merchant]},
            ],
        },
        "payment": {
            "vct": "mandate.payment.open.1",
            "exp": terms["mandate_expires_at"],
            "constraints": [
                {
                    "type": "payment.amount_range", "currency": terms["currency"], "min": 1,
                    "max": terms["ceiling_minor"],
                },
                {"type": "payment.allowed_payees", "allowed": [merchant]},
                {"type": "payment.budget", "max": terms["ceiling_minor"], "currency": terms["currency"]},
                {"type": "payment.agent_recurrence", "frequency": "ON_DEMAND", "max_occurrences": 1},
            ],
        },
    }  # fmt: skip

"""Native constraints of the open Checkout Mandate: `checkout.line_items`, `checkout.allowed_merchants`.

What is checked against what. The OPEN mandate holds the constraints, that is what the customer
allowed. The CLOSED values they bind are the checkout the closed mandate commits to (its
`checkout_hash` and embedded `checkout_jwt`), which the Merchant role has already matched to the
current session (steps M3 to M5); here that checkout is the `Checkout` argument, and the merchant
is the merchant identity the evaluator was built with.

Security reasoning:

- `checkout.line_items` follows the spec's flow formulation exactly: every requirement must be
  filled with the exact quantity, every unit in the checkout must be used, nothing twice. So
  an extra item, a missing item, a wrong quantity, or one unit counted for two requirements all
  fail. If the agent withheld the disclosure that would permit an item, the requirement has no
  edge to it and fails; withholding can only remove permissions.
- `checkout.allowed_merchants` is matched on the merchant `id`, never on the display name or the
  website, which are not identifiers. If no element was revealed the constraint is invalid, as the
  spec says.
- A constraint with a member this engine does not understand is `unresolved_constraint`.
"""

from __future__ import annotations

from typing import Any

from countersign.canonical.models import Checkout
from countersign.constraints.flow import max_flow
from countersign.constraints.model import (
    SATISFIED,
    UNRESOLVED,
    ConstraintResult,
    is_int,
    is_text,
    only_keys,
    violated,
)

LINE_ITEMS = "checkout.line_items"
ALLOWED_MERCHANTS = "checkout.allowed_merchants"
_REQUIREMENT_KEYS = {"id", "acceptable_items", "quantity"}


def evaluate_line_items(constraint: dict[str, Any], checkout: Checkout) -> ConstraintResult:
    if not only_keys(constraint, {"type", "items"}):
        return UNRESOLVED
    items = constraint.get("items")
    if not isinstance(items, list) or not items:
        return violated(LINE_ITEMS, "items_malformed")
    demands: list[int] = []
    acceptable: list[set[str]] = []
    seen_ids: set[str] = set()
    for requirement in items:
        if not isinstance(requirement, dict):
            return violated(LINE_ITEMS, "requirement_malformed")
        if not only_keys(requirement, _REQUIREMENT_KEYS):
            return UNRESOLVED
        rid, quantity, options = (
            requirement.get("id"),
            requirement.get("quantity"),
            requirement.get("acceptable_items"),
        )
        if not is_text(rid) or rid in seen_ids:
            return violated(LINE_ITEMS, "requirement_id_invalid")
        seen_ids.add(str(rid))
        if not is_int(quantity) or int(quantity) <= 0:
            return violated(LINE_ITEMS, "quantity_invalid")
        if not isinstance(options, list):
            return violated(LINE_ITEMS, "acceptable_items_malformed")
        ids: set[str] = set()
        for option in options:
            if not isinstance(option, dict) or not is_text(option.get("id")):
                return violated(LINE_ITEMS, "acceptable_item_malformed")
            if not only_keys(option, {"id", "title"}):
                return UNRESOLVED
            ids.add(str(option["id"]))
        demands.append(int(quantity))
        acceptable.append(ids)
    wanted: dict[str, int] = {}
    for line in checkout.line_items:
        wanted[line.item.id] = wanted.get(line.item.id, 0) + line.quantity
    checkout_ids = sorted(wanted)
    supplies = [wanted[i] for i in checkout_ids]
    edges = {
        (r, c)
        for r, ids in enumerate(acceptable)
        for c, item in enumerate(checkout_ids)
        if item in ids
    }
    flow = max_flow(demands, supplies, edges)
    if flow != sum(demands) or flow != sum(supplies):
        return violated(LINE_ITEMS, "not_matched")
    return SATISFIED


def evaluate_allowed_merchants(constraint: dict[str, Any], merchant_id: str) -> ConstraintResult:
    if not only_keys(constraint, {"type", "allowed"}):
        return UNRESOLVED
    allowed = constraint.get("allowed")
    if not isinstance(allowed, list):
        return violated(ALLOWED_MERCHANTS, "allowed_malformed")
    if not allowed:
        return violated(ALLOWED_MERCHANTS, "none_revealed")
    found = False
    for entry in allowed:
        if (
            not isinstance(entry, dict)
            or not is_text(entry.get("id"))
            or not is_text(entry.get("name"))
        ):
            return violated(ALLOWED_MERCHANTS, "merchant_malformed")
        if not only_keys(entry, {"id", "name", "website"}):
            return UNRESOLVED
        found = found or entry["id"] == merchant_id
    return SATISFIED if found else violated(ALLOWED_MERCHANTS, "merchant_not_allowed")

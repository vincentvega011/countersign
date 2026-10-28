"""Merchant policy: category limits, outside every mandate (docs/PROTOCOL.md Decision 3).

Mandates carry no categories (AP2 has no category constraint and Decision 4 adds none). A merchant
may still refuse certain categories for agent purchases. That is a rule of the merchant, not of the
customer's authority, so it lives here, separate from mandate evaluation, and is evaluated by its
own function against the catalog's categories, never against anything the agent states.

Fail closed: a line item whose category is unknown is refused when a category policy exists, and
an empty allowed set refuses everything. No policy (None) means no category restriction. The other
policy rules of the architecture (unmandated cap, velocity) are not part of this module yet.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from countersign.canonical.models import Checkout


@dataclass(frozen=True)
class CategoryPolicy:
    allowed: frozenset[str]


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    reason: str


def check_category_policy(
    checkout: Checkout,
    policy: CategoryPolicy | None,
    category_of: Callable[[str], str | None],
) -> PolicyResult:
    if policy is None:
        return PolicyResult(True, "no_category_policy")
    for line in checkout.line_items:
        category = category_of(line.item.id)
        if category is None:
            return PolicyResult(False, "category_unknown")
        if category not in policy.allowed:
            return PolicyResult(False, "category_not_allowed")
    return PolicyResult(True, "categories_allowed")

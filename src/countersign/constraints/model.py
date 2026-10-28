"""Shared pieces of the constraint engine: the result type and strict value helpers.

Only AP2's native constraint types are evaluated (docs/PROTOCOL.md Decision 4). Every function in
this package is a pure function of the verified mandate content, the checkout or payment values and
an explicit state view (INV-1): no network, no model output, time only as an argument. Money is an
integer count of minor units (INV-9); a float, a boolean or a string where an integer is required
is a malformed constraint, never coerced.

Failure vocabulary (the `reason` of a result is always a fixed string, never request text):

- a violated constraint: `<type>:<problem>`, for example `payment.amount_range:above_max`;
- a malformed constraint or mandate (wrong type, missing field, negative amount): the same form,
  for example `payment.budget:max_not_integer`;
- `unresolved_constraint` (with `unresolved=True`): a constraint type this engine does not
  evaluate, or one it only evaluates in a restricted form (docs/PROTOCOL.md Decision 2). AP2 says
  an unknown constraint MUST fail evaluation; it is never skipped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeGuard

from countersign.canonical import JsonValue


@dataclass(frozen=True)
class ConstraintResult:
    satisfied: bool
    reason: str
    unresolved: bool = False


SATISFIED = ConstraintResult(True, "satisfied")
UNRESOLVED = ConstraintResult(False, "unresolved_constraint", unresolved=True)


def violated(constraint: str, problem: str) -> ConstraintResult:
    return ConstraintResult(False, f"{constraint}:{problem}")


def is_int(value: object) -> TypeGuard[int]:
    """A JSON integer. `True`, `1.0` and `"1"` are not integers here."""
    return isinstance(value, int) and not isinstance(value, bool)


def json_equal(a: JsonValue, b: JsonValue) -> bool:
    """Equality that keeps JSON types apart: 1, 1.0 and true are three different values."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b, strict=True))
    return bool(a == b)


def only_keys(constraint: dict[str, Any], allowed: set[str]) -> bool:
    """True if the constraint has no member this engine does not understand.

    A member that is not understood might restrict the mandate further, so it is never ignored.
    """
    return set(constraint) <= allowed


def is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)

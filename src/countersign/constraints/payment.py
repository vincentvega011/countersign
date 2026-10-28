"""Native constraints of the open Payment Mandate (docs/PROTOCOL.md 1.2.6, Decisions 2 and 4).

What is checked against what. The OPEN Payment Mandate holds the constraints, that is what the
customer allowed. The CLOSED Payment Mandate holds the values they bind: `payee`,
`payment_amount` (integer minor units and currency), `payment_instrument`, `pisp` and
`execution_date`. The Checkout Mandate chain supplies the open Checkout Mandate digests for
`payment.reference`. The spend view supplies `payment.budget`.

Security reasoning, per constraint:

- `payment.amount_range`: currency must be equal, and `min <= amount <= max` on integers. `max` and
  `min` that are floats, booleans or negative make the mandate invalid; a payment amount of zero
  or less is invalid (INV-9: integers only).
- `payment.allowed_payees`, `payment.allowed_payment_instruments`, `payment.allowed_pisps`:
  membership on identifiers (payee `id`; instrument `id` and `type`; the three PISP names). If
  nothing was revealed the constraint cannot be satisfied.
- `payment.reference`: the digest must equal the digest of an open Checkout Mandate in the
  Checkout Mandate chain presented with it, so this payment cannot be paired with another checkout.
- `payment.budget`: `max` is an integer count of minor units of the constraint currency; a value
  that is not a JSON integer makes the mandate invalid (Decision 2). The rule is
  `captured + in_flight + this amount <= max`, with the view excluding this presentation.
  Without a spend view the constraint fails (fail closed).
- `payment.agent_recurrence`: accepted only with `max_occurrences` exactly 1. Absent, larger,
  smaller or non-integer values are `unresolved_constraint`, because repeat use is not implemented.
- `payment.execution_date`: ISO 8601 `not_before` and `not_after`, inclusive. A date without a time
  is a UTC day (`not_after` covers the whole day); a time without an offset is ambiguous and
  rejected. When the closed mandate has no `execution_date`, the injected clock is the execution
  time. Countersign only executes immediately, so an `execution_date` later than now plus the
  skew is refused whether or not a constraint mentions it (`execution_date:in_future`).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from countersign.constraints.budget import SpendView
from countersign.constraints.model import (
    SATISFIED,
    UNRESOLVED,
    ConstraintResult,
    is_int,
    is_text,
    only_keys,
    violated,
)
from countersign.mandates import CLOCK_SKEW_SECONDS

AMOUNT_RANGE = "payment.amount_range"
ALLOWED_PAYEES = "payment.allowed_payees"
ALLOWED_INSTRUMENTS = "payment.allowed_payment_instruments"
ALLOWED_PISPS = "payment.allowed_pisps"
REFERENCE = "payment.reference"
EXECUTION_DATE = "payment.execution_date"
BUDGET = "payment.budget"
RECURRENCE = "payment.agent_recurrence"

FREQUENCIES = frozenset(
    {"ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"}
)
_CURRENCY = re.compile(r"[A-Z]{3}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_DATETIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})")


@dataclass(frozen=True)
class PaymentFacts:
    """The closed values, validated, plus what the constraints are evaluated against."""

    payee: dict[str, Any]
    amount_minor: int
    currency: str
    instrument: dict[str, Any] | None
    pisp: dict[str, Any] | None
    executes_at: datetime
    spend: SpendView | None
    open_checkout_digests: frozenset[str]


def parse_instant(value: object, *, end_of_day: bool = False) -> datetime | None:
    """Strict ISO 8601: `YYYY-MM-DD` (a UTC day) or a full timestamp with `Z` or an offset."""
    if not isinstance(value, str):
        return None
    try:
        if _DATE.fullmatch(value):
            day = date.fromisoformat(value)
            start = datetime(day.year, day.month, day.day, tzinfo=UTC)
            return start + timedelta(days=1) - timedelta(microseconds=1) if end_of_day else start
        if _DATETIME.fullmatch(value):
            return datetime.fromisoformat(value).astimezone(UTC)
    except ValueError:
        return None
    return None


def closed_facts(
    content: dict[str, Any],
    *,
    now: datetime,
    spend: SpendView | None,
    open_checkout_digests: frozenset[str],
) -> PaymentFacts | ConstraintResult:
    """Validate the closed Payment Mandate values, or return the failure."""
    payee = content.get("payee")
    if (
        not isinstance(payee, dict)
        or not is_text(payee.get("id"))
        or not is_text(payee.get("name"))
    ):
        return violated("payment_mandate", "payee_invalid")
    amount = content.get("payment_amount")
    if (
        not isinstance(amount, dict)
        or set(amount) != {"amount", "currency"}
        or not is_int(amount["amount"])
        or amount["amount"] <= 0
        or not isinstance(amount["currency"], str)
        or not _CURRENCY.fullmatch(amount["currency"])
    ):
        return violated("payment_mandate", "payment_amount_invalid")
    instrument = content.get("payment_instrument")
    if instrument is not None and (
        not isinstance(instrument, dict)
        or not is_text(instrument.get("id"))
        or not is_text(instrument.get("type"))
    ):
        return violated("payment_mandate", "payment_instrument_invalid")
    pisp = content.get("pisp")
    if pisp is not None and (
        not isinstance(pisp, dict)
        or not all(is_text(pisp.get(k)) for k in ("legal_name", "brand_name", "domain_name"))
    ):
        return violated("payment_mandate", "pisp_invalid")
    executes_at = now
    if "execution_date" in content:
        parsed = parse_instant(content["execution_date"])
        if parsed is None:
            return violated(EXECUTION_DATE, "execution_date_invalid")
        if parsed > now + timedelta(seconds=CLOCK_SKEW_SECONDS):
            return violated(EXECUTION_DATE, "in_future")
        executes_at = parsed
    return PaymentFacts(
        payee,
        amount["amount"],
        amount["currency"],
        instrument,
        pisp,
        executes_at,
        spend,
        open_checkout_digests,
    )


def _allowed_list(constraint: dict[str, Any], name: str) -> list[Any] | ConstraintResult:
    if not only_keys(constraint, {"type", "allowed"}):
        return UNRESOLVED
    allowed = constraint.get("allowed")
    if not isinstance(allowed, list):
        return violated(name, "allowed_malformed")
    if not allowed:
        return violated(name, "none_revealed")
    return allowed


def amount_range(constraint: dict[str, Any], facts: PaymentFacts) -> ConstraintResult:
    if not only_keys(constraint, {"type", "currency", "max", "min"}):
        return UNRESOLVED
    maximum, currency = constraint.get("max"), constraint.get("currency")
    if not is_int(maximum) or maximum < 0:
        return violated(AMOUNT_RANGE, "max_invalid")
    minimum: int | None = None
    if "min" in constraint:
        raw = constraint["min"]
        if not is_int(raw) or raw < 0 or raw > maximum:
            return violated(AMOUNT_RANGE, "min_invalid")
        minimum = raw
    if not isinstance(currency, str) or not _CURRENCY.fullmatch(currency):
        return violated(AMOUNT_RANGE, "currency_invalid")
    if currency != facts.currency:
        return violated(AMOUNT_RANGE, "currency_mismatch")
    if facts.amount_minor > maximum:
        return violated(AMOUNT_RANGE, "above_max")
    if minimum is not None and facts.amount_minor < minimum:
        return violated(AMOUNT_RANGE, "below_min")
    return SATISFIED


def allowed_payees(constraint: dict[str, Any], facts: PaymentFacts) -> ConstraintResult:
    allowed = _allowed_list(constraint, ALLOWED_PAYEES)
    if isinstance(allowed, ConstraintResult):
        return allowed
    found = False
    for entry in allowed:
        if (
            not isinstance(entry, dict)
            or not is_text(entry.get("id"))
            or not is_text(entry.get("name"))
        ):
            return violated(ALLOWED_PAYEES, "payee_malformed")
        if not only_keys(entry, {"id", "name", "website"}):
            return UNRESOLVED
        found = found or entry["id"] == facts.payee["id"]
    return SATISFIED if found else violated(ALLOWED_PAYEES, "payee_not_allowed")


def allowed_instruments(constraint: dict[str, Any], facts: PaymentFacts) -> ConstraintResult:
    allowed = _allowed_list(constraint, ALLOWED_INSTRUMENTS)
    if isinstance(allowed, ConstraintResult):
        return allowed
    found = False
    for entry in allowed:
        if (
            not isinstance(entry, dict)
            or not is_text(entry.get("id"))
            or not is_text(entry.get("type"))
        ):
            return violated(ALLOWED_INSTRUMENTS, "instrument_malformed")
        if not only_keys(entry, {"id", "type", "description"}):
            return UNRESOLVED
        if facts.instrument is not None:
            found = found or (
                entry["id"] == facts.instrument["id"] and entry["type"] == facts.instrument["type"]
            )
    return SATISFIED if found else violated(ALLOWED_INSTRUMENTS, "instrument_not_allowed")


def allowed_pisps(constraint: dict[str, Any], facts: PaymentFacts) -> ConstraintResult:
    allowed = _allowed_list(constraint, ALLOWED_PISPS)
    if isinstance(allowed, ConstraintResult):
        return allowed
    names = ("legal_name", "brand_name", "domain_name")
    found = False
    for entry in allowed:
        if not isinstance(entry, dict) or not all(is_text(entry.get(k)) for k in names):
            return violated(ALLOWED_PISPS, "pisp_malformed")
        if not only_keys(entry, set(names)):
            return UNRESOLVED
        if facts.pisp is not None:
            found = found or all(entry[k] == facts.pisp[k] for k in names)
    return SATISFIED if found else violated(ALLOWED_PISPS, "pisp_not_allowed")


def reference(constraint: dict[str, Any], facts: PaymentFacts) -> ConstraintResult:
    if not only_keys(constraint, {"type", "conditional_transaction_id"}):
        return UNRESOLVED
    digest = constraint.get("conditional_transaction_id")
    if not is_text(digest):
        return violated(REFERENCE, "reference_malformed")
    if digest not in facts.open_checkout_digests:
        return violated(REFERENCE, "checkout_mandate_not_referenced")
    return SATISFIED


def budget(constraint: dict[str, Any], facts: PaymentFacts) -> ConstraintResult:
    if not only_keys(constraint, {"type", "max", "currency"}):
        return UNRESOLVED
    maximum, currency = constraint.get("max"), constraint.get("currency")
    if not is_int(maximum):
        return violated(BUDGET, "max_not_integer")
    if maximum < 0:
        return violated(BUDGET, "max_negative")
    if not isinstance(currency, str) or not _CURRENCY.fullmatch(currency):
        return violated(BUDGET, "currency_invalid")
    if currency != facts.currency:
        return violated(BUDGET, "currency_mismatch")
    spend = facts.spend
    if spend is None:
        return violated(BUDGET, "spend_view_unavailable")
    if spend.currency != currency:
        return violated(BUDGET, "spend_view_currency_mismatch")
    if spend.used_minor + facts.amount_minor > maximum:
        return violated(BUDGET, "over_budget")
    return SATISFIED


def agent_recurrence(constraint: dict[str, Any], facts: PaymentFacts) -> ConstraintResult:
    if not only_keys(constraint, {"type", "frequency", "max_occurrences"}):
        return UNRESOLVED
    if constraint.get("frequency") not in FREQUENCIES:
        return violated(RECURRENCE, "frequency_invalid")
    occurrences = constraint.get("max_occurrences")
    if not is_int(occurrences) or occurrences != 1:
        return UNRESOLVED
    return SATISFIED


def execution_date(constraint: dict[str, Any], facts: PaymentFacts) -> ConstraintResult:
    if not only_keys(constraint, {"type", "not_before", "not_after"}):
        return UNRESOLVED
    if "not_before" in constraint:
        earliest = parse_instant(constraint["not_before"])
        if earliest is None:
            return violated(EXECUTION_DATE, "not_before_invalid")
        if facts.executes_at < earliest:
            return violated(EXECUTION_DATE, "before_window")
    if "not_after" in constraint:
        latest = parse_instant(constraint["not_after"], end_of_day=True)
        if latest is None:
            return violated(EXECUTION_DATE, "not_after_invalid")
        if facts.executes_at > latest:
            return violated(EXECUTION_DATE, "after_window")
    return SATISFIED


PAYMENT_HANDLERS: dict[str, Callable[[dict[str, Any], PaymentFacts], ConstraintResult]] = {
    AMOUNT_RANGE: amount_range,
    ALLOWED_PAYEES: allowed_payees,
    ALLOWED_INSTRUMENTS: allowed_instruments,
    ALLOWED_PISPS: allowed_pisps,
    REFERENCE: reference,
    BUDGET: budget,
    RECURRENCE: agent_recurrence,
    EXECUTION_DATE: execution_date,
}

"""Parsing of ACP request bodies against the vendored schemas.

Security reasoning. A request is untrusted input that must never become part of what Countersign
prices, signs or stores. Every body goes through the strict JSON loader first (INV-8): duplicate keys,
NaN, Infinity, excess decimal precision, bad UTF-8 and oversized input are refused with an `Error`
before anything else reads it. The vendored request schemas set `additionalProperties: false`, so an
unknown top-level member is refused (`invalid_field`) and nothing else is guessed (INV-10).

Only the members that carry the agent's intent are read: `line_items` (item `id` and, as the vendored
examples show, `quantity`), `currency` and `capabilities` on create. Prices and names come from the
catalog. A `unit_amount` the agent sends is compared with the catalog and refused if it differs, never
used. Money is an integer of minor units (INV-9); a float or a bool is refused.

The vendored `Item` schema has no `quantity` member although its own description and examples use it.
Countersign accepts an integer `quantity` (default 1, at most `MAX_QUANTITY`) and refuses fractional
quantities, because it sells whole items only. This is recorded in docs/PROTOCOL.md Decision 52.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

from countersign.canonical.jsonstrict import DEFAULT_MAX_BYTES, StrictJsonError, loads_strict
from countersign.protocols.acp.errors import AcpError

JsonLoader = Callable[[bytes], Any]
MAX_TEXT = 127
MAX_LINES = 20
MAX_QUANTITY = 99
SUPPORTED_VERSION = "2026-04-17"

CREATE_FIELDS = frozenset(
    {
        "buyer", "line_items", "currency", "fulfillment_details", "capabilities",
        "fulfillment_groups", "affiliate_attribution", "coupons", "discounts", "locale",
        "timezone", "quote_id", "metadata",
    }
)  # fmt: skip
UPDATE_FIELDS = frozenset(
    {
        "buyer", "line_items", "fulfillment_details", "fulfillment_groups",
        "selected_fulfillment_options", "coupons", "discounts",
    }
)  # fmt: skip
COMPLETE_FIELDS = frozenset(
    {
        "buyer", "payment_data", "authentication_result", "affiliate_attribution", "risk_signals",
        "marketing_consents",
    }
)  # fmt: skip
CANCEL_FIELDS = frozenset({"intent_trace"})
ITEM_FIELDS = frozenset({"id", "name", "unit_amount", "quantity"})


@dataclass(frozen=True)
class CartLine:
    item_id: str
    quantity: int
    unit_amount: int | None  # what the agent believes the price is; compared, never used


@dataclass(frozen=True)
class CreateRequest:
    lines: tuple[CartLine, ...]
    currency: str


@dataclass(frozen=True)
class UpdateRequest:
    lines: tuple[CartLine, ...] | None


@dataclass(frozen=True)
class CompleteRequest:
    has_payment_data: bool


def _bad(param: str, why: str, code: str = "invalid_field") -> AcpError:
    return AcpError(400, code, why, param=param)


async def read_body(stream: AsyncIterator[bytes], *, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Read a body, stopping as soon as it exceeds `max_bytes`."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in stream:
        size += len(chunk)
        if size > max_bytes:
            raise AcpError(400, "json_too_large", "The request body is too large.")
        chunks.append(chunk)
    return b"".join(chunks)


def parse_json_object(
    raw: bytes, *, allow_empty: bool = False, loader: JsonLoader = loads_strict
) -> dict[str, Any]:
    if not raw.strip():
        if allow_empty:
            return {}
        raise AcpError(400, "invalid_json", "The request body is empty.")
    try:
        value = loader(raw)
    except StrictJsonError as exc:
        # The loader's stable code (duplicate key, NaN, precision, size, syntax); no text from the body.
        raise AcpError(400, exc.code, "The request body is not acceptable JSON.") from None
    if not isinstance(value, dict):
        raise _bad("$", "The body must be a JSON object.", "invalid_json")
    return value


def check_members(body: dict[str, Any], allowed: frozenset[str]) -> None:
    for key in body:
        if key not in allowed:
            raise _bad(f"$.{key}"[:80], "This member is not part of the request schema.")


def _line(raw: Any, index: int) -> CartLine:
    path = f"$.line_items[{index}]"
    if not isinstance(raw, dict):
        raise _bad(path, "A line item must be an object.")
    check_members_at(raw, ITEM_FIELDS, path)
    item_id = raw.get("id")
    if not isinstance(item_id, str) or not 1 <= len(item_id) <= MAX_TEXT:
        raise _bad(f"{path}.id", "The item id must be a string of 1 to 127 characters.")
    quantity = raw.get("quantity", 1)
    if type(quantity) is not int:
        raise _bad(f"{path}.quantity", "The quantity must be a whole number.")
    if not 1 <= quantity <= MAX_QUANTITY:
        raise AcpError(
            400, "quantity_limit", "The quantity is outside the allowed range.",
            param=f"{path}.quantity",
        )  # fmt: skip
    unit = raw.get("unit_amount")
    if unit is not None and (type(unit) is not int or unit < 0):
        raise _bad(f"{path}.unit_amount", "The unit amount must be integer minor units.")
    name = raw.get("name")
    if name is not None and not isinstance(name, str):
        raise _bad(f"{path}.name", "The name must be a string.")
    return CartLine(item_id, quantity, unit)


def check_members_at(body: dict[str, Any], allowed: frozenset[str], path: str) -> None:
    for key in body:
        if key not in allowed:
            raise _bad(f"{path}.{key}"[:80], "This member is not part of the request schema.")


def _lines(raw: Any) -> tuple[CartLine, ...]:
    if not isinstance(raw, list):
        raise _bad("$.line_items", "line_items must be an array.")
    if len(raw) > MAX_LINES:
        raise AcpError(
            400, "line_limit", "Too many line items.", param="$.line_items"
        )  # at most MAX_LINES
    return tuple(_line(x, i) for i, x in enumerate(raw))


def _no_discounts(body: dict[str, Any]) -> None:
    """Coupons and discounts are not supported; silently ignoring them would mislead the agent."""
    if body.get("coupons"):
        raise _bad("$.coupons", "Coupons are not supported.", "unsupported_field")
    discounts = body.get("discounts")
    if isinstance(discounts, dict) and discounts.get("codes"):
        raise _bad("$.discounts", "Discount codes are not supported.", "unsupported_field")


def parse_create(body: dict[str, Any]) -> CreateRequest:
    check_members(body, CREATE_FIELDS)
    for required in ("line_items", "currency", "capabilities"):
        if required not in body:
            raise _bad(f"$.{required}", "A required member is missing.", "missing_field")
    if not isinstance(body["capabilities"], dict):
        raise _bad("$.capabilities", "capabilities must be an object.")
    currency = body["currency"]
    if not isinstance(currency, str) or len(currency) != 3:
        raise _bad("$.currency", "currency must be a three letter ISO 4217 code.")
    lines = _lines(body["line_items"])
    if not lines:
        raise _bad("$.line_items", "At least one line item is required.", "missing_field")
    _no_discounts(body)
    return CreateRequest(lines, currency.upper())


def parse_update(body: dict[str, Any]) -> UpdateRequest:
    check_members(body, UPDATE_FIELDS)
    _no_discounts(body)
    if "line_items" not in body:
        return UpdateRequest(None)
    lines = _lines(body["line_items"])
    if not lines:
        raise _bad("$.line_items", "At least one line item is required.", "missing_field")
    return UpdateRequest(lines)


def parse_complete(body: dict[str, Any]) -> CompleteRequest:
    check_members(body, COMPLETE_FIELDS)
    if "payment_data" not in body:
        raise _bad("$.payment_data", "A required member is missing.", "missing_field")
    if not isinstance(body["payment_data"], dict):
        raise _bad("$.payment_data", "payment_data must be an object.")
    return CompleteRequest(True)


def parse_cancel(body: dict[str, Any]) -> None:
    check_members(body, CANCEL_FIELDS)

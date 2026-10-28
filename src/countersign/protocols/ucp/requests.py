"""Parsing of UCP checkout request bodies.

Security reasoning. A request is untrusted input that must never become part of what Countersign
signs. This module therefore reads only the members that carry the platform's intent, and nothing
else:

- For create and update that is `line_items`: for each, `item.id` and `quantity`, plus on update
  the line `id` and an optional `item.quantity_unit` assertion. Everything else in the body is
  discarded without being read. In particular `item.price`, `item.title`, `totals`, `currency`,
  `status` and `id` are members the checkout schema marks `ucp_request: omit` for these
  operations; the business is authoritative for them, so a value sent for them has no effect
  (`ignored_members` reports the ones that differ so the platform is told, docs/PROTOCOL.md
  Decision 17).
- Prices and titles come from the catalog in the service layer, never from here.
- Bodies pass through the strict JSON loader first: duplicate keys, NaN, Infinity, excess decimal
  precision, bad UTF-8 and oversized input are refused with a UCP-shaped protocol error.

Shape errors (a member of the wrong type, an empty list) are protocol errors (HTTP 400). Business
rules (unknown item, quantity limit) are decided in the service and returned as business outcomes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any

from countersign.canonical.jsonstrict import DEFAULT_MAX_BYTES, StrictJsonError, loads_strict
from countersign.protocols.ucp.messages import (
    INVALID_REQUEST,
    ProtocolError,
)
from countersign.protocols.ucp.profile import PAYMENT_CREDENTIAL_TYPE, PAYMENT_HANDLER_ID

MAX_TEXT = 127
MAX_SAFE_INT = 9_007_199_254_740_991  # the schema maximum for `quantity`


@dataclass(frozen=True)
class LineRequest:
    item_id: str
    quantity: int
    line_id: str | None  # only meaningful on update
    unit: tuple[str, int] | None  # asserted (unit, effective scale), if the platform sent one


@dataclass(frozen=True)
class CheckoutRequest:
    lines: tuple[LineRequest, ...]


def _bad(path: str, why: str) -> ProtocolError:
    return ProtocolError(400, INVALID_REQUEST, f"{path}: {why}")


async def read_body(stream: AsyncIterator[bytes], *, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Read a request body, stopping as soon as it exceeds `max_bytes`."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in stream:
        size += len(chunk)
        if size > max_bytes:
            raise ProtocolError(400, "json_too_large", f"the body exceeds {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def parse_json_object(raw: bytes, *, allow_empty: bool = False) -> dict[str, Any]:
    """Strictly parse a body that must be a JSON object. An empty body is `{}` only if allowed."""
    if not raw.strip():
        if allow_empty:
            return {}
        raise ProtocolError(400, "json_syntax", "the request body is empty")
    try:
        value = loads_strict(raw)
    except StrictJsonError as exc:
        raise ProtocolError(400, exc.code, str(exc)) from None
    if not isinstance(value, dict):
        raise _bad("$", "the body must be a JSON object")
    return value


def check_content_type(value: str | None) -> None:
    """The REST binding sends and accepts `application/json` only."""
    media = (value or "").split(";", 1)[0].strip().lower()
    if media != "application/json":
        raise ProtocolError(400, INVALID_REQUEST, "Content-Type must be application/json")


def _line(raw: Any, index: int, *, update: bool) -> LineRequest:
    path = f"$.line_items[{index}]"
    if not isinstance(raw, dict):
        raise _bad(path, "a line item must be an object")
    item = raw.get("item")
    if not isinstance(item, dict):
        raise _bad(f"{path}.item", "item must be an object")
    item_id = item.get("id")
    if not isinstance(item_id, str) or not 1 <= len(item_id) <= MAX_TEXT:
        raise _bad(f"{path}.item.id", f"item id must be a string of 1 to {MAX_TEXT} characters")
    quantity = raw.get("quantity")
    if type(quantity) is not int or not 1 <= quantity <= MAX_SAFE_INT:
        raise _bad(f"{path}.quantity", "quantity must be an integer of at least 1")

    line_id: str | None = None
    if update and "id" in raw:
        line_id = raw["id"]
        if not isinstance(line_id, str) or not 1 <= len(line_id) <= MAX_TEXT:
            raise _bad(f"{path}.id", f"line id must be a string of 1 to {MAX_TEXT} characters")

    unit: tuple[str, int] | None = None
    if "quantity_unit" in item:
        qu = item["quantity_unit"]
        if not isinstance(qu, dict) or not isinstance(qu.get("unit"), str):
            raise _bad(f"{path}.item.quantity_unit", "quantity_unit must be an object with a unit")
        scale = qu.get("scale", 0)
        if type(scale) is not int or scale < 0:
            raise _bad(f"{path}.item.quantity_unit.scale", "scale must be a non-negative integer")
        unit = (qu["unit"], scale)
    return LineRequest(item_id=item_id, quantity=quantity, line_id=line_id, unit=unit)


def parse_checkout_request(body: Mapping[str, Any], *, update: bool) -> CheckoutRequest:
    """Extract the intent from a create or update body (see the module docstring)."""
    lines = body.get("line_items")
    if not isinstance(lines, list):
        raise _bad("$.line_items", "line_items is required and must be an array")
    if not lines:
        raise _bad("$.line_items", "line_items must contain at least one line item")
    return CheckoutRequest(lines=tuple(_line(x, i, update=update) for i, x in enumerate(lines)))


# Members the vendored schemas mark `ucp_request: omit` for create and update.
_OMIT_TOP = ("ucp", "id", "status", "currency", "totals", "links", "expires_at", "order")


def ignored_members(body: Mapping[str, Any], response: Mapping[str, Any]) -> list[tuple[str, str]]:
    """JSONPaths of `omit` members the platform sent whose value differs from the response.

    A platform that echoes the whole checkout on update (the spec's full-replacement rule) sends
    these with the business's own values, which is not worth a warning. A value that differs is
    ignored and reported as `(path, member)`.
    """
    out: list[tuple[str, str]] = []
    for member in _OMIT_TOP:
        if member in body and body[member] != response.get(member):
            out.append((f"$.{member}", member))
    sent = body.get("line_items")
    got = response.get("line_items")
    if isinstance(sent, list) and isinstance(got, list):
        for i, line in enumerate(sent):
            if not isinstance(line, dict) or i >= len(got):
                continue
            if "totals" in line and line["totals"] != got[i]["totals"]:
                out.append((f"$.line_items[{i}].totals", "totals"))
            item = line.get("item")
            if isinstance(item, dict):
                for member in ("title", "price"):
                    if member in item and item[member] != got[i]["item"][member]:
                        out.append((f"$.line_items[{i}].item.{member}", member))
    return out


@dataclass(frozen=True)
class CompleteRequest:
    """The two credentials a complete request may carry. Either may be absent."""

    checkout_mandate: str | None
    payment_token: str | None


def parse_complete_request(body: Mapping[str, Any]) -> CompleteRequest:
    """Read `ap2.checkout_mandate` and the Payment Mandate token; ignore everything else.

    The token is `credential.token` of the instrument whose `handler_id` is Countersign's handler
    and whose credential `type` is `ap2_payment_mandate` (docs/PROTOCOL.md Decisions 8 and 39).
    Instruments of other handlers are ignored. More than one instrument of ours, or a value of the
    wrong type, is a protocol error: the request is ambiguous and nothing is guessed.
    """
    ap2 = body.get("ap2")
    mandate: str | None = None
    if ap2 is not None:
        if not isinstance(ap2, dict):
            raise _bad("$.ap2", "ap2 must be an object")
        value = ap2.get("checkout_mandate")
        if value is not None and not isinstance(value, str):
            raise _bad("$.ap2.checkout_mandate", "the checkout mandate must be a string")
        mandate = value
    token: str | None = None
    payment = body.get("payment")
    if payment is not None:
        if not isinstance(payment, dict):
            raise _bad("$.payment", "payment must be an object")
        instruments = payment.get("instruments", [])
        if not isinstance(instruments, list):
            raise _bad("$.payment.instruments", "instruments must be an array")
        found: list[str | None] = []
        for index, instrument in enumerate(instruments):
            if (
                not isinstance(instrument, dict)
                or instrument.get("handler_id") != PAYMENT_HANDLER_ID
            ):
                continue
            credential = instrument.get("credential")
            where = f"$.payment.instruments[{index}].credential"
            if not isinstance(credential, dict):
                raise _bad(where, "credential must be an object")
            if credential.get("type") != PAYMENT_CREDENTIAL_TYPE:
                raise _bad(f"{where}.type", f"type must be {PAYMENT_CREDENTIAL_TYPE}")
            candidate = credential.get("token")
            if not isinstance(candidate, str):
                raise _bad(f"{where}.token", "token must be a string")
            found.append(candidate)
        if len(found) > 1:
            raise _bad("$.payment.instruments", "more than one Countersign payment instrument")
        token = found[0] if found else None
    return CompleteRequest(mandate, token)

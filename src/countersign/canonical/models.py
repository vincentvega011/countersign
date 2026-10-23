"""The canonical checkout model: the subset of a UCP checkout whose terms Countersign signs and compares.

Mirrors the UCP checkout fields in the vendored schemas (`id`, `currency`, `line_items`, `totals`;
line item `id`, `item` {`id`, `title`, `price`}, `quantity`, `totals`; total `type`, `amount`,
`display_text`) and the totals invariants in the checkout specification. Other checkout members
(`status`, `links`, `payment`, ...) are not terms and are ignored by `Checkout.from_ucp`.

Security reasoning. The capture gate (docs/architecture.md section 5.9) re-derives these terms from
the live PayPal order and requires equality with the signed checkout, so this model must be
unambiguous and impossible to build in an inconsistent state:

- Every amount is a `Money` (integer minor units, no floats). Models are frozen, `strict`, and
  forbid extra fields, so an unknown or misspelled member is an error, not silently dropped.
- Items sold by anything other than whole items are rejected. A `quantity_unit` is accepted only
  when it is the `each` identity (`C62`, scale 0); weight, length or time units would need pricing
  arithmetic that Countersign does not do and PayPal cannot carry.
- Internal consistency is validated at construction: line totals equal unit price times quantity,
  every `total` is the sum of its other entries, the order subtotal is the sum of line subtotals,
  the order `items_discount` rolls up the line ones, signs follow the UCP rules, and every amount
  is in the checkout currency.
- `terms()` is what is hashed and compared. It drops what PayPal cannot return and what does not
  change the money (`display_text`, an explicit `each` unit), keeps list order (totals are
  rendered in order), and `terms_hash()` is domain separated (docs/PROTOCOL.md Decision 12).
  `payee`, `invoice_id` and `custom_id`, which the gate also compares, are added by the PayPal
  mapping, not here.
- Title and item id are limited to 127 characters, the longest PayPal returns unchanged for an item
  `name` or `sku`, so the live order can be compared exactly.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, InstanceOf, model_validator

from countersign.canonical.hashing import domain_hash
from countersign.canonical.jcs import canonicalize
from countersign.canonical.money import MAX_MINOR, Money, check_currency

TERMS_DOMAIN = "cs.terms.v1"
MAX_TEXT = 127

TotalType = Literal["subtotal", "items_discount", "discount", "fulfillment", "tax", "fee", "total"]
_SUBTRACTIVE = frozenset({"items_discount", "discount"})  # must be negative
_NON_NEGATIVE = frozenset({"subtotal", "fulfillment", "tax", "fee", "total"})


class UcpShapeError(ValueError):
    """A UCP object has the wrong shape (not an object, array or integer, or a member is missing)."""

    code = "checkout_shape_invalid"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class EachQuantityUnit(_Model):
    """A `quantity_unit` descriptor, accepted only for the `each` identity (`C62`, scale 0).

    `display_text` and `increment` are not part of the unit identity in UCP and are not compared.
    """

    unit: str
    scale: int | None = None
    display_text: str
    increment: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _only_each(self) -> EachQuantityUnit:
        if self.unit != "C62" or self.scale not in (None, 0):
            raise ValueError(
                "non-each quantity_unit is not supported: Countersign prices whole items only"
            )
        return self

    def to_ucp(self) -> dict[str, Any]:
        out: dict[str, Any] = {"unit": self.unit, "display_text": self.display_text}
        if self.scale is not None:
            out["scale"] = self.scale
        if self.increment is not None:
            out["increment"] = self.increment
        return out


class Total(_Model):
    """One entry of a `totals` array."""

    type: TotalType
    amount: InstanceOf[Money]
    display_text: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _sign(self) -> Total:
        minor = self.amount.minor
        if self.type in _SUBTRACTIVE and minor >= 0:
            raise ValueError(f"{self.type} must be negative")
        if self.type in _NON_NEGATIVE and minor < 0:
            raise ValueError(f"{self.type} must not be negative")
        return self

    def to_ucp(self, *, terms: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type, "amount": self.amount.minor}
        if self.display_text is not None and not terms:
            out["display_text"] = self.display_text
        return out


class Item(_Model):
    id: str = Field(min_length=1, max_length=MAX_TEXT)
    title: str = Field(min_length=1, max_length=MAX_TEXT)
    price: InstanceOf[Money]
    quantity_unit: EachQuantityUnit | None = None

    @model_validator(mode="after")
    def _price_not_negative(self) -> Item:
        if self.price.minor < 0:
            raise ValueError("price must not be negative")
        return self

    def to_ucp(self, *, terms: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "title": self.title, "price": self.price.minor}
        if self.quantity_unit is not None and not terms:
            out["quantity_unit"] = self.quantity_unit.to_ucp()
        return out


def _exactly_one(totals: Sequence[Total], kind: str, where: str) -> Total:
    found = [t for t in totals if t.type == kind]
    if len(found) != 1:
        raise ValueError(f"{where} must contain exactly one {kind} entry, found {len(found)}")
    return found[0]


def _check_sum(totals: Sequence[Total], currency: str, where: str) -> Money:
    """The `total` entry must equal the sum of every other entry; returns the subtotal."""
    subtotal = _exactly_one(totals, "subtotal", where)
    total = _exactly_one(totals, "total", where)
    parts = Money.sum((t.amount for t in totals if t.type != "total"), currency)
    if parts != total.amount:
        raise ValueError(f"{where} total does not equal the sum of its entries")
    return subtotal.amount


class LineItem(_Model):
    id: str = Field(min_length=1, max_length=MAX_TEXT)
    item: Item
    quantity: int = Field(ge=1, le=MAX_MINOR)
    totals: tuple[Total, ...]

    @model_validator(mode="after")
    def _consistent(self) -> LineItem:
        currency = self.item.price.currency
        for entry in self.totals:
            if entry.amount.currency != currency:
                raise ValueError("line item totals must use the item's currency")
        subtotal = _check_sum(self.totals, currency, f"line item {self.id!r} totals")
        if subtotal != self.item.price * self.quantity:
            raise ValueError(f"line item {self.id!r} subtotal is not unit price times quantity")
        return self

    def amounts(self, kind: str) -> list[Money]:
        return [t.amount for t in self.totals if t.type == kind]

    def to_ucp(self, *, terms: bool = False) -> dict[str, Any]:
        return {
            "id": self.id,
            "item": self.item.to_ucp(terms=terms),
            "quantity": self.quantity,
            "totals": [t.to_ucp(terms=terms) for t in self.totals],
        }


class Checkout(_Model):
    id: str = Field(min_length=1)
    currency: str
    line_items: tuple[LineItem, ...] = Field(min_length=1)
    totals: tuple[Total, ...]

    @model_validator(mode="after")
    def _consistent(self) -> Checkout:
        check_currency(self.currency)
        for line in self.line_items:
            if line.item.price.currency != self.currency:
                raise ValueError("every line item must use the checkout currency")
        for entry in self.totals:
            if entry.amount.currency != self.currency:
                raise ValueError("every total must use the checkout currency")
        ids = [line.id for line in self.line_items]
        if len(set(ids)) != len(ids):
            raise ValueError("line item ids must be unique")

        subtotal = _check_sum(self.totals, self.currency, "checkout totals")
        line_subtotals = Money.sum(
            (m for line in self.line_items for m in line.amounts("subtotal")), self.currency
        )
        if subtotal != line_subtotals:
            raise ValueError("checkout subtotal is not the sum of the line item subtotals")
        order_rollup = Money.sum(
            (t.amount for t in self.totals if t.type == "items_discount"), self.currency
        )
        line_rollup = Money.sum(
            (m for line in self.line_items for m in line.amounts("items_discount")), self.currency
        )
        if order_rollup != line_rollup:
            raise ValueError("checkout items_discount is not the sum of the line item discounts")
        return self

    # ---- construction ----

    @classmethod
    def from_lines(
        cls,
        checkout_id: str,
        currency: str,
        lines: Sequence[tuple[str, Item, int]],
        adjustments: Sequence[Total] = (),
    ) -> Checkout:
        """Build a consistent checkout: each line is `(line id, item, quantity)`.

        `adjustments` are order-level entries (fulfillment, tax, fee, discount) placed between the
        subtotal and the total, in the given order. The total is computed.
        """
        line_items = []
        for line_id, item, quantity in lines:
            subtotal = item.price * quantity
            line_items.append(
                LineItem(
                    id=line_id,
                    item=item,
                    quantity=quantity,
                    totals=(
                        Total(type="subtotal", amount=subtotal),
                        Total(type="total", amount=subtotal),
                    ),
                )
            )
        entries = [
            Total(
                type="subtotal",
                amount=Money.sum((li.totals[0].amount for li in line_items), currency),
            ),
            *adjustments,
        ]
        total = Money.sum((e.amount for e in entries), currency)
        return cls(
            id=checkout_id,
            currency=currency,
            line_items=tuple(line_items),
            totals=(*entries, Total(type="total", amount=total)),
        )

    @classmethod
    def from_ucp(cls, data: Mapping[str, Any]) -> Checkout:
        """Build from a UCP checkout object (integers of minor units).

        Members outside the supported set are ignored at the top level only; inside line items,
        items and totals an unknown member is an error.
        """
        raw = _mapping(data, "checkout")
        currency = _get(raw, "currency", "checkout")
        if not isinstance(currency, str):
            raise UcpShapeError("checkout currency must be a string")
        lines = _get(raw, "line_items", "checkout")
        totals = _get(raw, "totals", "checkout")
        return cls(
            id=_get(raw, "id", "checkout"),
            currency=currency,
            line_items=tuple(_line_item(x, currency) for x in _array(lines, "line_items")),
            totals=tuple(_total(x, currency) for x in _array(totals, "totals")),
        )

    # ---- output ----

    def to_ucp(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "currency": self.currency,
            "line_items": [li.to_ucp() for li in self.line_items],
            "totals": [t.to_ucp() for t in self.totals],
        }

    def canonical_bytes(self) -> bytes:
        """JCS bytes of every modelled member, including display text."""
        return canonicalize(self.to_ucp())

    def terms(self) -> dict[str, Any]:
        """The members the gate compares: no display text, no explicit `each` unit."""
        return {
            "id": self.id,
            "currency": self.currency,
            "line_items": [li.to_ucp(terms=True) for li in self.line_items],
            "totals": [t.to_ucp(terms=True) for t in self.totals],
        }

    def terms_bytes(self) -> bytes:
        return canonicalize(self.terms())

    def terms_hash(self) -> bytes:
        """Domain-separated SHA-256 over the JCS bytes of the terms."""
        return domain_hash(TERMS_DOMAIN, self.terms_bytes())


# ---- UCP parsing helpers ----


def _mapping(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise UcpShapeError(f"{where} must be an object")
    return value


def _array(value: object, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise UcpShapeError(f"{where} must be an array")
    return value


def _get(raw: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in raw:
        raise UcpShapeError(f"{where} is missing {key!r}")
    return raw[key]


def _total(value: object, currency: str) -> Total:
    raw = dict(_mapping(value, "total"))
    raw["amount"] = Money(currency, _get(raw, "amount", "total"))
    return Total(**raw)


def _item(value: object, currency: str) -> Item:
    raw = dict(_mapping(value, "item"))
    price = _get(raw, "price", "item")
    raw["price"] = Money.from_ucp(price, currency)
    if "quantity_unit" in raw:
        raw["quantity_unit"] = EachQuantityUnit(**_mapping(raw["quantity_unit"], "quantity_unit"))
    return Item(**raw)


def _line_item(value: object, currency: str) -> LineItem:
    raw = dict(_mapping(value, "line item"))
    raw["item"] = _item(_get(raw, "item", "line item"), currency)
    raw["totals"] = tuple(
        _total(x, currency) for x in _array(_get(raw, "totals", "line item"), "totals")
    )
    return LineItem(**raw)

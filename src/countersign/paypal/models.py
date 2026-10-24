"""Typed views of the PayPal objects Countersign reads, and the typed order request it sends.

Responses. Each model ignores members it does not know (PayPal adds fields) and refuses a response
that lacks one it needs, so a changed or partial answer fails closed instead of reading as a default.
Every amount becomes a `Money` through `Money.from_paypal`, so a float, a malformed decimal, a
negative amount or an unsupported currency is a parse failure; no floats exist on these paths. The
fields are those in docs/ENV.md section 2.3. `status` values stay strings: the schema's lists grow,
and callers compare against the one value they need. The authorization status enum has no `EXPIRED`,
so `expiration_time` is required and callers judge expiry from it.

Requests. `OrderRequest` is the only order Countersign creates: intent `AUTHORIZE`, one purchase unit.
It checks the limits (`limits.py`) and that the amounts add up the way PayPal requires (items times
quantity to `item_total`, per-unit tax to `tax_total`, `amount` the sum), so a mismatch is found before
anything is sent rather than as a 422.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from countersign.canonical.money import Money
from countersign.paypal.limits import (
    LimitError,
    check_custom_id,
    check_invoice_id,
    check_item_text,
)

MAX_ITEM_QUANTITY = 9_999_999_999  # PayPal: `^[1-9][0-9]{0,9}$`


def _money(value: Any) -> Money:
    """`{"currency_code": "USD", "value": "74.00"}` to Money; anything else is an error."""
    if isinstance(value, Money):
        return value
    if not isinstance(value, dict):
        raise ValueError("an amount must be an object")  # noqa: TRY004 (pydantic needs ValueError)
    code, text = value.get("currency_code"), value.get("value")
    if not isinstance(code, str) or not isinstance(text, str):
        raise ValueError(  # noqa: TRY004 (pydantic needs ValueError)
            "an amount needs a string currency_code and a string value"
        )
    return Money.from_paypal(text, code)


PayPalMoney = Annotated[Money, BeforeValidator(_money)]


class _View(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, arbitrary_types_allowed=True)


class Link(_View):
    href: str
    rel: str
    method: str | None = None


class Authorization(_View):
    id: str
    status: str
    amount: PayPalMoney
    expiration_time: datetime
    invoice_id: str | None = None
    custom_id: str | None = None
    create_time: datetime | None = None
    links: tuple[Link, ...] = ()


class Capture(_View):
    id: str
    status: str
    amount: PayPalMoney
    final_capture: bool
    invoice_id: str | None = None
    custom_id: str | None = None
    links: tuple[Link, ...] = ()


class ItemView(_View):
    name: str
    quantity: str
    unit_amount: PayPalMoney
    tax: PayPalMoney | None = None
    sku: str | None = None
    category: str | None = None


class Breakdown(_View):
    item_total: PayPalMoney | None = None
    tax_total: PayPalMoney | None = None
    shipping: PayPalMoney | None = None
    handling: PayPalMoney | None = None
    insurance: PayPalMoney | None = None
    shipping_discount: PayPalMoney | None = None
    discount: PayPalMoney | None = None


class Payee(_View):
    merchant_id: str | None = None


class Payments(_View):
    authorizations: tuple[Authorization, ...] = ()
    captures: tuple[Capture, ...] = ()


class PurchaseUnit(_View):
    """`amount` is the total; PayPal nests `breakdown` inside the amount object, so it is lifted here."""

    amount: PayPalMoney
    breakdown: Breakdown | None = None
    reference_id: str | None = None
    invoice_id: str | None = None
    custom_id: str | None = None
    items: tuple[ItemView, ...] = ()
    payee: Payee | None = None
    payments: Payments | None = None

    @model_validator(mode="before")
    @classmethod
    def _lift_breakdown(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("amount"), dict):
            amount = dict(data["amount"])
            if "breakdown" in amount and "breakdown" not in data:
                return {**data, "breakdown": amount.pop("breakdown"), "amount": amount}
        return data


class Order(_View):
    id: str
    status: str
    intent: str
    purchase_units: Annotated[tuple[PurchaseUnit, ...], Field(min_length=1)]
    links: tuple[Link, ...] = ()

    @property
    def authorizations(self) -> tuple[Authorization, ...]:
        return tuple(
            a for u in self.purchase_units if u.payments for a in u.payments.authorizations
        )

    @property
    def captures(self) -> tuple[Capture, ...]:
        return tuple(c for u in self.purchase_units if u.payments for c in u.payments.captures)


# ---- requests ----


@dataclass(frozen=True)
class OrderItem:
    name: str
    quantity: int
    unit_amount: Money
    tax: Money | None = None
    sku: str | None = None
    category: Literal["DIGITAL_GOODS", "PHYSICAL_GOODS", "DONATION"] | None = None

    def __post_init__(self) -> None:
        check_item_text(self.name, "item name")
        if self.sku is not None:
            check_item_text(self.sku, "item sku")
        if type(self.quantity) is not int or not 1 <= self.quantity <= MAX_ITEM_QUANTITY:
            raise LimitError("item quantity must be an integer from 1 to 9999999999")
        for amount in (self.unit_amount, self.tax):
            if amount is not None and amount.minor < 0:
                raise LimitError("item amounts must not be negative")

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "quantity": str(self.quantity),
            "unit_amount": amount_json(self.unit_amount),
        }
        if self.tax is not None:
            out["tax"] = amount_json(self.tax)
        if self.sku is not None:
            out["sku"] = self.sku
        if self.category is not None:
            out["category"] = self.category
        return out


def amount_json(money: Money) -> dict[str, str]:
    return {"currency_code": money.currency, "value": money.to_paypal()}


@dataclass(frozen=True)
class ExperienceContext:
    return_url: str
    cancel_url: str
    user_action: Literal["CONTINUE", "PAY_NOW"] = "PAY_NOW"
    shipping_preference: Literal["GET_FROM_FILE", "NO_SHIPPING", "SET_PROVIDED_ADDRESS"] = (
        "NO_SHIPPING"
    )
    payment_method_preference: Literal["UNRESTRICTED", "IMMEDIATE_PAYMENT_REQUIRED"] = (
        "IMMEDIATE_PAYMENT_REQUIRED"
    )

    def __post_init__(self) -> None:
        for name, url in (("return_url", self.return_url), ("cancel_url", self.cancel_url)):
            parts = urlsplit(url) if isinstance(url, str) else None
            if parts is None or parts.scheme not in ("http", "https") or not parts.netloc:
                raise LimitError(f"{name} must be an http or https URL")
            if len(url) > 2000 or any(ord(c) < 0x20 for c in url):
                raise LimitError(f"{name} is too long or has control characters")


@dataclass(frozen=True)
class OrderRequest:
    """One purchase unit, intent AUTHORIZE. `amount` must equal items plus tax."""

    amount: Money
    invoice_id: str
    custom_id: str
    items: tuple[OrderItem, ...]
    experience_context: ExperienceContext
    reference_id: str = "default"
    description: str | None = None

    def __post_init__(self) -> None:
        check_invoice_id(self.invoice_id)
        check_custom_id(self.custom_id)
        if not 1 <= len(self.reference_id) <= 256 or not self.reference_id.isprintable():
            raise LimitError("reference_id must be 1 to 256 printable characters")
        if self.description is not None and not (
            1 <= len(self.description) <= 127 and self.description.isprintable()
        ):
            raise LimitError("description must be 1 to 127 printable characters")
        if not self.items:
            raise LimitError("an order needs at least one item")
        currency = self.amount.currency
        for item in self.items:
            for money in (item.unit_amount, item.tax):
                if money is not None and money.currency != currency:
                    raise LimitError("every amount must use the order currency")
        if self.amount.minor <= 0:
            raise LimitError("the order amount must be positive")
        if self.item_total + self.tax_total != self.amount:
            raise LimitError("amount is not item_total plus tax_total")

    @property
    def item_total(self) -> Money:
        return Money.sum((i.unit_amount * i.quantity for i in self.items), self.amount.currency)

    @property
    def tax_total(self) -> Money:
        return Money.sum(
            (i.tax * i.quantity for i in self.items if i.tax is not None), self.amount.currency
        )

    def to_json(self) -> dict[str, Any]:
        breakdown: dict[str, Any] = {"item_total": amount_json(self.item_total)}
        if any(i.tax is not None for i in self.items):
            breakdown["tax_total"] = amount_json(self.tax_total)
        unit: dict[str, Any] = {
            "reference_id": self.reference_id,
            "invoice_id": self.invoice_id,
            "custom_id": self.custom_id,
            "amount": {**amount_json(self.amount), "breakdown": breakdown},
            "items": [i.to_json() for i in self.items],
        }
        if self.description is not None:
            unit["description"] = self.description
        ctx = self.experience_context
        return {
            "intent": "AUTHORIZE",
            "purchase_units": [unit],
            "payment_source": {
                "paypal": {
                    "experience_context": {
                        "return_url": ctx.return_url,
                        "cancel_url": ctx.cancel_url,
                        "user_action": ctx.user_action,
                        "shipping_preference": ctx.shipping_preference,
                        "payment_method_preference": ctx.payment_method_preference,
                    }
                }
            },
        }

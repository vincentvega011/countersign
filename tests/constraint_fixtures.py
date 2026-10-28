"""Builders for constraint tests: open and closed mandates with real constraints, verified chains."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from countersign.canonical.models import Checkout, Item
from countersign.canonical.money import Money
from countersign.mandates import (
    VCT_CHECKOUT,
    VCT_CHECKOUT_OPEN,
    VCT_PAYMENT,
    VCT_PAYMENT_OPEN,
    VerifiedChain,
    verify_chain,
)
from tests.mandate_issuer import NOW, Keys, issue
from tests.merchant_support import make_checkout

MERCHANT = {"id": "m-demo", "name": "Demo Store", "website": "https://demo.example"}
INSTRUMENT = {"id": "paypal-wallet-1", "type": "paypal", "description": "Sandbox wallet"}
PISP = {"legal_name": "Demo PISP Ltd", "brand_name": "DemoPay", "domain_name": "pisp.example"}
CHECKOUT_AUD = "merchant"
PAYMENT_AUD = "credential-provider"


def line_items_constraint(
    item_id: str = "sku-headphones", quantity: int = 2, title: str = "Over-ear headphones"
) -> dict[str, Any]:
    return {
        "type": "checkout.line_items",
        "items": [
            {
                "id": "line_1",
                "acceptable_items": [{"id": item_id, "title": title}],
                "quantity": quantity,
            }
        ],
    }


def checkout_constraints() -> list[dict[str, Any]]:
    return [
        line_items_constraint(),
        {"type": "checkout.allowed_merchants", "allowed": [dict(MERCHANT)]},
    ]


def payment_constraints(open_checkout_digest: str, maximum: int = 10_000) -> list[dict[str, Any]]:
    return [
        {"type": "payment.reference", "conditional_transaction_id": open_checkout_digest},
        {"type": "payment.amount_range", "currency": "USD", "max": maximum, "min": 1},
        {"type": "payment.allowed_payees", "allowed": [dict(MERCHANT)]},
        {"type": "payment.allowed_payment_instruments", "allowed": [dict(INSTRUMENT)]},
        {"type": "payment.budget", "max": maximum, "currency": "USD"},
        {"type": "payment.agent_recurrence", "frequency": "ON_DEMAND", "max_occurrences": 1},
    ]


def closed_payment_values(amount: int = 8500, currency: str = "USD") -> dict[str, Any]:
    return {
        "payee": dict(MERCHANT),
        "payment_amount": {"amount": amount, "currency": currency},
        "payment_instrument": dict(INSTRUMENT),
    }


def checkout_for(item_id: str = "sku-headphones", quantity: int = 2, price: int = 4000) -> Checkout:
    item = Item(id=item_id, title="Over-ear headphones", price=Money("USD", price))
    return Checkout.from_lines("chk_abcdefghijklmnopqrstuv", "USD", [("li_1", item, quantity)])


def verified_checkout_chain(
    keys: Keys | None = None,
    *,
    constraints: list[dict[str, Any]] | None = None,
    open_edit: Callable[[dict[str, Any]], None] | None = None,
    closed_edit: Callable[[dict[str, Any]], None] | None = None,
    **issue_kwargs: Any,
) -> tuple[VerifiedChain, Keys]:
    keys = keys or Keys()

    def edit_open(content: dict[str, Any]) -> None:
        content["constraints"] = constraints if constraints is not None else checkout_constraints()
        if open_edit:
            open_edit(content)

    issued = issue(
        "checkout",
        keys=keys,
        edit_open_content=edit_open,
        edit_kb_content=closed_edit,
        **issue_kwargs,
    )
    chain = verify_chain(
        issued.token,
        issuer_key=keys.issuer,
        expected_vcts=[VCT_CHECKOUT_OPEN, VCT_CHECKOUT],
        audience=CHECKOUT_AUD,
        clock=lambda: NOW,
    )
    return chain, keys


def verified_payment_chain(
    keys: Keys,
    checkout_chain: VerifiedChain,
    *,
    constraints: list[dict[str, Any]] | Callable[[str], list[dict[str, Any]]] | None = None,
    values: dict[str, Any] | None = None,
    open_edit: Callable[[dict[str, Any]], None] | None = None,
    **issue_kwargs: Any,
) -> VerifiedChain:
    digest = checkout_chain.links[0].digest

    def edit_open(content: dict[str, Any]) -> None:
        if callable(constraints):
            content["constraints"] = constraints(digest)
        else:
            content["constraints"] = (
                constraints if constraints is not None else payment_constraints(digest)
            )
        if open_edit:
            open_edit(content)

    def edit_closed(content: dict[str, Any]) -> None:
        content.update(closed_payment_values() if values is None else values)

    issued = issue(
        "payment",
        keys=keys,
        audience=PAYMENT_AUD,
        edit_open_content=edit_open,
        edit_kb_content=edit_closed,
        **issue_kwargs,
    )
    return verify_chain(
        issued.token,
        issuer_key=keys.issuer,
        expected_vcts=[VCT_PAYMENT_OPEN, VCT_PAYMENT],
        audience=PAYMENT_AUD,
        clock=lambda: NOW,
    )


def default_checkout() -> Checkout:
    return make_checkout(quantity=2)

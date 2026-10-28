"""Mandates built by our issuers validate against the vendored AP2 JSON schemas; broken ones do not.

The content validated is what the verifier hands to the engine: the delegate payload with its
disclosures resolved. Validating it proves Countersign issues only claims in the vendored schemas
(docs/PROTOCOL.md Decision 4), so a standard verifier accepts them.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from tests.constraint_fixtures import (
    verified_checkout_chain,
    verified_payment_chain,
)

SCHEMAS = Path(__file__).resolve().parents[2] / "spec/vendor/ap2/schemas/ap2"
REGISTRY: Registry = Registry()
for _file in SCHEMAS.rglob("*.json"):
    _doc = json.loads(_file.read_text())
    REGISTRY = REGISTRY.with_resource(_doc["$id"], Resource.from_contents(_doc))

IDS = {
    "open_checkout": "https://ap2-protocol.org/schemas/open_checkout_mandate",
    "checkout": "https://ap2-protocol.org/schemas/checkout_mandate.json",
    "open_payment": "https://ap2-protocol.org/schemas/payment_mandate_open.json",
    "payment": "https://ap2-protocol.org/schemas/payment_mandate.json",
}


def valid(kind: str, content: Any) -> bool:
    return Draft202012Validator({"$ref": IDS[kind]}, registry=REGISTRY).is_valid(
        json.loads(json.dumps(content))
    )


def contents() -> dict[str, dict[str, Any]]:
    checkout_chain, keys = verified_checkout_chain()
    payment_chain = verified_payment_chain(keys, checkout_chain)
    return {
        "open_checkout": dict(checkout_chain.links[0].content),
        "checkout": dict(checkout_chain.final.content),
        "open_payment": dict(payment_chain.links[0].content),
        "payment": dict(payment_chain.final.content),
    }


@pytest.mark.parametrize("kind", list(IDS))
def test_issuer_built_mandates_validate(kind: str) -> None:
    assert valid(kind, contents()[kind]), kind


def test_all_four_vendored_schemas_load() -> None:
    assert set(IDS.values()) <= {
        r
        for r in (
            d["$id"] for d in map(json.loads, (p.read_text() for p in SCHEMAS.rglob("*.json")))
        )
    }


def mutated(kind: str, edit: Any) -> dict[str, Any]:
    content = copy.deepcopy(contents()[kind])
    edit(content)
    return content


@pytest.mark.parametrize(
    ("kind", "edit"),
    [
        ("open_checkout", lambda c: c.update(vct="mandate.checkout.open.2")),
        ("open_checkout", lambda c: c.pop("cnf")),
        ("open_checkout", lambda c: c.pop("constraints")),
        ("open_checkout", lambda c: c.update(constraints=[c["constraints"][1]])),  # no line_items
        ("open_checkout", lambda c: c["constraints"].append({"type": "acme.unknown"})),
        ("open_checkout", lambda c: c["constraints"][0]["items"][0].update(quantity=0)),
        ("open_checkout", lambda c: c["constraints"][0]["items"][0].pop("acceptable_items")),
        ("open_checkout", lambda c: c["constraints"][1]["allowed"][0].pop("id")),
        ("open_checkout", lambda c: c.update(exp="soon")),
        ("checkout", lambda c: c.update(vct="mandate.checkout.open.1")),
        ("checkout", lambda c: c.pop("checkout_hash")),
        ("checkout", lambda c: c.pop("checkout_jwt")),
        ("open_payment", lambda c: c.update(vct="mandate.payment.1")),
        ("open_payment", lambda c: c.pop("cnf")),
        ("open_payment", lambda c: c.update(constraints=c["constraints"][1:])),  # no reference
        ("open_payment", lambda c: c["constraints"].append({"type": "payment.velocity"})),
        (
            "open_payment",
            lambda c: c["constraints"][1].update(max=100.5),
        ),  # amount_range is integer
        ("open_payment", lambda c: c["constraints"][1].pop("currency")),
        ("open_payment", lambda c: c["constraints"][4].update(max="1000")),  # budget max a string
        ("open_payment", lambda c: c["constraints"][5].update(frequency="HOURLY")),
        ("open_payment", lambda c: c["constraints"][2]["allowed"][0].pop("name")),
        ("payment", lambda c: c.update(vct="mandate.payment.open.1")),
        ("payment", lambda c: c.pop("payee")),
        ("payment", lambda c: c.pop("payment_amount")),
        ("payment", lambda c: c["payment_amount"].update(amount=85.5)),
        ("payment", lambda c: c.pop("payment_instrument")),
        ("payment", lambda c: c.pop("transaction_id")),
    ],
)
def test_broken_mandates_do_not_validate(kind: str, edit: Any) -> None:
    assert not valid(kind, mutated(kind, edit))


def test_the_schema_is_looser_than_the_engine_where_the_spec_is_vague() -> None:
    """`payment.budget.max` is a JSON `number` in the schema; Countersign requires an integer
    (Decision 2). The schema accepts the fraction, the evaluator rejects it."""
    assert valid(
        "open_payment", mutated("open_payment", lambda c: c["constraints"][4].update(max=1000.5))
    )

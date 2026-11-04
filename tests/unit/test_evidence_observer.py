"""What the service keeps of PayPal objects: an allowlist, never a payer, a token or a header (Decision 103)."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import httpx

from countersign.evidence.observer import SPECS, sanitize
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig

ROOT = Path(__file__).resolve().parents[2]
DIRTY_ORDER: dict[str, Any] = {
    "id": "ORD1",
    "status": "COMPLETED",
    "intent": "AUTHORIZE",
    "payer": {
        "name": {"given_name": "Pat", "surname": "Buyer"},
        "email_address": "pat@example.test",
        "payer_id": "PAYERID123",
    },
    "payment_source": {"paypal": {"email_address": "pat@example.test", "account_id": "ACC"}},
    "links": [{"href": "https://api.example/v2/orders/ORD1?access_token=SECRET", "rel": "self"}],
    "access_token": "A21AAsecret",
    "purchase_units": [
        {
            "reference_id": "default",
            "invoice_id": "chk_1",
            "custom_id": "cs1.x",
            "amount": {
                "currency_code": "USD",
                "value": "45.00",
                "extra": "x",
                "breakdown": {"item_total": {"currency_code": "USD", "value": "45.00"}},
            },
            "items": [
                {
                    "name": "Thing",
                    "quantity": "1",
                    "sku": "s",
                    "description": "free text",
                    "unit_amount": {"currency_code": "USD", "value": "45.00", "x": 1},
                }
            ],
            "payee": {"merchant_id": "M1", "email_address": "shop@example.test"},
            "shipping": {
                "name": {"full_name": "Pat Buyer"},
                "address": {"address_line_1": "1 Road"},
            },
            "payments": {
                "captures": [
                    {
                        "id": "CAP1",
                        "status": "COMPLETED",
                        "final_capture": True,
                        "amount": {"currency_code": "USD", "value": "45.00"},
                        "seller_receivable_breakdown": {"paypal_fee": {}},
                        "links": [{"href": "x"}],
                    }
                ]
            },
        }
    ],
}


def test_only_allowlisted_members_survive_at_every_depth() -> None:
    clean = sanitize("order", DIRTY_ORDER)
    text = json.dumps(clean)
    for banned in (
        "pat@",
        "Buyer",
        "PAYERID",
        "SECRET",
        "A21AA",
        "shop@",
        "Road",
        "free text",
        "access_token",
        "payer",
        "shipping",
        "links",
        "payment_source",
        "paypal_fee",
    ):
        assert banned not in text, banned
    unit = clean["purchase_units"][0]
    assert unit["payee"] == {"merchant_id": "M1"} and unit["amount"]["value"] == "45.00"
    assert "extra" not in unit["amount"] and "x" not in unit["items"][0]["unit_amount"]
    assert unit["payments"]["captures"][0]["id"] == "CAP1"


def test_a_member_added_by_paypal_later_is_dropped_by_default() -> None:
    body = {"id": "A1", "status": "CREATED", "brand_new_member": {"payer": "x"}}
    assert sanitize("authorization", body) == {"id": "A1", "status": "CREATED"}


def test_the_wrong_types_never_get_through() -> None:
    assert sanitize("capture", {"id": {"nested": 1}, "status": ["x"], "amount": "45.00"}) == {
        "id": None,
        "status": None,
        "amount": {},
    }  # a scalar spec turns a container into None, a money spec turns a scalar into {}


def test_the_client_hands_the_observer_only_a_parsed_body_and_survives_its_failure() -> None:
    seen: list[tuple[str, dict[str, Any]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(
                200, json={"access_token": "TOKEN", "token_type": "Bearer", "expires_in": 3600}
            )
        return httpx.Response(
            200,
            json={
                "id": "ORD1",
                "status": "CREATED",
                "intent": "AUTHORIZE",
                "purchase_units": [{"amount": {"currency_code": "USD", "value": "1.00"}}],
            },
        )

    client = PayPalClient(
        PayPalConfig(client_id="a", client_secret="b"),
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
    )
    client.observe_with(lambda kind, body: seen.append((kind, body)))
    client.get_order("ORD1")
    assert seen and seen[0][0] == "order" and "TOKEN" not in json.dumps(seen)

    def broken(kind: str, body: dict[str, Any]) -> None:
        raise RuntimeError("store down")

    client.observe_with(broken)
    assert client.get_order("ORD1").id == "ORD1"  # a read does not fail because evidence did


def test_the_allowlists_name_no_personal_member() -> None:
    def names(spec: Any) -> set[str]:
        if isinstance(spec, list):
            return names(spec[0])
        if isinstance(spec, dict):
            return set(spec) | {n for v in spec.values() for n in names(v)}
        return set()

    everything = {n for spec in SPECS.values() for n in names(spec)}
    assert not {
        n
        for n in everything
        if any(w in n for w in ("email", "name_", "payer", "address", "phone", "token", "link"))
    } - {"name"}  # item `name` is the product title


def test_the_offline_verifier_imports_nothing_of_the_service() -> None:
    allowed = {"rfc8785", "cryptography", "countersign_verify"}
    stdlib = __import__("sys").stdlib_module_names
    for path in sorted((ROOT / "countersign_verify").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            names = []
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            for name in names:
                top = name.split(".")[0]
                assert top in stdlib or top in allowed, f"{path.name} imports {name}"

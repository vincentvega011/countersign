"""The bundle the service stores at capture, read back through the endpoint (PayPal is the simulator)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text

from tests.evidence_tamper import write_vectors
from tests.integration.test_shopper import run
from tests.mode_support import reset
from tests.shopper_support import ShopperWorld, make_world

ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "tests" / "vectors" / "evidence" / "valid.json"


@pytest.fixture
def world(app_engine: Engine, admin_engine: Engine) -> Iterator[ShopperWorld]:
    reset(admin_engine)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE consent_records, key_revocations, key_challenge_uses, key_challenges, "
                "customer_keys, open_mandate_revocations, open_mandates, agent_proposals, "
                "proposal_uses, purchase_offers, activity_sessions, paypal_observations, "
                "evidence_bundles CASCADE"
            )
        )
    yield make_world(app_engine)


def bought(world: ShopperWorld) -> tuple[Any, dict[str, Any]]:
    result = run(world)
    assert result.outcome == "completed"
    response = world.http.get(f"/evidence/{result.capture_id}")
    assert response.status_code == 200, response.text
    return result, response.json()


def test_a_capture_stores_a_bundle_keyed_by_the_capture_id(world: ShopperWorld) -> None:
    result, bundle = bought(world)
    assert bundle["capture_id"] == result.capture_id and bundle["checkout_id"] == result.checkout_id
    assert set(bundle) == {
        "v", "kind", "capture_id", "checkout_id", "order_id", "authorization_id", "checkout_jwt",
        "mandates", "receipts", "consent", "paypal", "gate", "log", "keys",
    }  # fmt: skip
    assert bundle["consent"]["customer_id"].startswith("cus_")
    for kind in ("order", "authorization", "capture"):
        assert bundle["paypal"][kind]
    kinds = [e["kind"] for e in bundle["log"]["entries"]]
    assert "gate.captured" in kinds and kinds.count("gate.step") >= 9
    assert bundle["log"]["size"] == len(kinds) == len(bundle["log"]["proofs"])


def test_unknown_and_malformed_ids_get_the_same_answer(world: ShopperWorld) -> None:
    """No oracle: an unknown id, a malformed one and a path below the route answer identically."""
    answers = []
    for path in ("/evidence/NOPE", "/evidence/bad id!", "/evidence/" + "A" * 65, "/evidence/a/b",
                 "/evidence/%00", "/evidence/..%2f..%2fpyproject.toml"):  # fmt: skip
        r = world.http.get(path)
        answers.append((r.status_code, r.content, r.headers["cache-control"],
                        r.headers["content-type"]))  # fmt: skip
    assert answers[0] == (404, b'{"code":"evidence_unknown"}', "no-store", "application/json")
    assert all(a == answers[0] for a in answers), answers


EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PERSONAL = re.compile(
    r"(?i)^(payer|payer_id|buyer|email|email_address|name|given_name|surname|full_name|address|"
    r"address_line_\d|admin_area_\d|postal_code|country_code|phone|shipping|birth_date|tax_info)$"
)


def personal_members(node: Any, where: str = "") -> list[str]:
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            # `name` is allowed only as a product title (order items) or the store's own name (the
            # merchant and the allowed payees): never a person.
            business = ".items[" in where or re.search(r"(\.merchant|\.allowed\[\d+\])$", where)
            if PERSONAL.match(key) and not (key == "name" and business):
                found.append(f"{where}.{key}")
            found += personal_members(value, f"{where}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            found += personal_members(value, f"{where}[{i}]")
    elif isinstance(node, str):
        if EMAIL.search(node):
            found.append(f"{where}: email-shaped text")
        if node.startswith("{"):
            try:
                found += personal_members(json.loads(node), f"{where}<json>")
            except ValueError:
                pass
    return found


def test_a_served_bundle_holds_no_email_and_no_payer_or_buyer_details(
    world: ShopperWorld,
) -> None:
    """Decisions 103 and 107: what is served in every mode is sanitized sandbox data."""
    result, bundle = bought(world)
    raw = world.http.get(f"/evidence/{result.capture_id}").text
    assert personal_members(bundle) == []
    assert not EMAIL.search(raw)
    assert personal_members({"payer": {"email_address": "a@b.example"}}) != []  # the scan works


def test_the_service_never_emits_what_the_strict_verifier_refuses(world: ShopperWorld) -> None:
    """Decision 106: the stored text parses under the verifier's rules with no float anywhere."""
    from countersign_verify.crypto import Float, loads

    result, _ = bought(world)
    value = loads(world.http.get(f"/evidence/{result.capture_id}").content)
    stack = [value]
    while stack:
        node = stack.pop()
        assert not isinstance(node, Float)
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str) and node[:1] in "{[":
            try:
                stack.append(loads(node))
            except Exception:  # noqa: BLE001, S112 (not every bracketed text is JSON)
                continue


def test_the_stored_bundle_never_changes(world: ShopperWorld, admin_engine: Engine) -> None:
    result, first = bought(world)
    again = world.http.get(f"/evidence/{result.capture_id}").text
    assert json.loads(again) == first
    with admin_engine.connect() as conn:
        rows = conn.execute(text("SELECT count(*) FROM evidence_bundles")).scalar()
    assert rows == 1


def test_a_fresh_bundle_verifies_offline_and_the_committed_vector_is_current(
    world: ShopperWorld, tmp_path: Path
) -> None:
    """The service's own bundle passes the standalone CLI; `WRITE_EVIDENCE_VECTORS=1` rewrites the vector."""
    _, bundle = bought(world)
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    keys = {}
    for name in ("merchant", "platform"):
        (tmp_path / f"{name}.json").write_text(json.dumps(bundle["keys"][name]))
        keys[name] = str(tmp_path / f"{name}.json")
    done = subprocess.run(
        [sys.executable, "-m", "countersign_verify", str(path), "--merchant-key", keys["merchant"],
         "--platform-key", keys["platform"]],
        capture_output=True, text=True, cwd=ROOT, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.count("PASS") == 12 and "FAIL" not in done.stdout
    if os.environ.get("WRITE_EVIDENCE_VECTORS") == "1":
        VALID.parent.mkdir(parents=True, exist_ok=True)
        VALID.write_text(json.dumps(bundle, indent=1, sort_keys=True) + "\n")
        write_vectors(bundle, VALID.parent)
    committed = json.loads(VALID.read_text())
    assert set(committed) == set(bundle) and set(committed["paypal"]) == set(bundle["paypal"])


def test_nothing_personal_is_stored_from_what_paypal_returned(
    world: ShopperWorld, admin_engine: Engine
) -> None:
    bought(world)
    with admin_engine.connect() as conn:
        bodies = [r[0] for r in conn.execute(text("SELECT body FROM paypal_observations")).all()]
    assert bodies
    joined = " ".join(bodies).lower()
    for word in ("payer", "email", "shipping", "access_token", "links", "given_name"):
        assert word not in joined


@pytest.mark.parametrize("env", ["demo", "prod", ""])
def test_the_endpoint_is_served_in_every_mode(
    app_engine: Engine, admin_engine: Engine, env: str
) -> None:
    from countersign.runtime import Mode, RuntimeSettings

    reset(admin_engine)
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE paypal_observations, evidence_bundles CASCADE"))
    world = make_world(app_engine, RuntimeSettings(Mode.FULL, env))
    assert world.http.get("/evidence/CAP1").json() == {"code": "evidence_unknown"}
    result, bundle = bought(world)
    assert bundle["capture_id"] == result.capture_id

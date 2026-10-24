"""merchant_authorization on real responses, verified in Python and by the independent Node script."""

from __future__ import annotations

import base64
import copy
import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient
from joserfc import jws
from joserfc.jwk import ECKey
from sqlalchemy import Engine

from countersign.api.app import create_app
from countersign.canonical.hashing import b64url, checkout_hash
from countersign.canonical.jcs import canonicalize
from countersign.canonical.models import Checkout
from countersign.catalog.catalog import load_catalog
from countersign.merchant.authorization import (
    INVALID,
    AuthorizationError,
    checkout_jwt,
    verify_authorization,
)
from countersign.merchant.keys import MerchantKey, generate_jwk, validate_jwk
from countersign.protocols.ucp.profile import REST_BASE_PATH
from tests.ucp_schemas import BASE as SCHEMA_BASE
from tests.ucp_schemas import validator

SITE = "https://shop.example.test"
AGENT = {"UCP-Agent": 'profile="https://platform.example/profile"'}
CATALOG = load_catalog()
A, B = CATALOG.items[0], CATALOG.items[1]
ROOT = REST_BASE_PATH + "/checkout-sessions"
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "interop_verify.mjs"
AP2_CHECKOUT = validator(
    SCHEMA_BASE + "common/payment_ap2_mandate.json#/$defs/dev.ucp.shopping.checkout"
)


@pytest.fixture
def key() -> MerchantKey:
    return validate_jwk(generate_jwk())


@pytest.fixture
def client(app_engine: Engine, clean_checkouts: None, key: MerchantKey) -> Iterator[TestClient]:
    app = create_app(key=key, public_base_url=SITE, engine=app_engine)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def keys(client: TestClient) -> list[dict[str, Any]]:
    return client.get("/.well-known/ucp").json()["keys"]  # type: ignore[no-any-return]


def line(item: Any = A, qty: int = 1, **extra: Any) -> dict[str, Any]:
    return {"item": {"id": item.id}, "quantity": qty, **extra}


def create(client: TestClient) -> dict[str, Any]:
    r = client.post(ROOT, json={"line_items": [line(A, 2)]}, headers=AGENT)
    assert r.status_code == 201
    return r.json()  # type: ignore[no-any-return]


def all_response_kinds(client: TestClient) -> dict[str, dict[str, Any]]:
    """One real response of every kind the binding produces for an existing checkout."""
    out: dict[str, dict[str, Any]] = {}
    c = out["create"] = create(client)
    url = f"{ROOT}/{c['id']}"
    out["get"] = client.get(url, headers=AGENT).json()
    out["update"] = client.put(
        url, json={"line_items": [{"id": "li_1", **line(B, 3)}]}, headers=AGENT
    ).json()
    out["update_warned"] = client.put(
        url,
        json={
            "line_items": [{"id": "li_1", "item": {"id": A.id, "price": 1}, "quantity": 1}],
            "id": "x",
        },
        headers=AGENT,
    ).json()
    out["update_rejected"] = client.put(
        url, json={"line_items": [{"item": {"id": "nope"}, "quantity": 1}]}, headers=AGENT
    ).json()
    out["complete"] = client.post(url + "/complete", json={}, headers=AGENT).json()
    out["cancel"] = client.post(url + "/cancel", json={}, headers=AGENT).json()
    out["cancel_again"] = client.post(url + "/cancel", json={}, headers=AGENT).json()
    out["update_canceled"] = client.put(url, json={"line_items": [line()]}, headers=AGENT).json()
    out["complete_canceled"] = client.post(url + "/complete", json={}, headers=AGENT).json()
    return out


def test_every_response_kind_is_signed_and_verifies(
    client: TestClient, keys: list[dict[str, Any]]
) -> None:
    responses = all_response_kinds(client)
    assert len(responses) == 10
    assert any("messages" in r for r in responses.values())
    for name, body in responses.items():
        assert "ap2" in body, name
        verify_authorization(body, keys)


def test_responses_validate_against_the_ap2_extension_schema(client: TestClient) -> None:
    for name, body in all_response_kinds(client).items():
        assert list(AP2_CHECKOUT.iter_errors(body)) == [], name


def test_the_signature_pattern_from_the_schema_holds(client: TestClient) -> None:
    for body in all_response_kinds(client).values():
        assert re.fullmatch(
            r"[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+", body["ap2"]["merchant_authorization"]
        )


def test_responses_with_no_checkout_carry_no_signature(client: TestClient) -> None:
    unknown = client.get(f"{ROOT}/chk_{'A' * 22}", headers=AGENT).json()
    refused = client.post(
        ROOT, json={"line_items": [{"item": {"id": "nope"}, "quantity": 1}]}, headers=AGENT
    ).json()
    assert "ap2" not in unknown and "ap2" not in refused
    assert unknown["ucp"]["status"] == "error"


def test_the_signing_key_is_the_one_in_the_profile(client: TestClient, key: MerchantKey) -> None:
    body = create(client)
    header = body["ap2"]["merchant_authorization"].split("..")[0]
    decoded = json.loads(base64.urlsafe_b64decode(header + "=="))
    assert decoded == {"alg": "ES256", "kid": key.kid}
    assert client.get("/.well-known/ucp").json()["keys"] == [key.public_jwk]


def test_two_gets_of_one_checkout_have_different_signatures_that_both_verify(
    client: TestClient, keys: list[dict[str, Any]]
) -> None:
    c = create(client)
    a = client.get(f"{ROOT}/{c['id']}", headers=AGENT).json()
    b = client.get(f"{ROOT}/{c['id']}", headers=AGENT).json()
    assert a["ap2"] != b["ap2"]
    verify_authorization(a, keys)
    verify_authorization(b, keys)


# ---------------- tampering on real responses ----------------


def test_tampering_with_any_bound_field_of_a_real_response_breaks_it(
    client: TestClient, keys: list[dict[str, Any]]
) -> None:
    body = client.post(ROOT, json={"line_items": [line(A, 2), line(B, 1)]}, headers=AGENT).json()
    edits: list[tuple[str, Any]] = [
        ("id", "chk_ZZZZZZZZZZZZZZZZZZZZZZ"),
        ("status", "completed"),
        ("currency", "EUR"),
        ("expires_at", "2099-01-01T00:00:00Z"),
        ("links", [{"type": "x", "url": "https://evil.test"}]),
    ]
    for member, value in edits:
        bad = copy.deepcopy(body)
        bad[member] = value
        with pytest.raises(AuthorizationError):
            verify_authorization(bad, keys)
    for mutate in (
        lambda b: b["line_items"][0]["item"].__setitem__("price", 1),
        lambda b: b["line_items"][0].__setitem__("quantity", 99),
        lambda b: b["line_items"][1]["item"].__setitem__("id", "other"),
        lambda b: b["line_items"][0]["totals"][0].__setitem__("amount", 1),
        lambda b: b["totals"][-1].__setitem__("amount", 1),
        lambda b: b["totals"].append({"type": "fee", "amount": 0}),
        lambda b: b["ucp"]["capabilities"].clear(),
        lambda b: b.__setitem__("messages", []),
    ):
        bad = copy.deepcopy(body)
        mutate(bad)
        with pytest.raises(AuthorizationError):
            verify_authorization(bad, keys)


def test_a_stale_signature_after_an_update_is_rejected(
    client: TestClient, keys: list[dict[str, Any]]
) -> None:
    before = create(client)
    url = f"{ROOT}/{before['id']}"
    after = client.put(
        url, json={"line_items": [{"id": "li_1", **line(B, 5)}]}, headers=AGENT
    ).json()
    assert after["totals"] != before["totals"]

    stale = copy.deepcopy(after)
    stale["ap2"] = copy.deepcopy(before["ap2"])  # the new terms under the old signature
    with pytest.raises(AuthorizationError) as exc:
        verify_authorization(stale, keys)
    assert exc.value.code == INVALID

    reverse = copy.deepcopy(before)
    reverse["ap2"] = copy.deepcopy(after["ap2"])  # the old terms under the new signature
    with pytest.raises(AuthorizationError):
        verify_authorization(reverse, keys)

    # The old response still verifies as a statement about the old terms; what it must not do is
    # match the current ones, which is the Merchant role's check against session state.
    verify_authorization(before, keys)
    now = client.get(url, headers=AGENT).json()
    assert Checkout.from_ucp(before).terms_hash() != Checkout.from_ucp(now).terms_hash()
    assert Checkout.from_ucp(after).terms_hash() == Checkout.from_ucp(now).terms_hash()


def test_a_signature_in_a_request_has_no_effect(
    client: TestClient, keys: list[dict[str, Any]]
) -> None:
    first = create(client)
    sent = {"line_items": [{"id": "li_1", **line(A, 4)}], "ap2": first["ap2"]}
    body = client.put(f"{ROOT}/{first['id']}", json=sent, headers=AGENT).json()
    assert body["ap2"] != first["ap2"]
    verify_authorization(body, keys)
    assert body["line_items"][0]["quantity"] == 4


def test_a_mandate_field_in_a_create_or_update_request_is_ignored(
    client: TestClient, keys: list[dict[str, Any]]
) -> None:
    r = client.post(
        ROOT,
        json={
            "line_items": [line()],
            "ap2": {"checkout_mandate": "a.b.c~d~", "merchant_authorization": "x..y"},
        },
        headers=AGENT,
    )
    assert r.status_code == 201
    verify_authorization(r.json(), keys)


def test_another_merchants_key_does_not_verify(client: TestClient) -> None:
    body = create(client)
    stranger = validate_jwk(generate_jwk())
    with pytest.raises(AuthorizationError):
        verify_authorization(body, [stranger.public_jwk])
    with pytest.raises(AuthorizationError):
        verify_authorization(body, [{**stranger.public_jwk, "kid": body_kid(body)}])


def body_kid(body: dict[str, Any]) -> str:
    header = body["ap2"]["merchant_authorization"].split("..")[0]
    return json.loads(base64.urlsafe_b64decode(header + "=="))["kid"]  # type: ignore[no-any-return]


# ---------------- checkout_jwt from a response ----------------


def test_the_checkout_jwt_rebuilt_from_a_response_verifies_everywhere(
    client: TestClient, keys: list[dict[str, Any]]
) -> None:
    for body in all_response_kinds(client).values():
        jwt = checkout_jwt(body)
        assert jwt == verify_authorization(body, keys).checkout_jwt
        result = jws.deserialize_compact(jwt, ECKey.import_key(keys[0]), algorithms=["ES256"])
        assert json.loads(result.payload) == {k: v for k, v in body.items() if k != "ap2"}
        assert len(checkout_hash(jwt)) == 43


# ---------------- the independent Node verifier ----------------


def node(
    profile: dict[str, Any], body: Any, tmp_path: Path, name: str = "r"
) -> subprocess.CompletedProcess[str]:
    if shutil.which("node") is None:
        pytest.fail("node is not installed; the interop verifier needs Node 22 (see docs/ENV.md)")
    for package in ("jose", "canonicalize"):
        if not (SCRIPT.parents[1] / "node_modules" / package).is_dir():
            pytest.fail(f"the Node package {package} is not installed; run `make node-deps`")
    (tmp_path / "profile.json").write_text(json.dumps(profile))
    (tmp_path / f"{name}.json").write_text(json.dumps(body))
    return subprocess.run(
        ["node", str(SCRIPT), str(tmp_path / "profile.json"), str(tmp_path / f"{name}.json")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_the_node_verifier_accepts_every_real_response_and_agrees_on_the_hash(
    client: TestClient, tmp_path: Path
) -> None:
    profile = client.get("/.well-known/ucp").json()
    responses = all_response_kinds(client)
    for name, body in responses.items():
        done = node(profile, body, tmp_path, name)
        assert done.returncode == 0, (name, done.stdout, done.stderr)
        assert done.stdout.startswith("OK merchant_authorization verifies")
        assert f"kid={profile['keys'][0]['kid']}" in done.stdout
        assert f"checkout_hash={checkout_hash(checkout_jwt(body))}" in done.stdout


def test_the_node_verifier_rejects_a_tampered_response(client: TestClient, tmp_path: Path) -> None:
    profile = client.get("/.well-known/ucp").json()
    body = create(client)
    body["totals"][-1]["amount"] = 1
    done = node(profile, body, tmp_path)
    assert done.returncode == 1 and done.stdout.startswith("FAIL: the signature does not verify")


def test_the_node_verifier_rejects_a_stale_signature(client: TestClient, tmp_path: Path) -> None:
    profile = client.get("/.well-known/ucp").json()
    before = create(client)
    after = client.put(
        f"{ROOT}/{before['id']}", json={"line_items": [{"id": "li_1", **line(B, 5)}]}, headers=AGENT
    ).json()
    after["ap2"] = before["ap2"]
    assert node(profile, after, tmp_path).returncode == 1


def test_the_node_verifier_rejects_an_unpublished_kid_and_a_missing_signature(
    client: TestClient, tmp_path: Path
) -> None:
    profile = client.get("/.well-known/ucp").json()
    body = create(client)
    other = {**profile, "keys": [{**profile["keys"][0], "kid": "other"}]}
    done = node(other, body, tmp_path)
    assert done.returncode == 1 and "kid does not name exactly one key" in done.stdout
    del body["ap2"]
    done = node(profile, body, tmp_path)
    assert done.returncode == 1 and "no ap2.merchant_authorization" in done.stdout


def test_the_node_verifier_rejects_header_and_key_violations(
    client: TestClient, key: MerchantKey, tmp_path: Path
) -> None:
    profile = client.get("/.well-known/ucp").json()
    body = create(client)

    # An extra header member is refused even when the signature over it is valid for that header.
    def signed_with(header: dict[str, Any]) -> dict[str, Any]:
        out = {k: v for k, v in body.items() if k != "ap2"}
        head = b64url(json.dumps(header, separators=(",", ":")).encode())
        signing_input = head + "." + b64url(canonicalize(out))
        r, s = decode_dss_signature(
            key.private_key.private_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
        )
        sig = b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return {**out, "ap2": {"merchant_authorization": f"{head}..{sig}"}}

    good = signed_with({"alg": "ES256", "kid": key.kid})
    assert node(profile, good, tmp_path).returncode == 0
    for header in (
        {"alg": "ES256", "kid": key.kid, "typ": "JWT"},
        {"alg": "ES384", "kid": key.kid},
        {"alg": "none", "kid": key.kid},
        {"alg": "ES256"},
    ):
        done = node(profile, signed_with(header), tmp_path)
        assert done.returncode == 1, header
    leaky = {**profile, "keys": [{**profile["keys"][0], "d": "x" * 43}]}
    assert node(leaky, good, tmp_path).returncode == 1

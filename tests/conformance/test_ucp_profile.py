"""The served profile validates against the vendored UCP schema and never carries private keys."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from countersign.api.app import create_app
from countersign.merchant.keys import (
    PRIVATE_ONLY_MEMBERS,
    MerchantKey,
    MerchantKeyError,
    generate_jwk,
    validate_jwk,
    write_key_file,
)
from countersign.protocols.ucp.profile import (
    AP2_CAPABILITY,
    CHECKOUT_CAPABILITY,
    UCP_VERSION,
    ProfileError,
    build_profile,
)

SCHEMAS = Path(__file__).resolve().parents[2] / "spec/vendor/ucp/source/schemas"
BASE = "https://shop.example.test"


def _registry() -> Registry:
    reg: Registry = Registry()
    for f in SCHEMAS.rglob("*.json"):
        doc = json.loads(f.read_text())
        reg = reg.with_resource(doc["$id"], Resource.from_contents(doc))
    return reg


def _validator() -> Draft202012Validator:
    reg = _registry()
    schema = {"$ref": "https://ucp.dev/schemas/profile.json#/$defs/business_schema"}
    return Draft202012Validator(schema, registry=reg)


@pytest.fixture(scope="module")
def key() -> MerchantKey:
    return validate_jwk(generate_jwk())


def _walk(node: Any) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            out.append(k)
            out += _walk(v)
    elif isinstance(node, list):
        for v in node:
            out += _walk(v)
    return out


def test_profile_validates_against_vendored_schema(key: MerchantKey) -> None:
    errors = list(_validator().iter_errors(build_profile(public_base_url=BASE, key=key)))
    assert errors == []


def test_validator_is_not_vacuous(key: MerchantKey) -> None:
    v = _validator()
    p = build_profile(public_base_url=BASE, key=key)
    bad = json.loads(json.dumps(p))
    del bad["ucp"]["payment_handlers"]
    assert list(v.iter_errors(bad))
    bad = json.loads(json.dumps(p))
    bad["keys"][0]["d"] = "x"
    assert list(v.iter_errors(bad))
    bad = json.loads(json.dumps(p))
    bad["keys"][0]["alg"] = "ES384"
    assert list(v.iter_errors(bad))
    bad = json.loads(json.dumps(p))
    bad["ucp"]["version"] = "latest"
    assert list(v.iter_errors(bad))


def test_capabilities_and_extension_shape(key: MerchantKey) -> None:
    p = build_profile(public_base_url=BASE, key=key)
    caps = p["ucp"]["capabilities"]
    assert set(caps) == {CHECKOUT_CAPABILITY, AP2_CAPABILITY}
    (ap2,) = caps[AP2_CAPABILITY]
    assert ap2["extends"] == CHECKOUT_CAPABILITY
    assert ap2["config"] == {"vp_formats_supported": {"dc+sd-jwt": {}}}
    assert "vp_formats_supported" not in p  # Decision 6: not a top-level member
    assert p["ucp"]["version"] == UCP_VERSION
    (svc,) = p["ucp"]["services"]["dev.ucp.shopping"]
    assert svc["transport"] == "rest" and svc["endpoint"] == BASE + "/ucp/v1"


def test_private_member_list_matches_vendored_schema() -> None:
    schema = json.loads((SCHEMAS / "profile.json").read_text())
    forbidden = {
        name
        for clause in schema["$defs"]["jwk_public_key"]["not"]["anyOf"]
        for name in clause["required"]
    }
    assert forbidden == set(PRIVATE_ONLY_MEMBERS)


def test_top_level_members_are_exactly_ucp_and_keys(key: MerchantKey) -> None:
    assert set(build_profile(public_base_url=BASE, key=key)) == {"ucp", "keys"}
    assert set(build_profile(public_base_url=BASE, key=key)["ucp"]) == {
        "version",
        "services",
        "capabilities",
        "payment_handlers",
    }


def test_capabilities_equal_the_vendored_spec_example(key: MerchantKey) -> None:
    doc = (SCHEMAS.parents[1] / "docs/specification/payment/extensions/ap2-mandates.md").read_text()
    block = doc.split("**Business Profile Example:**")[1].split("```json")[1].split("```")[0]
    example = json.loads(block.replace("{{ ucp_version }}", "2026-08-25"))
    ours = build_profile(public_base_url=BASE, key=key)
    assert ours["ucp"]["version"] == example["ucp"]["version"] == "2026-08-25"
    assert ours["ucp"]["capabilities"] == example["ucp"]["capabilities"]


def test_builder_fails_if_allowlist_ever_admits_a_private_member(
    key: MerchantKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    from countersign.protocols.ucp import profile

    monkeypatch.setattr(profile, "PUBLIC_MEMBERS", (*profile.PUBLIC_MEMBERS, "d"))
    tainted = MerchantKey(
        kid=key.kid, public_jwk={**key.public_jwk, "d": "v"}, _private=key.private_key
    )
    with pytest.raises(ProfileError, match="private member in public key"):
        build_profile(public_base_url=BASE, key=tainted)


def test_final_check_catches_a_private_member(
    key: MerchantKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    from countersign.protocols.ucp import profile

    monkeypatch.setattr(profile, "_public_jwk", lambda k: {**k.public_jwk, "qi": "v"})
    with pytest.raises(ProfileError, match="private member in profile keys"):
        build_profile(public_base_url=BASE, key=key)


def test_keys_are_top_level_public_only(key: MerchantKey) -> None:
    p = build_profile(public_base_url=BASE, key=key)
    assert "keys" not in p["ucp"]
    (k,) = p["keys"]
    assert k["kid"] == key.kid and k["alg"] == "ES256" and k["crv"] == "P-256"
    assert not PRIVATE_ONLY_MEMBERS & set(_walk(p))


def test_secret_scalar_never_appears_anywhere(key: MerchantKey) -> None:
    jwk = generate_jwk()
    k = validate_jwk(jwk)
    text = json.dumps(build_profile(public_base_url=BASE, key=k))
    assert jwk["d"] not in text


def test_builder_refuses_private_member_in_key(key: MerchantKey) -> None:
    for member in sorted(PRIVATE_ONLY_MEMBERS):
        tainted = MerchantKey(
            kid=key.kid, public_jwk={**key.public_jwk, member: "v"}, _private=key.private_key
        )
        profile = build_profile(public_base_url=BASE, key=tainted)
        assert member not in profile["keys"][0]  # allowlist drops it


def test_builder_ignores_unlisted_members(key: MerchantKey) -> None:
    tainted = MerchantKey(
        kid=key.kid, public_jwk={**key.public_jwk, "note": "x"}, _private=key.private_key
    )
    assert "note" not in build_profile(public_base_url=BASE, key=tainted)["keys"][0]


@pytest.mark.parametrize("base", ["", BASE + "/", "ftp://x.test", "shop.example.test"])
def test_bad_base_url_refused(key: MerchantKey, base: str) -> None:
    with pytest.raises(ProfileError):
        build_profile(public_base_url=base, key=key)


def test_endpoint_serves_the_profile_without_private_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "k.json"
    write_key_file(path)
    raw_d = json.loads(path.read_text())["d"]
    monkeypatch.setenv("MERCHANT_KEY_PATH", str(path))
    client = TestClient(create_app(public_base_url=BASE))
    r = client.get("/.well-known/ucp")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert list(_validator().iter_errors(r.json())) == []
    assert not PRIVATE_ONLY_MEMBERS & set(_walk(r.json()))
    assert raw_d not in r.text


def test_app_refuses_to_start_without_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MERCHANT_KEY_PATH", str(tmp_path / "missing.json"))
    with pytest.raises(MerchantKeyError):
        create_app(public_base_url=BASE)


def test_app_refuses_to_start_with_wrong_curve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "k.json"
    jwk = generate_jwk()
    jwk["crv"] = "P-384"
    path.write_text(json.dumps(jwk))
    path.chmod(0o600)
    monkeypatch.setenv("MERCHANT_KEY_PATH", str(path))
    with pytest.raises(MerchantKeyError):
        create_app(public_base_url=BASE)


def test_the_payment_handler_that_carries_the_mandate_token(key: MerchantKey) -> None:
    """Requirement of docs/PROTOCOL.md Decision 39: a handler whose `id` is the `handler_id` of the
    instrument that holds the Payment Mandate token, validated by the vendored profile schema."""
    from countersign.protocols.ucp.profile import (
        PAYMENT_CREDENTIAL_TYPE,
        PAYMENT_HANDLER_ID,
        PAYMENT_HANDLER_NAME,
    )

    profile = build_profile(public_base_url=BASE, key=key)
    ((name, (handler,)),) = profile["ucp"]["payment_handlers"].items()
    assert name == PAYMENT_HANDLER_NAME and handler["id"] == PAYMENT_HANDLER_ID
    assert handler["config"]["credential_type"] == PAYMENT_CREDENTIAL_TYPE
    assert list(_validator().iter_errors(profile)) == []
    broken = json.loads(json.dumps(profile))
    del broken["ucp"]["payment_handlers"][PAYMENT_HANDLER_NAME][0]["id"]
    assert list(_validator().iter_errors(broken))  # the schema requires the handler id

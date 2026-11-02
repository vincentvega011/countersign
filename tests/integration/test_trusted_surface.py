"""Device key enrolment against the real Postgres, as the restricted application role.

Every refusal code, the add-only rules, the single use of a challenge under a race, the grants and
the log-before-answer rule. Records are signed by a Python device (tests/surface_support.py) that
builds the signed bytes without the production record builder.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient
from joserfc.jwk import ECKey
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from countersign.api.app import create_app
from countersign.ledger import store as ledger
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.trusted_surface import Authorizer, Refused, TrustedSurface
from countersign.trusted_surface import service as surface_service
from tests.integration.conftest import START, Clock
from tests.surface_support import (
    BASE,
    ORIGIN,
    Device,
    body_for,
    record_for,
    revoke_body_for,
    revoke_record_for,
)


@pytest.fixture
def surface(app_engine: Engine, clean_keys: None, clock: Clock) -> TrustedSurface:
    return TrustedSurface(app_engine, public_origin=ORIGIN, clock_us=clock)


@pytest.fixture
def client(app_engine: Engine, surface: TrustedSurface, clock: Clock) -> Iterator[TestClient]:
    app = create_app(
        key=validate_jwk(generate_jwk()),
        public_base_url=ORIGIN,
        engine=app_engine,
        clock_us=clock,
        trusted_surface=surface,
    )
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def challenge(client: TestClient) -> dict[str, Any]:
    r = client.post(f"{BASE}/challenge", json={"purpose": "register_device_key"})
    assert r.status_code == 200, r.text
    return dict(r.json())


def enrol(client: TestClient, device: Device | None = None, **kw: Any) -> tuple[Device, Any]:
    device = device or Device()
    return device, client.post(BASE, json=body_for(device, challenge(client), **kw))


REVOKE = BASE + "/revoke"


def challenge_for(client: TestClient, purpose: str) -> dict[str, Any]:
    r = client.post(f"{BASE}/challenge", json={"purpose": purpose})
    assert r.status_code == 200, r.text
    return dict(r.json())


def revoke(
    client: TestClient, signer: Device, cid: str, target: Device | str | None = None, **kw: Any
) -> Any:
    issued = challenge_for(client, "revoke_device_key")
    return client.post(
        REVOKE, json=revoke_body_for(signer, issued, customer_id=cid, target=target, **kw)
    )


def add_key(client: TestClient, old: Device, cid: str) -> Device:
    """A second device for the customer, vouched for by `old`."""
    new = Device()
    r = client.post(BASE, json=body_for(new, challenge(client), customer_id=cid, authorizer=old))
    assert r.status_code == 201, r.text
    return new


def code(response: Any) -> str:
    return str(response.json()["code"])


def customer(client: TestClient) -> tuple[Device, str]:
    device, r = enrol(client)
    assert r.status_code == 201, r.text
    return device, str(r.json()["customer_id"])


def rows(engine: Engine, sql: str, **params: Any) -> list[Any]:
    with engine.connect() as conn:
        return list(conn.execute(text(sql), params).all())


# ------------------------------------------------------------------------------------ the happy path


def test_a_valid_registration_creates_a_customer_and_stores_the_key(
    client: TestClient, admin_engine: Engine
) -> None:
    device, r = enrol(client)
    assert r.status_code == 201
    body = r.json()
    assert body["new_customer"] is True and body["new_key"] is True
    assert body["customer_id"].startswith("cus_") and len(body["customer_id"]) == 26
    # The thumbprint is computed by the server and matches an independent RFC 7638 implementation.
    assert body["thumbprint"] == device.thumbprint == ECKey.import_key(device.jwk).thumbprint()
    stored = rows(admin_engine, "SELECT customer_id, thumbprint, jwk FROM customer_keys")
    assert len(stored) == 1 and stored[0].customer_id == body["customer_id"]
    assert json.loads(stored[0].jwk) == device.jwk
    assert r.headers["cache-control"] == "no-store"


def test_registration_and_challenge_are_in_the_log_and_the_log_verifies(
    client: TestClient, admin_engine: Engine
) -> None:
    device, _ = enrol(client)
    entries = rows(admin_engine, "SELECT kind, payload FROM decision_log")
    assert [e.kind for e in entries] == ["ts.key.registered"]
    payload = json.loads(bytes(entries[0].payload))
    assert payload["thumbprint"] == device.thumbprint and payload["customer_id"]
    with admin_engine.connect() as conn:
        assert ledger.verify_log(conn).ok


def test_challenges_are_random_and_carry_the_purpose(client: TestClient) -> None:
    a, b = challenge(client), challenge(client)
    assert a["challenge_id"] != b["challenge_id"] and a["nonce"] != b["nonce"]
    assert a["challenge_id"].startswith("kch_") and len(a["challenge_id"]) == 26
    assert a["purpose"] == "register_device_key" and len(a["nonce"]) >= 43
    assert a["expires_us"] == START + 300_000_000


def test_the_origin_is_compared_normalized_and_the_default_port_is_filled_in(
    client: TestClient,
) -> None:
    _, r = enrol(client, origin="HTTPS://Surface.Example.Test:443", sign_origin=ORIGIN)
    assert r.status_code == 201, r.text


# ------------------------------------------------------------------------------------ challenges


def test_a_replayed_challenge_is_refused(client: TestClient) -> None:
    ch = challenge(client)
    assert client.post(BASE, json=body_for(Device(), ch)).status_code == 201
    again = client.post(BASE, json=body_for(Device(), ch))
    assert again.status_code == 409 and code(again) == "challenge_used"


def test_the_same_request_twice_does_not_pass_the_second_time(client: TestClient) -> None:
    device, ch = Device(), None
    ch = challenge(client)
    body = body_for(device, ch)
    assert client.post(BASE, json=body).status_code == 201
    assert code(client.post(BASE, json=body)) == "challenge_used"


def test_an_expired_challenge_is_refused_at_exactly_five_minutes(
    client: TestClient, clock: Clock
) -> None:
    ch = challenge(client)
    clock.now = START + 300_000_000  # five minutes, written out so a changed constant is caught
    r = client.post(BASE, json=body_for(Device(), ch))
    assert r.status_code == 410 and code(r) == "challenge_expired"


def test_a_challenge_one_microsecond_before_expiry_still_works(
    client: TestClient, clock: Clock
) -> None:
    ch = challenge(client)
    clock.now = START + 300_000_000 - 1
    assert client.post(BASE, json=body_for(Device(), ch)).status_code == 201


def test_a_challenge_for_another_purpose_is_refused(
    client: TestClient, admin_engine: Engine
) -> None:
    ch = challenge(client)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE key_challenges SET purpose = 'sign_consent' WHERE id = :i"),
            {"i": ch["challenge_id"]},
        )
    r = client.post(BASE, json=body_for(Device(), ch))
    assert r.status_code == 400 and code(r) == "challenge_purpose_mismatch"


def test_an_unknown_challenge_is_refused(client: TestClient) -> None:
    ch = {"challenge_id": "kch_" + "A" * 22, "nonce": "n" * 43}
    r = client.post(BASE, json=body_for(Device(), ch))
    assert r.status_code == 404 and code(r) == "challenge_unknown"


def test_a_malformed_challenge_id_is_refused(client: TestClient) -> None:
    ch = challenge(client)
    for bad in ("kch_short", "x" * 500, "kch_" + "!" * 22, 12, None):
        r = client.post(BASE, json=body_for(Device(), ch, challenge_id=bad))
        assert r.status_code == 400 and code(r) == "malformed_request", bad


def test_a_challenge_is_not_spent_by_a_refused_registration(client: TestClient) -> None:
    ch = challenge(client)
    bad = client.post(BASE, json=body_for(Device(), ch, signer=Device()))
    assert code(bad) == "proof_invalid"
    assert client.post(BASE, json=body_for(Device(), ch)).status_code == 201


def test_only_the_registration_purpose_can_be_requested(client: TestClient) -> None:
    for purpose in ("sign_consent", "", None, 5):
        r = client.post(f"{BASE}/challenge", json={"purpose": purpose})
        assert r.status_code == 400 and code(r) == "purpose_unknown", purpose
    for body in ({}, {"purpose": "register_device_key", "extra": 1}, []):
        r = client.post(f"{BASE}/challenge", json=body)
        assert r.status_code == 400 and code(r) == "malformed_request", body


# ------------------------------------------------------------------------------------ origin


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example.test",
        "http://surface.example.test",
        "https://surface.example.test:8443",
        "https://surface.example.test/path",
        "https://surface.example.test?x",
        "https://user@surface.example.test",
        "surface.example.test",
        "javascript:alert(1)",
        "",
        None,
        7,
    ],
)
def test_a_wrong_origin_is_refused(client: TestClient, origin: Any) -> None:
    ch = challenge(client)
    r = client.post(BASE, json=body_for(Device(), ch, origin=origin, sign_origin=ORIGIN))
    assert r.status_code == 403 and code(r) == "origin_mismatch"


def test_a_signature_over_another_origin_does_not_verify(client: TestClient) -> None:
    ch = challenge(client)
    r = client.post(BASE, json=body_for(Device(), ch, sign_origin="https://evil.example.test"))
    assert r.status_code == 400 and code(r) == "proof_invalid"


def test_a_browser_origin_header_that_differs_is_refused(client: TestClient) -> None:
    ch = challenge(client)
    r = client.post(
        BASE, json=body_for(Device(), ch), headers={"Origin": "https://evil.example.test"}
    )
    assert r.status_code == 403 and code(r) == "origin_mismatch"
    ok = client.post(BASE, json=body_for(Device(), challenge(client)), headers={"Origin": ORIGIN})
    assert ok.status_code == 201


# ------------------------------------------------------------------------------------ the proof


def test_a_signature_by_a_different_key_is_refused(client: TestClient) -> None:
    ch = challenge(client)
    r = client.post(BASE, json=body_for(Device(), ch, signer=Device()))
    assert r.status_code == 400 and code(r) == "proof_invalid"


@pytest.mark.parametrize(
    "tamper",
    [
        {"v": 2},
        {"purpose": "countersign.consent.v1"},
        {"challenge": "x" * 43},
        {"challenge_id": "kch_" + "B" * 22},
        {"thumbprint": "t" * 43},
        {"customer_id": "cus_" + "C" * 22},
        {"origin": "https://surface.example.test:444"},
    ],
    ids=lambda t: next(iter(t)),
)
def test_a_tampered_record_does_not_verify(client: TestClient, tamper: dict[str, Any]) -> None:
    device, ch = Device(), challenge(client)
    body = body_for(device, ch)
    body["signature"] = device.sign(record_for(ch, device.thumbprint, override=tamper))
    r = client.post(BASE, json=body)
    assert r.status_code == 400 and code(r) == "proof_invalid"


def test_a_record_with_an_extra_member_does_not_verify(client: TestClient) -> None:
    from countersign.canonical.jcs import canonicalize

    device, ch = Device(), challenge(client)
    body = body_for(device, ch)
    extra = json.loads(record_for(ch, device.thumbprint)) | {"extra": 1}
    body["signature"] = device.sign(canonicalize(extra))
    assert code(client.post(BASE, json=body)) == "proof_invalid"


@pytest.mark.parametrize(
    "signature",
    ["", "A" * 85, "A" * 87, "A" * 86, "!" * 86, "A" * 43 + "=" * 43, 5, None, [], "A" * 4000],
)
def test_a_malformed_signature_is_refused(client: TestClient, signature: Any) -> None:
    ch = challenge(client)
    r = client.post(BASE, json=body_for(Device(), ch, signature=signature))
    assert r.status_code == 400 and code(r) in {"proof_invalid", "malformed_request"}


def test_a_der_encoded_signature_is_refused(client: TestClient) -> None:
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    device, ch = Device(), challenge(client)
    der = device.private.sign(record_for(ch, device.thumbprint), ec.ECDSA(hashes.SHA256()))
    body = body_for(device, ch, signature=base64.urlsafe_b64encode(der).rstrip(b"=").decode())
    assert code(client.post(BASE, json=body)) == "proof_invalid"


def test_the_signature_must_be_over_the_new_keys_own_thumbprint(client: TestClient) -> None:
    """A proof made for key A cannot be attached to key B's JWK."""
    a, b, ch = Device(), Device(), challenge(client)
    body = body_for(a, ch)
    body["jwk"] = b.jwk
    assert code(client.post(BASE, json=body)) == "proof_invalid"


# ------------------------------------------------------------------------------------ the JWK


def good_jwk() -> dict[str, str]:
    return Device().jwk


def swap(jwk: dict[str, str], **changes: Any) -> dict[str, Any]:
    out: dict[str, Any] = dict(jwk)
    for k, v in changes.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


def p384_jwk() -> dict[str, str]:
    from cryptography.hazmat.primitives.asymmetric import ec

    from tests.surface_support import b64

    n = ec.generate_private_key(ec.SECP384R1()).public_key().public_numbers()
    return {
        "kty": "EC", "crv": "P-384",
        "x": b64(n.x.to_bytes(48, "big")), "y": b64(n.y.to_bytes(48, "big")),
    }  # fmt: skip


def noncanonical(value: str) -> str:
    """The same 32 bytes spelled with a different final character (unused low bits set)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(value[-1])
    return value[:-1] + alphabet[last ^ 1]


def jwk_cases() -> list[tuple[str, dict[str, Any], str]]:
    base = good_jwk()
    cases: list[tuple[str, dict[str, Any], str]] = [
        ("private d", swap(base, d=base["x"]), "jwk_private_member"),
        ("private p", swap(base, p=base["x"]), "jwk_private_member"),
        ("curve P-384", p384_jwk(), "jwk_unsupported_curve"),
        ("curve name", swap(base, crv="P-521"), "jwk_unsupported_curve"),
        ("kty OKP", swap(base, kty="OKP"), "jwk_unsupported_curve"),
        (
            "off curve",
            swap(base, y=base["x"] if base["x"] != base["y"] else "A" * 43),
            "jwk_not_on_curve",
        ),
        ("zero point", swap(base, x="A" * 43, y="A" * 43), "jwk_not_on_curve"),
        ("extra alg", swap(base, alg="ES256"), "jwk_extra_members"),
        ("extra kid", swap(base, kid="k1"), "jwk_extra_members"),
        ("extra ext", swap(base, ext=True), "jwk_extra_members"),
        ("extra key_ops", swap(base, key_ops=["verify"]), "jwk_extra_members"),
        ("missing y", swap(base, y=None), "jwk_malformed"),
        ("missing crv", swap(base, crv=None), "jwk_malformed"),
        ("x short", swap(base, x=base["x"][:-1]), "jwk_malformed"),
        ("x long", swap(base, x=base["x"] + "A"), "jwk_malformed"),
        ("x padded", swap(base, x=base["x"] + "="), "jwk_malformed"),
        ("x not base64url", swap(base, x="+" + base["x"][1:]), "jwk_malformed"),
        ("x noncanonical", swap(base, x=noncanonical(base["x"])), "jwk_malformed"),
        ("x number", swap(base, x=5), "jwk_malformed"),
        ("y null", swap(base, y=None) | {"y": None}, "jwk_malformed"),
        ("jwk list", [], "jwk_malformed"),  # type: ignore[list-item]
        ("jwk string", "abc", "jwk_malformed"),  # type: ignore[dict-item]
        ("jwk null", None, "jwk_malformed"),  # type: ignore[dict-item]
    ]
    return cases


@pytest.mark.parametrize("name,jwk,expected", jwk_cases(), ids=[c[0] for c in jwk_cases()])
def test_a_bad_jwk_is_refused_with_its_own_code(
    client: TestClient, name: str, jwk: Any, expected: str
) -> None:
    ch = challenge(client)
    body = body_for(Device(), ch)
    body["jwk"] = jwk
    r = client.post(BASE, json=body)
    assert r.status_code == 400 and code(r) == expected, (name, r.text)


def test_a_missing_jwk_member_in_the_body_is_malformed(client: TestClient) -> None:
    ch = challenge(client)
    for missing in ("jwk", "challenge_id", "origin", "signature"):
        body = body_for(Device(), ch)
        del body[missing]
        r = client.post(BASE, json=body)
        assert r.status_code == 400 and code(r) == "malformed_request", missing
    extra = body_for(Device(), ch) | {"extra": 1}
    assert code(client.post(BASE, json=extra)) == "malformed_request"


# ------------------------------------------------------------------------------------ body limits


def test_an_oversized_body_is_refused(client: TestClient) -> None:
    ch = challenge(client)
    body = body_for(Device(), ch)
    body["origin"] = "https://" + "a" * 20_000
    r = client.post(BASE, content=json.dumps(body), headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and code(r) == "request_too_large"


def test_oversized_fields_inside_the_limit_are_refused(client: TestClient) -> None:
    ch = challenge(client)
    cases = {
        "origin": "https://" + "a" * 3000 + ".test",
        "signature": "A" * 3000,
        "customer_id": "cus_" + "A" * 3000,
        "challenge_id": "kch_" + "A" * 3000,
    }
    for field, value in cases.items():
        r = client.post(BASE, json=body_for(Device(), ch, **{field: value}))
        assert r.status_code in (400, 403) and code(r) in {
            "malformed_request", "origin_mismatch", "proof_invalid"
        }, field  # fmt: skip


def test_duplicate_keys_and_other_bad_json_are_refused(client: TestClient) -> None:
    ch = challenge(client)
    good = json.dumps(body_for(Device(), ch))
    headers = {"Content-Type": "application/json"}
    dup = good[:-1] + ', "origin": "https://evil.example.test"}'
    for raw in (dup, "{", "[]", "NaN", good.replace("}", ', "n": NaN}', 1)):
        r = client.post(BASE, content=raw, headers=headers)
        assert r.status_code == 400 and code(r) == "malformed_request", raw
    r = client.post(BASE, content=good, headers={"Content-Type": "text/plain"})
    assert code(r) == "malformed_request"


# ------------------------------------------------------------------------------------ customers


def test_adding_a_key_to_an_existing_customer_needs_an_old_key_signature(
    client: TestClient,
) -> None:
    old, cid = customer(client)
    new = Device()
    r = client.post(BASE, json=body_for(new, challenge(client), customer_id=cid))
    assert r.status_code == 403 and code(r) == "authorizer_required"
    r = client.post(BASE, json=body_for(new, challenge(client), customer_id=cid, authorizer=old))
    assert r.status_code == 201, r.text
    assert r.json() == {
        "customer_id": cid, "thumbprint": new.thumbprint, "new_customer": False, "new_key": True,
    }  # fmt: skip


def test_the_old_key_signature_must_be_over_the_same_record(client: TestClient) -> None:
    old, cid = customer(client)
    new, ch = Device(), challenge(client)
    body = body_for(new, ch, customer_id=cid, authorizer=old)
    other = challenge(client)
    body["authorizer"] = {
        "thumbprint": old.thumbprint,
        "signature": old.sign(record_for(other, new.thumbprint, customer_id=cid)),
    }
    r = client.post(BASE, json=body)
    assert r.status_code == 403 and code(r) == "authorizer_invalid"


def test_the_new_keys_own_signature_is_not_an_old_key_signature(client: TestClient) -> None:
    _, cid = customer(client)
    new, ch = Device(), challenge(client)
    body = body_for(new, ch, customer_id=cid)
    record = record_for(ch, new.thumbprint, customer_id=cid)
    body["authorizer"] = {"thumbprint": _.thumbprint, "signature": new.sign(record)}
    assert code(client.post(BASE, json=body)) == "authorizer_invalid"


def test_a_revoked_old_key_cannot_vouch(client: TestClient) -> None:
    old, cid = customer(client)
    other = add_key(client, old, cid)
    assert revoke(client, other, cid, old).status_code == 201
    r = client.post(
        BASE, json=body_for(Device(), challenge(client), customer_id=cid, authorizer=old)
    )
    assert r.status_code == 403 and code(r) == "authorizer_revoked"


def test_another_customers_key_cannot_vouch(client: TestClient) -> None:
    _, cid = customer(client)
    stranger, _ = customer(client)
    r = client.post(
        BASE, json=body_for(Device(), challenge(client), customer_id=cid, authorizer=stranger)
    )
    assert r.status_code == 403 and code(r) == "authorizer_unknown"


def test_an_unknown_customer_is_refused(client: TestClient) -> None:
    r = client.post(BASE, json=body_for(Device(), challenge(client), customer_id="cus_" + "Z" * 22))
    assert r.status_code == 404 and code(r) == "customer_unknown"


def test_a_malformed_customer_id_is_refused(client: TestClient) -> None:
    ch = challenge(client)
    for bad in ("cus_short", "x" * 300, 5, "", "kch_" + "A" * 22):
        r = client.post(BASE, json=body_for(Device(), ch, customer_id=bad))
        assert r.status_code == 400 and code(r) == "malformed_request", bad


def test_the_same_thumbprint_for_a_different_customer_is_a_conflict(client: TestClient) -> None:
    a, _ = customer(client)
    _, cid_b = customer(client)
    r = client.post(BASE, json=body_for(a, challenge(client), customer_id=cid_b))
    assert r.status_code == 409 and code(r) == "key_conflict"


def test_the_same_thumbprint_for_the_same_customer_is_an_idempotent_success(
    client: TestClient, admin_engine: Engine
) -> None:
    a, cid = customer(client)
    r = client.post(BASE, json=body_for(a, challenge(client), customer_id=cid))
    assert r.status_code == 200
    assert r.json() == {
        "customer_id": cid, "thumbprint": a.thumbprint, "new_customer": False, "new_key": False,
    }  # fmt: skip
    assert len(rows(admin_engine, "SELECT 1 FROM customer_keys")) == 1


def test_a_key_registered_again_without_a_customer_returns_its_customer(
    client: TestClient, admin_engine: Engine
) -> None:
    """Proof of possession is enough to learn which customer a key already belongs to."""
    a, cid = customer(client)
    r = client.post(BASE, json=body_for(a, challenge(client)))
    assert r.status_code == 200 and r.json()["customer_id"] == cid
    assert len(rows(admin_engine, "SELECT 1 FROM customer_keys")) == 1


def test_an_idempotent_repeat_still_spends_its_challenge(client: TestClient) -> None:
    a, cid = customer(client)
    ch = challenge(client)
    assert client.post(BASE, json=body_for(a, ch, customer_id=cid)).status_code == 200
    assert code(client.post(BASE, json=body_for(a, ch, customer_id=cid))) == "challenge_used"


def test_a_revoked_key_never_gets_the_idempotent_reregistration(client: TestClient) -> None:
    """Decision 78: revocation is final, whether or not the request names the customer."""
    a, cid = customer(client)
    other = add_key(client, a, cid)
    assert revoke(client, other, cid, a).status_code == 201
    for named in (cid, None):
        r = client.post(BASE, json=body_for(a, challenge(client), customer_id=named))
        assert r.status_code == 409 and code(r) == "key_revoked", named
    # and the same key under another customer is still a conflict, not a success
    _, cid_b = customer(client)
    r = client.post(BASE, json=body_for(a, challenge(client), customer_id=cid_b))
    assert r.status_code == 409 and code(r) == "key_conflict"


def test_two_new_customers_get_different_ids(client: TestClient) -> None:
    assert customer(client)[1] != customer(client)[1]


# ------------------------------------------------------------------------------------ concurrency


def race(surface: TrustedSurface, ch: Any, devices: list[Device]) -> list[str]:
    """Register every device on one challenge at the same instant; return each outcome."""
    issued = {"challenge_id": ch.challenge_id, "nonce": ch.nonce}
    gate = threading.Barrier(len(devices))

    def attempt(device: Device) -> str:
        body = body_for(device, issued)
        gate.wait()
        try:
            surface.register(
                jwk=body["jwk"], challenge_id=body["challenge_id"], customer_id=None,
                origin=body["origin"], signature=body["signature"], authorizer=None,
            )  # fmt: skip
        except Refused as error:
            return error.code
        return "ok"

    with ThreadPoolExecutor(len(devices)) as pool:
        return list(pool.map(attempt, devices))


@pytest.mark.parametrize("same_key", [False, True])
def test_exactly_one_of_many_simultaneous_registrations_on_one_challenge_wins(
    surface: TrustedSurface, admin_engine: Engine, same_key: bool
) -> None:
    for _ in range(4):
        ch = surface.issue_challenge("register_device_key")
        shared = Device()
        devices = [shared if same_key else Device() for _ in range(12)]
        results = race(surface, ch, devices)
        assert results.count("ok") == 1, results
        assert set(results) - {"ok"} <= {"challenge_used"}, results
        used = rows(
            admin_engine, "SELECT 1 FROM key_challenge_uses WHERE challenge_id = :c",
            c=ch.challenge_id,
        )  # fmt: skip
        assert len(used) == 1
    assert len(rows(admin_engine, "SELECT 1 FROM customer_keys")) == 4
    assert len(rows(admin_engine, "SELECT 1 FROM key_challenge_uses")) == 4
    with admin_engine.connect() as conn:
        assert ledger.verify_log(conn).ok


def test_one_key_on_two_challenges_at_once_makes_one_customer(
    surface: TrustedSurface, admin_engine: Engine
) -> None:
    device = Device()
    challenges = [surface.issue_challenge("register_device_key") for _ in range(8)]
    gate = threading.Barrier(len(challenges))

    def attempt(ch: Any) -> str:
        body = body_for(device, {"challenge_id": ch.challenge_id, "nonce": ch.nonce})
        gate.wait()
        try:
            surface.register(
                jwk=body["jwk"], challenge_id=body["challenge_id"], customer_id=None,
                origin=body["origin"], signature=body["signature"], authorizer=None,
            )  # fmt: skip
        except Refused as error:
            return error.code
        return "ok"

    with ThreadPoolExecutor(len(challenges)) as pool:
        results = list(pool.map(attempt, challenges))
    assert "ok" in results and set(results) <= {"ok", "key_conflict"}, results
    assert len(rows(admin_engine, "SELECT 1 FROM customer_keys")) == 1


# ------------------------------------------------------------------------------------ the database


def test_the_runtime_role_can_only_select_and_insert_here(
    client: TestClient, app_engine: Engine
) -> None:
    device, cid = customer(client)
    other = add_key(client, device, cid)
    assert revoke(client, other, cid, device).status_code == 201
    tables = (
        "key_challenges", "key_challenge_uses", "customer_keys", "key_revocations",
        "consent_records",
    )  # fmt: skip
    for table in tables:
        for sql in (f"DELETE FROM {table}", f"TRUNCATE {table} CASCADE"):
            with pytest.raises(DBAPIError), app_engine.begin() as conn:
                conn.execute(text(sql))
    for sql in (
        "UPDATE key_challenges SET purpose = 'x'",
        "UPDATE key_challenge_uses SET thumbprint = 'x'",
        "UPDATE customer_keys SET jwk = 'x'",
        "UPDATE customer_keys SET customer_id = 'cus_other'",
        "UPDATE key_revocations SET revoked_us = 0",
        "UPDATE key_revocations SET signature = 'x'",
        "UPDATE consent_records SET record = 'x'",
    ):
        with pytest.raises(DBAPIError), app_engine.begin() as conn:
            conn.execute(text(sql))
    assert len(rows(app_engine, "SELECT thumbprint FROM customer_keys")) == 2
    assert len(rows(app_engine, "SELECT thumbprint FROM key_revocations")) == 1


def test_customer_keys_has_no_revoked_column_and_no_trigger_any_more(
    admin_engine: Engine,
) -> None:
    columns = {r.column_name for r in rows(
        admin_engine,
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'customer_keys'",
    )}  # fmt: skip
    assert columns == {"customer_id", "thumbprint", "jwk", "created_us"}
    assert (
        rows(
            admin_engine,
            "SELECT 1 FROM pg_trigger WHERE tgrelid = 'customer_keys'::regclass AND NOT tgisinternal",
        )
        == []
    )


# ------------------------------------------------------------------------------------ the log


def test_every_refusal_is_logged_before_the_answer_with_a_thumbprint_and_no_body(
    client: TestClient, admin_engine: Engine
) -> None:
    device, ch = Device(), challenge(client)
    body = body_for(device, ch, signer=Device())
    r = client.post(BASE, json=body)
    assert code(r) == "proof_invalid"
    entries = rows(admin_engine, "SELECT kind, payload, checkout_id FROM decision_log")
    assert [e.kind for e in entries] == ["ts.key.refused"]
    payload = json.loads(bytes(entries[0].payload))
    assert payload == {
        "code": "proof_invalid", "thumbprint": device.thumbprint, "challenge_id": ch["challenge_id"],
    }  # fmt: skip
    raw = bytes(entries[0].payload).decode()
    assert body["signature"] not in raw and body["jwk"]["x"] not in raw and ORIGIN not in raw


def test_a_refusal_before_the_service_runs_is_logged_too(
    client: TestClient, admin_engine: Engine
) -> None:
    client.post(BASE, content="{", headers={"Content-Type": "application/json"})
    client.post(f"{BASE}/challenge", json={"purpose": "nope"})
    kinds = [e.kind for e in rows(admin_engine, "SELECT kind FROM decision_log ORDER BY seq")]
    assert kinds == ["ts.key.refused", "ts.challenge.refused"]


def test_a_log_failure_fails_a_refusal_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    ch = challenge(client)

    def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("log is down")

    monkeypatch.setattr(surface_service.ledger_store, "append", broken)
    r = client.post(BASE, json=body_for(Device(), ch, signer=Device()))
    assert r.status_code == 503 and code(r) == "log_unavailable"


def test_a_log_failure_means_no_key_is_registered(
    client: TestClient, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    ch = challenge(client)

    def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("log is down")

    monkeypatch.setattr(surface_service.ledger_store, "append", broken)
    r = client.post(BASE, json=body_for(Device(), ch))
    assert r.status_code == 503 and code(r) == "log_unavailable"
    assert rows(admin_engine, "SELECT 1 FROM customer_keys") == []
    assert rows(admin_engine, "SELECT 1 FROM key_challenge_uses") == []
    monkeypatch.undo()
    assert client.post(BASE, json=body_for(Device(), ch)).status_code == 201


def test_a_bad_configured_origin_stops_the_start(app_engine: Engine) -> None:
    from countersign.trusted_surface import KeyRefused

    for bad in ("", "localhost", "ftp://x", "https://x/path", "https://u@x"):
        with pytest.raises(KeyRefused):
            TrustedSurface(app_engine, public_origin=bad)


# ------------------------------------------------------------------------------------ wiring


@pytest.mark.parametrize("mode", ["full", "baseline"])
def test_the_composition_root_serves_enrolment_and_the_page_in_demo(
    app_engine: Engine, clean_keys: None, mode: str
) -> None:
    from countersign.runtime import Mode, RuntimeSettings
    from tests.mode_support import BASE as WORLD_BASE
    from tests.mode_support import make_world

    world = make_world(app_engine, RuntimeSettings(Mode(mode), "demo"))
    assert world.client.get("/approve/").status_code == 200
    issued = world.client.post(f"{BASE}/challenge", json={"purpose": "register_device_key"})
    assert issued.status_code == 200
    device = Device()
    body = body_for(device, issued.json(), origin=WORLD_BASE, sign_origin=WORLD_BASE)
    assert world.client.post(BASE, json=body).status_code == 201


# ------------------------------------------------------------------------------------ more shapes


def test_a_spent_challenge_is_reported_as_spent_even_with_a_bad_proof(client: TestClient) -> None:
    ch = challenge(client)
    assert client.post(BASE, json=body_for(Device(), ch)).status_code == 201
    r = client.post(BASE, json=body_for(Device(), ch, signer=Device()))
    assert r.status_code == 409 and code(r) == "challenge_used"


@pytest.mark.parametrize(
    "authorizer",
    [
        [],
        "x",
        5,
        {},
        {"thumbprint": "a" * 43},
        {"signature": "a" * 86},
        {"thumbprint": "a" * 43, "signature": "a" * 86, "extra": "x"},
        {"thumbprint": 5, "signature": "a" * 86},
        {"thumbprint": "a" * 43, "signature": ["a"]},
        {"thumbprint": "a" * 500, "signature": "a" * 86},
        {"thumbprint": "a" * 43, "signature": "a" * 500},
    ],
)
def test_a_malformed_authorizer_is_refused(client: TestClient, authorizer: Any) -> None:
    _, cid = customer(client)
    body = body_for(Device(), challenge(client), customer_id=cid)
    body["authorizer"] = authorizer
    r = client.post(BASE, json=body)
    assert r.status_code == 400 and code(r) == "malformed_request"


def test_an_authorizer_without_a_customer_is_refused(client: TestClient) -> None:
    old, _ = customer(client)
    r = client.post(BASE, json=body_for(Device(), challenge(client), authorizer=old))
    assert r.status_code == 400 and code(r) == "malformed_request"


# ------------------------------------------------------------------------------------ revocation


def two_keys(client: TestClient) -> tuple[Device, Device, str]:
    first, cid = customer(client)
    return first, add_key(client, first, cid), cid


def test_a_key_can_revoke_another_key_of_its_customer(
    client: TestClient, admin_engine: Engine
) -> None:
    first, second, cid = two_keys(client)
    r = revoke(client, second, cid, first)
    assert r.status_code == 201
    assert r.json() == {"customer_id": cid, "thumbprint": first.thumbprint, "new_revocation": True}
    row = rows(admin_engine, "SELECT * FROM key_revocations")
    assert len(row) == 1 and row[0].thumbprint == first.thumbprint
    assert row[0].customer_id == cid and row[0].signer_thumbprint == second.thumbprint
    assert row[0].signature and json.loads(row[0].record)["target_thumbprint"] == first.thumbprint
    kinds = [e.kind for e in rows(admin_engine, "SELECT kind FROM decision_log ORDER BY seq")]
    assert kinds[-1] == "ts.key.revoked"


def test_a_key_can_revoke_itself_and_then_it_is_gone_for_good(client: TestClient) -> None:
    first, second, cid = two_keys(client)
    assert revoke(client, first, cid).status_code == 201
    again = revoke(client, first, cid)  # it can no longer speak for the customer
    assert again.status_code == 403 and code(again) == "signer_revoked"
    assert revoke(client, second, cid).status_code == 201  # the last key may be revoked too
    last = revoke(client, second, cid)
    assert code(last) == "signer_revoked"


def test_revoking_a_revoked_key_is_an_idempotent_success(
    client: TestClient, admin_engine: Engine
) -> None:
    first, second, cid = two_keys(client)
    assert revoke(client, second, cid, first).status_code == 201
    r = revoke(client, second, cid, first)
    assert r.status_code == 200 and r.json()["new_revocation"] is False
    assert len(rows(admin_engine, "SELECT 1 FROM key_revocations")) == 1


def test_a_revoked_key_loses_every_power(client: TestClient) -> None:
    first, second, cid = two_keys(client)
    assert revoke(client, second, cid, first).status_code == 201
    assert code(revoke(client, first, cid, second)) == "signer_revoked"
    r = client.post(
        BASE, json=body_for(Device(), challenge(client), customer_id=cid, authorizer=first)
    )
    assert code(r) == "authorizer_revoked"
    assert code(client.post(BASE, json=body_for(first, challenge(client)))) == "key_revoked"
    # the other key still works
    r = client.post(
        BASE, json=body_for(Device(), challenge(client), customer_id=cid, authorizer=second)
    )
    assert r.status_code == 201


def test_revocation_refusals_have_stable_codes(client: TestClient) -> None:
    first, second, cid = two_keys(client)
    stranger, other_cid = customer(client)
    unknown_cid = "cus_" + "Z" * 22
    cases = [
        ("customer_unknown", revoke(client, first, unknown_cid, first)),
        ("signer_unknown", revoke(client, Device(), cid, first)),
        ("signer_unknown", revoke(client, stranger, cid, first)),  # another customer's key
        ("key_unknown", revoke(client, first, cid, Device())),
        ("key_unknown", revoke(client, first, cid, stranger)),  # another customer's key as target
        ("proof_invalid", revoke(client, first, cid, second, sign_with=Device())),
        ("proof_invalid", revoke(client, first, cid, second, sign_with=second)),
        ("origin_mismatch", revoke(client, first, cid, second, origin="https://evil.example.test")),
    ]
    for expected, response in cases:
        assert code(response) == expected, (expected, response.text)
    assert other_cid != cid


@pytest.mark.parametrize(
    "tamper",
    [
        {"v": 2},
        {"purpose": "countersign.device-key.register.v1"},
        {"challenge": "x" * 43},
        {"challenge_id": "kch_" + "B" * 22},
        {"customer_id": "cus_" + "C" * 22},
        {"target_thumbprint": "t" * 43},
        {"signer_thumbprint": "s" * 43},
        {"origin": "https://surface.example.test:444"},
    ],
    ids=lambda t: next(iter(t)),
)
def test_a_tampered_revocation_record_does_not_verify(
    client: TestClient, tamper: dict[str, Any]
) -> None:
    first, second, cid = two_keys(client)
    issued = challenge_for(client, "revoke_device_key")
    body = revoke_body_for(second, issued, customer_id=cid, target=first)
    body["signature"] = second.sign(
        revoke_record_for(
            issued, customer_id=cid, target=first.thumbprint, signer=second.thumbprint,
            override=tamper,
        )
    )  # fmt: skip
    r = client.post(REVOKE, json=body)
    assert r.status_code == 400 and code(r) == "proof_invalid"


def test_a_revocation_cannot_reuse_a_challenge_of_another_purpose_or_twice(
    client: TestClient,
) -> None:
    first, second, cid = two_keys(client)
    wrong = challenge(client)  # a registration challenge
    r = client.post(REVOKE, json=revoke_body_for(second, wrong, customer_id=cid, target=first))
    assert code(r) == "challenge_purpose_mismatch"
    issued = challenge_for(client, "revoke_device_key")
    body = revoke_body_for(second, issued, customer_id=cid, target=first)
    assert client.post(REVOKE, json=body).status_code == 201
    assert code(client.post(REVOKE, json=body)) == "challenge_used"
    reg = body_for(Device(), issued)  # and a revocation challenge is no registration challenge
    assert code(client.post(BASE, json=reg)) == "challenge_purpose_mismatch"


def test_a_revocation_challenge_expires(client: TestClient, clock: Clock) -> None:
    first, second, cid = two_keys(client)
    issued = challenge_for(client, "revoke_device_key")
    clock.now = START + 300_000_000
    r = client.post(REVOKE, json=revoke_body_for(second, issued, customer_id=cid, target=first))
    assert r.status_code == 410 and code(r) == "challenge_expired"


def test_malformed_revocation_bodies_are_refused(client: TestClient) -> None:
    first, second, cid = two_keys(client)
    issued = challenge_for(client, "revoke_device_key")
    good = revoke_body_for(second, issued, customer_id=cid, target=first)
    for field, bad in (
        ("customer_id", "cus_short"), ("target", "x"), ("signer", 5), ("signature", None),
        ("challenge_id", "kch_x"), ("target", "A" * 4000),
    ):  # fmt: skip
        r = client.post(REVOKE, json={**good, field: bad})
        assert r.status_code == 400 and code(r) == "malformed_request", field
    assert code(client.post(REVOKE, json={**good, "extra": 1})) == "malformed_request"
    missing = {k: v for k, v in good.items() if k != "target"}
    assert code(client.post(REVOKE, json=missing)) == "malformed_request"


def race_revoke(
    surface: TrustedSurface, cid: str, pairs: list[tuple[Device, Device, dict[str, Any]]]
) -> list[str]:
    """Each (signer, target, challenge) revocation at the same instant; the outcome of each."""
    gate = threading.Barrier(len(pairs))

    def attempt(pair: tuple[Device, Device, dict[str, Any]]) -> str:
        signer, target, ch = pair
        body = revoke_body_for(signer, ch, customer_id=cid, target=target)
        gate.wait()
        try:
            surface.revoke(
                challenge_id=body["challenge_id"], customer_id=cid, target=body["target"],
                signer=body["signer"], origin=body["origin"], signature=body["signature"],
            )  # fmt: skip
        except Refused as error:
            return error.code
        return "ok"

    with ThreadPoolExecutor(len(pairs)) as pool:
        return list(pool.map(attempt, pairs))


def test_two_keys_revoking_each_other_at_once_leave_one_standing(
    surface: TrustedSurface, client: TestClient, admin_engine: Engine
) -> None:
    for _ in range(3):
        first, second, cid = two_keys(client)
        issued = [
            {"challenge_id": c.challenge_id, "nonce": c.nonce}
            for c in (surface.issue_challenge("revoke_device_key") for _ in range(2))
        ]
        results = sorted(
            race_revoke(surface, cid, [(first, second, issued[0]), (second, first, issued[1])])
        )
        assert results == ["ok", "signer_revoked"], results
        done = rows(
            admin_engine, "SELECT 1 FROM key_revocations WHERE customer_id = :c", c=cid
        )  # fmt: skip
        assert len(done) == 1


def test_many_revocations_of_one_key_make_one_row(
    surface: TrustedSurface, client: TestClient, admin_engine: Engine
) -> None:
    first, second, cid = two_keys(client)
    gate = threading.Barrier(8)
    issued = [surface.issue_challenge("revoke_device_key") for _ in range(8)]

    def attempt(ch: Any) -> bool:
        body = revoke_body_for(
            second,
            {"challenge_id": ch.challenge_id, "nonce": ch.nonce},
            customer_id=cid,
            target=first,
        )
        gate.wait()
        done = surface.revoke(
            challenge_id=body["challenge_id"], customer_id=cid, target=body["target"],
            signer=body["signer"], origin=body["origin"], signature=body["signature"],
        )  # fmt: skip
        return done.new_revocation

    with ThreadPoolExecutor(8) as pool:
        fresh = list(pool.map(attempt, issued))
    assert fresh.count(True) == 1
    assert len(rows(admin_engine, "SELECT 1 FROM key_revocations")) == 1


def test_a_revocation_failure_in_the_log_revokes_nothing(
    client: TestClient, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second, cid = two_keys(client)

    def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("log is down")

    monkeypatch.setattr(surface_service.ledger_store, "append", broken)
    r = revoke(client, second, cid, first)
    assert r.status_code == 503 and code(r) == "log_unavailable"
    assert rows(admin_engine, "SELECT 1 FROM key_revocations") == []


def test_migration_0008_moves_existing_revocations_and_downgrades_back(ledger_db: Any) -> None:
    from alembic import command
    from sqlalchemy import create_engine

    from tests.integration.conftest import (
        alembic_config,
        create_database,
        drop_database,
        scratch_urls,
    )

    name, url = scratch_urls(ledger_db.server_url)
    role = "cs_mig_" + name[-8:]
    create_database(ledger_db.server_url, name)
    try:
        config = alembic_config(url, role)
        command.upgrade(config, "0007")
        engine = create_engine(url, isolation_level="AUTOCOMMIT")
        tp = "t" * 43
        with engine.connect() as conn:
            conn.execute(
                text(
                    "INSERT INTO customer_keys (customer_id, thumbprint, jwk, created_us, revoked_us) "
                    "VALUES ('cus_x', :t, '{}', 10, 20), ('cus_x', :u, '{}', 10, NULL)"
                ),
                {"t": tp, "u": "u" * 43},
            )
        command.upgrade(config, "0008")
        with engine.connect() as conn:
            moved = conn.execute(
                text("SELECT thumbprint, customer_id, revoked_us, record FROM key_revocations")
            ).all()
            assert [(r.thumbprint, r.customer_id, r.revoked_us, r.record) for r in moved] == [
                (tp, "cus_x", 20, "migrated")
            ]
            cols = {
                r[0]
                for r in conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns WHERE table_name = 'customer_keys'"
                    )
                )
            }
            assert "revoked_us" not in cols
        command.downgrade(config, "0007")
        with engine.connect() as conn:
            back = conn.execute(
                text("SELECT thumbprint, revoked_us FROM customer_keys ORDER BY thumbprint")
            ).all()
            assert [(r.thumbprint, r.revoked_us) for r in back] == [(tp, 20), ("u" * 43, None)]
        command.upgrade(config, "head")
        engine.dispose()
    finally:
        drop_database(ledger_db.server_url, name, role)


# ------------------------------------------------------------------------------------ the customer lock


def hold_customer_lock(engine: Engine, cid: str) -> Any:
    """An open transaction that holds the per-customer advisory lock; `.rollback()` releases it."""
    conn = engine.connect()
    transaction = conn.begin()
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"cs.ts.customer:{cid}"})

    class Held:
        def release(self) -> None:
            transaction.rollback()
            conn.close()

    return Held()


def blocked_until_released(engine: Engine, cid: str, work: Callable[[], Any]) -> Any:
    """Run `work` in a thread while the customer lock is held elsewhere: it must wait, then finish."""
    held = hold_customer_lock(engine, cid)
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["result"] = work()
        except Exception as error:  # noqa: BLE001 - the test reads it
            box["error"] = error

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(0.8)
    waiting = thread.is_alive()
    held.release()
    thread.join(10)
    assert waiting, "the operation did not wait for the customer lock"
    assert not thread.is_alive()
    if "error" in box:
        raise box["error"]
    return box["result"]


def test_revocation_waits_for_the_customer_lock(
    surface: TrustedSurface, client: TestClient, admin_engine: Engine
) -> None:
    first, second, cid = two_keys(client)
    ch = surface.issue_challenge("revoke_device_key")
    body = revoke_body_for(
        second, {"challenge_id": ch.challenge_id, "nonce": ch.nonce}, customer_id=cid, target=first
    )

    def work() -> Any:
        return surface.revoke(
            challenge_id=body["challenge_id"], customer_id=cid, target=body["target"],
            signer=body["signer"], origin=body["origin"], signature=body["signature"],
        )  # fmt: skip

    assert blocked_until_released(admin_engine, cid, work).new_revocation is True


def test_adding_a_key_waits_for_the_customer_lock(
    surface: TrustedSurface, client: TestClient, admin_engine: Engine
) -> None:
    first, cid = customer(client)
    new = Device()
    ch = surface.issue_challenge("register_device_key")
    body = body_for(
        new, {"challenge_id": ch.challenge_id, "nonce": ch.nonce}, customer_id=cid, authorizer=first
    )

    def work() -> Any:
        return surface.register(
            jwk=body["jwk"], challenge_id=body["challenge_id"], customer_id=cid,
            origin=body["origin"], signature=body["signature"],
            authorizer=Authorizer(first.thumbprint, body["authorizer"]["signature"]),
        )  # fmt: skip

    assert blocked_until_released(admin_engine, cid, work).new_key is True

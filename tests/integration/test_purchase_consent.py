"""Human Present approval: the customer signs the exact merchant-signed checkout (Decisions 29, 90).

Real Postgres. A Python "device" signs a consent record built here (with its own rebuild of the closed
mandate contents). The backend verifies the merchant's signature before it shows anything, rebuilds the
mandates from its own copy of the checkout, and only then signs. The issued mandates are run through
the real Merchant and Credential Provider verifiers.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient
from joserfc.jwk import ECKey
from sqlalchemy import Engine, text

from countersign.api.app import create_app
from countersign.canonical.jcs import canonicalize
from countersign.checkout.state import Status
from countersign.constraints import CheckoutConstraintEvaluator
from countersign.cp.verify import verify_payment
from countersign.merchant.authorization import AuthorizationError
from countersign.merchant.decision_log import LedgerDecisionLog
from countersign.merchant.keys import MerchantKey, generate_jwk, validate_jwk
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.policy import policy_hash
from countersign.merchant.verify import Accepted, CheckoutMandateVerifier, MerchantConfig
from countersign.trusted_surface import Refused, TrustedSurface
from countersign.trusted_surface import purchase as purchase_module
from tests.checkout_seed import seed_checkout
from tests.integration.conftest import Clock
from tests.integration.test_trusted_surface import (
    add_key,
    challenge_for,
    code,
    customer,
    revoke,
    rows,
)
from tests.merchant_support import make_checkout
from tests.surface_support import (
    ORIGIN,
    Device,
    closed_twin,
    purchase_body,
    purchase_record_for,
)

OFFER = "/trusted-surface/purchases/offer"
CONSENT = "/trusted-surface/purchases/consent"
ISSUER = "https://platform.example"


@pytest.fixture
def clock() -> Clock:
    c = Clock()
    c.now = time.time_ns() // 1000  # the checkout seed uses the wall clock
    return c


@pytest.fixture
def platform() -> ECKey:
    return ECKey.generate_key("P-256")


@pytest.fixture
def merchant_key() -> MerchantKey:
    return validate_jwk(generate_jwk())


@pytest.fixture
def surface(
    app_engine: Engine,
    clean_keys: None,
    clean_checkouts: None,
    clock: Clock,
    platform: ECKey,
    merchant_key: MerchantKey,
) -> TrustedSurface:
    return TrustedSurface(
        app_engine, public_origin=ORIGIN, clock_us=clock, platform_key=platform, issuer=ISSUER,
        merchant_key=merchant_key,
    )  # fmt: skip


@pytest.fixture
def client(app_engine: Engine, surface: TrustedSurface, clock: Clock) -> Iterator[TestClient]:
    app = create_app(
        key=validate_jwk(generate_jwk()), public_base_url=ORIGIN, engine=app_engine,
        clock_us=clock, trusted_surface=surface,
    )  # fmt: skip
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


class Shop:
    """A customer with a device key and a ready checkout."""

    def __init__(self, client: TestClient, engine: Engine, letter: str = "A") -> None:
        self.client = client
        self.engine = engine
        self.device, self.cid = customer(client)
        self.checkout = make_checkout(checkout_id="chk_" + letter * 22)
        seed_checkout(engine, self.checkout, status=Status.READY_FOR_COMPLETE)

    def offer(self, checkout_id: str | None = None) -> Any:
        return self.client.post(OFFER, json={"checkout_id": checkout_id or self.checkout.id})

    def issued(self) -> dict[str, Any]:
        return challenge_for(self.client, "consent_checkout")

    def body(self, offer: dict[str, Any] | None = None, **kw: Any) -> dict[str, Any]:
        offer = offer or self.offer().json()
        device = kw.pop("device", self.device)
        sign_with = kw.pop("sign_with", None)
        issued = kw.pop("issued", None) or self.issued()
        record = purchase_record_for(device, kw.pop("cid", self.cid), issued, offer, **kw)
        return purchase_body(device, record, sign_with=sign_with)

    def post(self, body: dict[str, Any], **headers: str) -> Any:
        return self.client.post(CONSENT, json=body, headers=headers)


@pytest.fixture
def shop(client: TestClient, app_engine: Engine) -> Shop:
    return Shop(client, app_engine)


def decode(part: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def nothing_issued(admin: Engine, response: Any) -> None:
    assert rows(admin, "SELECT 1 FROM purchase_consents") == []
    assert "mandate" not in response.text.lower() or "code" in response.json()


# ------------------------------------------------------------------------------------ the offer


def test_the_offer_shows_the_verified_terms_of_the_stored_checkout(shop: Shop) -> None:
    r = shop.offer()
    assert r.status_code == 201, r.text
    offer = r.json()
    terms = offer["terms"]
    assert terms["checkout_id"] == shop.checkout.id and terms["currency"] == "USD"
    assert terms["items"] == [
        {"id": "sku-headphones", "title": "Over-ear headphones", "quantity": 2,
         "unit_minor": 4000, "line_minor": 8000},
    ]  # fmt: skip
    assert terms["total_minor"] == 8500
    assert {"type": "total", "amount_minor": 8500} in terms["totals"]
    assert terms["merchant"] == {
        "id": "merchant-1", "name": "Countersign demo store", "website": ORIGIN,
    }  # fmt: skip
    assert len(offer["checkout_hash"]) == 43 and offer["offer_id"].startswith("off_")


def test_nothing_is_shown_when_the_merchant_signature_does_not_verify(
    shop: Shop, monkeypatch: pytest.MonkeyPatch, admin_engine: Engine
) -> None:
    def refuse(*_a: Any, **_k: Any) -> None:
        raise AuthorizationError("merchant_authorization_invalid", "forced")

    monkeypatch.setattr(purchase_module, "verify_authorization", refuse)
    r = shop.offer()
    assert r.status_code == 502 and code(r) == "merchant_authorization_invalid"
    assert "terms" not in r.text and "Over-ear" not in r.text
    assert rows(admin_engine, "SELECT 1 FROM purchase_offers") == []


def test_an_offer_for_a_missing_unready_or_expired_checkout_is_refused(
    shop: Shop, app_engine: Engine, admin_engine: Engine, clock: Clock
) -> None:
    assert code(shop.offer("chk_" + "Z" * 22)) == "checkout_unknown"
    assert code(shop.offer("nope")) == "checkout_unknown"
    other = make_checkout(checkout_id="chk_" + "B" * 22)
    seed_checkout(app_engine, other, status=Status.INCOMPLETE)
    r = shop.offer(other.id)
    assert r.status_code == 409 and code(r) == "checkout_not_ready"
    clock.now += 2 * 24 * 3600 * 1_000_000
    r = shop.offer()
    assert r.status_code == 410 and code(r) == "checkout_expired"
    assert rows(admin_engine, "SELECT 1 FROM purchase_offers") == []


# ------------------------------------------------------------------------------------ the good path


def test_consent_issues_closed_mandates_the_real_verifiers_accept(
    shop: Shop, surface: TrustedSurface, platform: ECKey, merchant_key: MerchantKey,
    app_engine: Engine, clock: Clock, admin_engine: Engine,
) -> None:  # fmt: skip
    offer = shop.offer().json()
    r = shop.post(shop.body(offer))
    assert r.status_code == 201, r.text
    out = r.json()
    cm, pm = out["checkout_mandate"], out["payment_mandate"]
    # The customer id is the sub claim of both (Decision 47) and each mandate is one link.
    for token in (cm, pm):
        assert token.count("~") == len(token.split("~")) - 1 and "~~" not in token
        assert decode(token.split(".")[1])["sub"] == shop.cid
    now_s = clock.now // 1_000_000
    public = ECKey.import_key(platform.as_dict(private=False))
    merchant = CheckoutMandateVerifier(
        MerchantConfig(
            issuer="https://merchant.example", signing_key=merchant_key,
            published_keys=[merchant_key.public_jwk], platform_key=public,
        ),
        PostgresReservationStore(app_engine, "merchant"),
        LedgerDecisionLog(app_engine, policy_hash(), clock),
        lambda: float(now_s),
        CheckoutConstraintEvaluator("merchant-1"),
    )  # fmt: skip
    assert isinstance(
        merchant.verify(mandate=cm, issued_checkout=None, current=shop.checkout), Accepted
    )
    verified = verify_payment(
        payment_token=pm, checkout_mandate=cm, current=shop.checkout, platform_key=public,
        payee_id="merchant-1", audience="credential-provider", checkout_audience="merchant",
        clock=lambda: float(now_s),
    )  # fmt: skip
    assert verified.mode == "human_present" and verified.customer_id == shop.cid
    assert verified.total.minor == 8500 and verified.session_hash == offer["checkout_hash"]
    done = rows(admin_engine, "SELECT customer_id, offer_id FROM purchase_consents")
    assert [(d.customer_id, d.offer_id) for d in done] == [(shop.cid, offer["offer_id"])]


def test_the_mandate_expiry_is_the_earlier_of_the_checkout_and_fifteen_minutes(shop: Shop) -> None:
    offer = shop.offer().json()
    issued = shop.issued()
    out = shop.post(shop.body(offer, issued=issued)).json()
    expected = min(offer["terms"]["checkout_expires_at"], int(issued["issued_at"]) + 900)
    assert out["expires_at"] == expected


# ------------------------------------------------------------------------------------ refusals


def test_a_changed_checkout_yields_no_mandate(shop: Shop, admin_engine: Engine) -> None:
    offer = shop.offer().json()
    body = shop.body(offer)
    other = make_checkout(checkout_id=shop.checkout.id, price=5000)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE checkout_sessions SET checkout = :c, version = version + 1 WHERE id = :i"),
            {"c": canonicalize(other.to_ucp()), "i": shop.checkout.id},
        )
    r = shop.post(body)
    assert r.status_code == 409 and code(r) == "checkout_changed"
    nothing_issued(admin_engine, r)


@pytest.mark.parametrize("status", ["canceled", "complete_in_progress", "incomplete"])
def test_a_checkout_that_is_no_longer_ready_yields_no_mandate(
    shop: Shop, admin_engine: Engine, status: str
) -> None:
    offer = shop.offer().json()
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE checkout_sessions SET status = :s, version = version + 1 WHERE id = :i"),
            {"s": status, "i": shop.checkout.id},
        )
    r = shop.post(shop.body(offer))
    assert r.status_code == 409 and code(r) == "checkout_not_ready"
    nothing_issued(admin_engine, r)


def test_an_expired_checkout_yields_no_mandate(
    client: TestClient, app_engine: Engine, admin_engine: Engine, clock: Clock
) -> None:
    short = Shop(client, app_engine, "C")
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE checkout_sessions SET expires_us = :e, version = version + 1 WHERE id = :i"
            ),
            {"e": clock.now + 5 * 60 * 1_000_000, "i": short.checkout.id},
        )
    offer = short.offer().json()
    clock.now += 6 * 60 * 1_000_000
    r = short.post(short.body(offer))
    assert r.status_code == 410 and code(r) == "checkout_expired"
    nothing_issued(admin_engine, r)


def test_an_offer_and_a_challenge_expire(shop: Shop, admin_engine: Engine, clock: Clock) -> None:
    offer = shop.offer().json()
    issued = shop.issued()
    clock.now += 11 * 60 * 1_000_000
    r = shop.post(shop.body(offer, issued=issued))
    assert code(r) == "challenge_expired"
    r = shop.post(shop.body(offer))  # a fresh challenge, a stale offer
    assert r.status_code == 410 and code(r) == "offer_expired"
    nothing_issued(admin_engine, r)


def test_the_stored_merchant_signature_is_verified_again_at_consent(
    shop: Shop, admin_engine: Engine, merchant_key: MerchantKey
) -> None:
    from countersign.merchant.authorization import checkout_jwt, sign_checkout
    from countersign.protocols.ucp.responses import checkout_response

    offer = shop.offer().json()
    stranger = validate_jwk(generate_jwk())
    forged = checkout_jwt(
        sign_checkout(checkout_response(shop.checkout, Status.READY_FOR_COMPLETE, 2**40), stranger)
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE purchase_offers SET checkout_jwt = :j WHERE id = :i"),
            {"j": forged, "i": offer["offer_id"]},
        )
    r = shop.post(shop.body(offer))
    assert code(r) == "merchant_authorization_invalid"
    nothing_issued(admin_engine, r)


def test_a_consent_for_another_checkout_is_refused(
    shop: Shop, client: TestClient, app_engine: Engine, admin_engine: Engine
) -> None:
    other = Shop(client, app_engine, "D")
    offer_a, offer_b = shop.offer().json(), other.offer().json()
    # Offer A's id with offer B's terms and mandates, correctly signed by the customer.
    issued = shop.issued()
    mismatched = purchase_record_for(
        shop.device, shop.cid, issued, offer_a, terms=offer_b["terms"],
        mandate=closed_twin(offer_b["terms"], offer_b["checkout_hash"], int(issued["issued_at"])),
    )  # fmt: skip
    r = shop.post(purchase_body(shop.device, mismatched))
    assert code(r) == "consent_claims_mismatch"
    # Offer A's terms but the hash of B's checkout in the mandates.
    issued = shop.issued()
    swapped = purchase_record_for(
        shop.device, shop.cid, issued, offer_a,
        mandate=closed_twin(offer_a["terms"], offer_b["checkout_hash"], int(issued["issued_at"])),
    )  # fmt: skip
    assert code(shop.post(purchase_body(shop.device, swapped))) == "consent_claims_mismatch"
    nothing_issued(admin_engine, r)


@pytest.mark.parametrize("member", ["terms", "mandate"])
def test_any_changed_member_is_refused_even_with_a_valid_signature(
    shop: Shop, admin_engine: Engine, member: str
) -> None:
    offer = shop.offer().json()
    issued = shop.issued()
    record = purchase_record_for(shop.device, shop.cid, issued, offer)
    if member == "terms":
        record["terms"]["total_minor"] = 100
    else:
        record["mandate"]["payment"]["payment_amount"]["amount"] = 100
    r = shop.post(purchase_body(shop.device, record))
    assert code(r) == "consent_claims_mismatch"
    nothing_issued(admin_engine, r)


def test_a_replayed_consent_and_a_second_consent_on_one_offer_are_refused(
    shop: Shop, admin_engine: Engine
) -> None:
    offer = shop.offer().json()
    body = shop.body(offer)
    assert shop.post(body).status_code == 201
    assert code(shop.post(body)) == "challenge_used"
    second = shop.post(shop.body(offer))  # a fresh challenge for the same offer
    assert second.status_code == 409 and code(second) == "offer_used"
    assert len(rows(admin_engine, "SELECT 1 FROM purchase_consents")) == 1


def test_a_consent_is_bound_to_its_purpose_and_origin(shop: Shop) -> None:
    offer = shop.offer().json()
    wrong_challenge = challenge_for(shop.client, "consent_open_mandates")
    assert code(shop.post(shop.body(offer, issued=wrong_challenge))) == "challenge_purpose_mismatch"
    assert (
        code(
            shop.post(
                shop.body(offer, override={"purpose": "countersign.consent.open-mandates.v1"})
            )
        )
        == "consent_purpose_mismatch"
    )
    assert (
        code(shop.post(shop.body(offer, origin="https://evil.example.test"))) == "origin_mismatch"
    )
    assert (
        code(shop.post(shop.body(offer), Origin="https://evil.example.test")) == "origin_mismatch"
    )
    assert shop.post(shop.body(offer), Origin=ORIGIN).status_code == 201


def test_an_unregistered_revoked_or_foreign_device_key_cannot_approve(
    shop: Shop, client: TestClient, admin_engine: Engine
) -> None:
    offer = shop.offer().json()
    stranger = Device()
    r = shop.post(shop.body(offer, device=stranger))
    assert r.status_code == 403 and code(r) == "device_key_unknown"
    other, _ = customer(client)
    assert code(shop.post(shop.body(offer, device=other))) == "device_key_customer_mismatch"
    assert code(shop.post(shop.body(offer, sign_with=other))) == "consent_signature_invalid"
    second = add_key(client, shop.device, shop.cid)
    assert revoke(client, second, shop.cid, shop.device).status_code == 201
    r = shop.post(shop.body(offer))
    assert r.status_code == 403 and code(r) == "device_key_revoked"
    nothing_issued(admin_engine, r)


def test_the_time_rules_of_the_record_are_enforced(shop: Shop, clock: Clock) -> None:
    offer = shop.offer().json()
    assert code(shop.post(shop.body(offer, lifetime=601))) == "consent_time_invalid"
    assert code(shop.post(shop.body(offer, lifetime=0))) == "consent_time_invalid"
    issued = shop.issued()
    assert (
        code(
            shop.post(
                shop.body(
                    offer, issued=issued, override={"issued_at": int(issued["issued_at"]) + 5}
                )
            )
        )
        == "consent_time_invalid"
    )
    issued = shop.issued()
    clock.now += 4 * 60 * 1_000_000
    assert shop.post(shop.body(offer, issued=issued)).status_code == 201


def test_malformed_requests_are_refused_and_logged(
    shop: Shop, admin_engine: Engine, client: TestClient
) -> None:
    for body in ({}, {"record": {}, "signature": "x"}, {"record": [], "signature": "x"}):
        r = shop.post(body)
        assert r.status_code == 400
    r = client.post(CONSENT, content="{", headers={"Content-Type": "application/json"})
    assert code(r) == "malformed_request"
    logged = rows(admin_engine, "SELECT kind FROM decision_log WHERE kind = 'ts.purchase.refused'")
    assert len(logged) >= 4


def test_without_the_platform_key_there_is_no_mandate(
    app_engine: Engine, clean_keys: None, clean_checkouts: None, clock: Clock,
    merchant_key: MerchantKey,
) -> None:  # fmt: skip
    surface = TrustedSurface(
        app_engine, public_origin=ORIGIN, clock_us=clock, merchant_key=merchant_key
    )
    app = create_app(
        key=validate_jwk(generate_jwk()), public_base_url=ORIGIN, engine=app_engine,
        clock_us=clock, trusted_surface=surface,
    )  # fmt: skip
    with TestClient(app, raise_server_exceptions=False) as c:
        s = Shop(c, app_engine)
        assert code(s.post(s.body())) == "signing_unavailable"


def test_exactly_one_of_many_simultaneous_consents_on_one_offer_wins(
    shop: Shop, surface: TrustedSurface, admin_engine: Engine
) -> None:
    offer = shop.offer().json()
    bodies = [shop.body(offer) for _ in range(8)]
    gate = threading.Barrier(len(bodies))

    def attempt(body: dict[str, Any]) -> str:
        gate.wait()
        try:
            surface.consent_purchase(record=body["record"], signature=body["signature"])
        except Refused as error:
            return error.code
        return "ok"

    with ThreadPoolExecutor(len(bodies)) as pool:
        results = list(pool.map(attempt, bodies))
    assert results.count("ok") == 1 and set(results) - {"ok"} == {"offer_used"}, results
    assert len(rows(admin_engine, "SELECT 1 FROM purchase_consents")) == 1

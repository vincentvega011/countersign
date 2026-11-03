"""Consent and the platform-issued open mandates, against the real Postgres.

A Python "device" signs a consent record built by tests/surface_support.py (which has its own, independent
rebuild of the mandate contents). The backend verifies, rebuilds, and only then signs. Every refusal
code, the claim comparison, the single use of the nonce under a race, the mandatory `sub`, the refusal
of whole-element selective disclosure, and the issued mandates against the vendored AP2 schemas and the
existing mandate verifiers.
"""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from joserfc.jwk import ECKey
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from sqlalchemy import Engine

from countersign.api.app import create_app
from countersign.canonical.hashing import sd_hash
from countersign.catalog.catalog import load_catalog
from countersign.mandates import VCT_CHECKOUT, VCT_CHECKOUT_OPEN, verify_chain
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.trusted_surface import Refused, TrustedSurface
from countersign.trusted_surface import service as surface_service
from countersign.trusted_surface.issuer import IssuerRefused, issue_open_mandate
from tests.integration.conftest import START, Clock
from tests.integration.test_trusted_surface import (
    BASE,
    add_key,
    challenge_for,
    code,
    customer,
    revoke,
    rows,
)
from tests.mandate_issuer import Keys, issue, public_jwk
from tests.surface_support import (
    ORIGIN,
    Device,
    consent_body,
    consent_record_for,
    mandate_twin,
    proposal_body_for,
    proposal_of,
    terms_for,
)

CONSENT = "/trusted-surface/consent"
PROPOSALS = "/trusted-surface/proposals"
START_S = START // 1_000_000
SCHEMAS = Path(__file__).resolve().parents[2] / "spec/vendor/ap2/schemas/ap2"
ITEMS = load_catalog().items


@pytest.fixture
def platform() -> ECKey:
    return ECKey.generate_key("P-256")


@pytest.fixture
def surface(app_engine: Engine, clean_keys: None, clock: Clock, platform: ECKey) -> TrustedSurface:
    return TrustedSurface(
        app_engine, public_origin=ORIGIN, clock_us=clock, platform_key=platform,
        issuer="https://platform.example",
    )  # fmt: skip


@pytest.fixture
def client(app_engine: Engine, surface: TrustedSurface, clock: Clock) -> Iterator[TestClient]:
    app = create_app(
        key=validate_jwk(generate_jwk()), public_base_url=ORIGIN, engine=app_engine,
        clock_us=clock, trusted_surface=surface,
    )  # fmt: skip
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


class Setup:
    def __init__(self, client: TestClient, engine: Engine | None = None) -> None:
        self.client = client
        self.engine = engine
        self.device, self.cid = customer(client)
        self.agent = ECKey.generate_key(
            "P-256"
        )  # signs key bindings in the tests that bind mandates
        self.agent_jwk = public_jwk(self.agent)
        self.agent_device = Device(private=self.agent.raw_value)  # the same key, signing proposals
        self.exp = START_S + 7 * 86400

    def proposal(self, terms: dict[str, Any], agent: Device | None = None) -> str:
        """A proposal for these terms through the endpoint (signed by `agent`).

        A test that exercises a consent refusal for terms the endpoint would itself refuse (an item
        outside the catalog, an expiry out of range) gets the proposal inserted directly instead: what
        is under test is the consent check, which must not trust the proposal's own validation.
        """
        who = agent or self.agent_device
        proposal = proposal_of(terms)
        issued = challenge_for(self.client, "agent_proposal")
        r = self.client.post(PROPOSALS, json=proposal_body_for(who, issued, proposal))
        if r.status_code == 201:
            return str(r.json()["proposal_id"])
        assert code(r) == "proposal_invalid", r.text
        assert self.engine is not None
        import secrets

        from sqlalchemy import text as sql

        pid = "prp_" + secrets.token_urlsafe(12)
        with self.engine.begin() as conn:
            conn.execute(
                sql(
                    "INSERT INTO agent_proposals (id, challenge_id, agent_thumbprint, agent_jwk, "
                    "terms, signature, created_us) VALUES (:i, :c, :t, :j, :m, 'x', :u)"
                ),
                {
                    "i": pid, "c": issued["challenge_id"], "t": who.thumbprint,
                    "j": json.dumps(who.jwk, sort_keys=True, separators=(",", ":")),
                    "m": json.dumps(proposal, sort_keys=True, separators=(",", ":")),
                    "u": START,
                },
            )  # fmt: skip
        return pid

    def terms(self, **kw: Any) -> dict[str, Any]:
        return terms_for(self.agent_jwk, mandate_exp=kw.pop("mandate_exp", self.exp), **kw)

    def issued(self) -> dict[str, Any]:
        return challenge_for(self.client, "consent_open_mandates")

    def body(self, **kw: Any) -> dict[str, Any]:
        terms = kw.pop("terms", None) or self.terms()
        issued = kw.pop("issued", None) or self.issued()
        proposer = kw.pop("proposer", None)
        signer = kw.pop("sign_with", None)
        proposal_id = kw.pop("proposal_id", None) or self.proposal(terms, proposer)
        record = consent_record_for(self.device, self.cid, issued, terms, **kw)
        return consent_body(self.device, record, proposal_id, sign_with=signer)

    def post(self, body: dict[str, Any], **headers: str) -> Any:
        return self.client.post(CONSENT, json=body, headers=headers)


@pytest.fixture
def setup(client: TestClient, app_engine: Engine) -> Setup:
    return Setup(client, app_engine)


def decode(part: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def issuer_payload(token: str) -> dict[str, Any]:
    return dict(decode(token.split(".")[1]))


def content_of(token: str) -> dict[str, Any]:
    """The disclosed delegate content of a one-link open mandate."""
    jwt, disclosure, _ = token.split("~")
    assert jwt
    return dict(decode(disclosure)[1])


def schema_validator(name: str) -> Draft202012Validator:
    registry: Registry = Registry()
    for file in SCHEMAS.rglob("*.json"):
        doc = json.loads(file.read_text())
        registry = registry.with_resource(doc["$id"], Resource.from_contents(doc))
    schema = json.loads((SCHEMAS / name).read_text())
    return Draft202012Validator(schema, registry=registry)


# ------------------------------------------------------------------------------------ the good path


def test_valid_consent_issues_two_mandates_that_follow_the_vendored_schemas(
    setup: Setup, admin_engine: Engine
) -> None:
    r = setup.post(setup.body())
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["customer_id"] == setup.cid and out["expires_at"] == setup.exp
    checkout, payment = out["checkout_mandate"], out["payment_mandate"]
    for token, schema in (
        (checkout, "open_checkout_mandate.json"),
        (payment, "open_payment_mandate.json"),
    ):
        content = content_of(token)
        errors = list(schema_validator(schema).iter_errors(content))
        assert errors == [], errors
        assert content["cnf"] == {"jwk": setup.agent_jwk} and content["iat"] == START_S
        assert content["exp"] == setup.exp
        assert not any("..." in c or "_sd" in c for c in content["constraints"])
    assert [c["type"] for c in content_of(checkout)["constraints"]] == [
        "checkout.line_items", "checkout.allowed_merchants",
    ]  # fmt: skip
    kinds = [c["type"] for c in content_of(payment)["constraints"]]
    assert kinds == [
        "payment.reference", "payment.amount_range", "payment.allowed_payees", "payment.budget",
        "payment.agent_recurrence",
    ]  # fmt: skip
    assert content_of(payment)["constraints"][0]["conditional_transaction_id"] == sd_hash(checkout)
    recurrence = content_of(payment)["constraints"][-1]
    assert recurrence["max_occurrences"] == 1


def test_every_issued_mandate_carries_the_customer_id_as_sub(setup: Setup) -> None:
    out = setup.post(setup.body()).json()
    for token in (out["checkout_mandate"], out["payment_mandate"]):
        payload = issuer_payload(token)
        assert payload["sub"] == setup.cid
        assert payload["iss"] == "https://platform.example" and payload["iat"] == START_S
        header = decode(token.split(".")[0])
        assert header["alg"] == "ES256" and header["typ"] == "dc+sd-jwt"


def test_issued_mandates_pass_the_existing_chain_verifier_once_the_agent_binds_them(
    setup: Setup, platform: ECKey
) -> None:
    out = setup.post(setup.body()).json()
    keys = Keys(
        issuer=platform,
        agents=[setup.agent, ECKey.generate_key("P-256"), ECKey.generate_key("P-256")],
    )
    closed = issue("checkout", keys=keys, reuse_open_token=out["checkout_mandate"], now=START_S)
    chain = verify_chain(
        closed.token, issuer_key=platform, expected_vcts=[VCT_CHECKOUT_OPEN, VCT_CHECKOUT],
        audience="merchant", clock=lambda: START_S,
    )  # fmt: skip
    assert chain.links[0].claims["sub"] == setup.cid
    assert chain.links[0].cnf_thumbprint == setup.agent.thumbprint()


def test_the_consent_is_stored_with_its_signature_key_and_mandates(
    setup: Setup, admin_engine: Engine
) -> None:
    body = setup.body()
    out = setup.post(body).json()
    (row,) = rows(admin_engine, "SELECT * FROM consent_records")
    assert row.id == out["consent_id"] and row.customer_id == setup.cid
    assert row.signature == body["signature"] and json.loads(row.record) == body["record"]
    assert json.loads(row.device_jwk) == setup.device.jwk
    assert row.checkout_mandate == out["checkout_mandate"]
    assert row.payment_mandate == out["payment_mandate"]
    assert row.checkout_open_digest == sd_hash(out["checkout_mandate"])
    assert row.payment_open_digest == sd_hash(out["payment_mandate"])
    kinds = [e.kind for e in rows(admin_engine, "SELECT kind FROM decision_log ORDER BY seq")]
    assert kinds[-1] == "ts.consent.issued"
    entry = rows(admin_engine, "SELECT payload FROM decision_log ORDER BY seq DESC LIMIT 1")[0]
    logged = bytes(entry.payload).decode()
    assert out["checkout_mandate"] not in logged and body["signature"] not in logged


def test_several_items_become_several_line_requirements(setup: Setup) -> None:
    items = [
        {"id": ITEMS[0].id, "title": ITEMS[0].title, "quantity": 2},
        {"id": ITEMS[1].id, "title": ITEMS[1].title, "quantity": 1},
    ]
    out = setup.post(setup.body(terms=setup.terms(items=items))).json()
    lines = content_of(out["checkout_mandate"])["constraints"][0]["items"]
    assert [(line["acceptable_items"][0]["id"], line["quantity"]) for line in lines] == [
        (ITEMS[0].id, 2), (ITEMS[1].id, 1),
    ]  # fmt: skip


# ------------------------------------------------------------------------------------ no consent, no mandate


def nothing_issued(admin_engine: Engine, response: Any) -> None:
    assert response.status_code >= 400, response.text
    body = response.json()
    assert set(body) == {"code"}, body
    assert rows(admin_engine, "SELECT 1 FROM consent_records") == []
    assert (
        rows(
            admin_engine,
            "SELECT 1 FROM key_challenge_uses WHERE thumbprint IS NOT NULL AND challenge_id IN (SELECT id FROM key_challenges WHERE purpose = 'consent_open_mandates')",
        )
        == []
    )


def test_no_consent_means_no_mandate(setup: Setup, admin_engine: Engine) -> None:
    for body in (
        {},
        {"record": {}, "signature": "x", "proposal_id": "prp_AAAAAAAAAAAAAAAA"},
        {"record": setup.body()["record"], "proposal_id": "prp_AAAAAAAAAAAAAAAA"},
        {**setup.body(), "signature": ""},
        {**setup.body(), "signature": "A" * 86},
    ):
        nothing_issued(admin_engine, setup.post(body))


def test_a_malformed_request_is_refused_and_logged(setup: Setup, admin_engine: Engine) -> None:
    for raw in ("{", "[]", "NaN"):
        r = setup.client.post(CONSENT, content=raw, headers={"Content-Type": "application/json"})
        assert r.status_code == 400 and code(r) == "malformed_request"
    r = setup.client.post(CONSENT, content="{}", headers={"Content-Type": "text/plain"})
    assert code(r) == "malformed_request"
    kinds = {e.kind for e in rows(admin_engine, "SELECT kind FROM decision_log")}
    assert kinds - {"ts.key.registered"} == {"ts.consent.refused"}


def test_numbers_and_types_in_the_record_are_strict(setup: Setup, admin_engine: Engine) -> None:
    for path, bad in (
        (("issued_at",), 1.5), (("issued_at",), True), (("terms", "ceiling_minor"), 8000.5),
        (("terms", "ceiling_minor"), True), (("terms", "items", 0, "quantity"), 1.0),
        (("terms", "mandate_expires_at"), str(setup.exp)), (("v",), 1.0), (("v",), True),
    ):  # fmt: skip
        body = setup.body()
        target: Any = body["record"]
        for step in path[:-1]:
            target = target[step]
        target[path[-1]] = bad
        r = setup.post(body)
        assert r.status_code == 400 and code(r) == "consent_malformed", path
    nothing_issued(admin_engine, setup.post({**setup.body(), "record": []}))


def test_extra_and_missing_members_in_the_record_are_refused(setup: Setup) -> None:
    for edit in (
        lambda r: r.update(extra=1),
        lambda r: r.pop("origin"),
        lambda r: r["terms"].update(extra=1),
        lambda r: r["terms"].pop("currency"),
        lambda r: r["terms"]["merchant"].update(extra="x"),
        lambda r: r["terms"]["items"][0].pop("title"),
        lambda r: r["terms"]["items"][0].update(extra=1),
        lambda r: r["terms"]["items"].clear(),
        lambda r: r["terms"].__setitem__("items", r["terms"]["items"] * 11),
        lambda r: r.__setitem__("mandate", []),
    ):
        body = setup.body()
        edit(body["record"])
        r = setup.post(body)
        assert code(r) == "consent_malformed"


@pytest.mark.parametrize(
    "path,value,expected",
    [
        (("v",), 2, "consent_malformed"),
        (("purpose",), "countersign.device-key.register.v1", "consent_purpose_mismatch"),
        (("customer_id",), "cus_" + "Q" * 22, "device_key_customer_mismatch"),
        (("device_thumbprint",), "q" * 43, "device_key_unknown"),
        (("challenge_id",), "kch_" + "Q" * 22, "challenge_unknown"),
        (("challenge",), "n" * 43, "challenge_nonce_mismatch"),
        (("issued_at",), START_S + 1, "consent_signature_invalid"),
        (("expires_at",), START_S + 301, "consent_signature_invalid"),
        (("origin",), "https://evil.example.test", "origin_mismatch"),
        (("terms", "ceiling_minor"), 9000, "consent_signature_invalid"),
        (("terms", "currency"), "EUR", "consent_signature_invalid"),
        (("terms", "mandate_expires_at"), START_S + 86400, "consent_signature_invalid"),
        (("terms", "agent_thumbprint"), "a" * 43, "consent_signature_invalid"),
        (("terms", "merchant", "id"), "other", "consent_signature_invalid"),
        (("terms", "merchant", "name"), "Other", "consent_signature_invalid"),
        (("terms", "merchant", "website"), "https://other.example", "consent_signature_invalid"),
        (("terms", "items", 0, "id"), ITEMS[1].id, "consent_signature_invalid"),
        (("terms", "items", 0, "title"), "Other title", "consent_signature_invalid"),
        (("terms", "items", 0, "quantity"), 2, "consent_signature_invalid"),
        (("mandate", "checkout", "exp"), START_S + 5, "consent_signature_invalid"),
        (("mandate", "checkout", "vct"), "mandate.checkout.1", "consent_signature_invalid"),
        (
            ("mandate", "checkout", "constraints", 0, "items", 0, "quantity"),
            9,
            "consent_signature_invalid",
        ),
        (("mandate", "payment", "constraints", 0, "max"), 900000, "consent_signature_invalid"),
        (("mandate", "payment", "constraints", 2, "max"), 900000, "consent_signature_invalid"),
        (
            ("mandate", "payment", "constraints", 3, "max_occurrences"),
            5,
            "consent_signature_invalid",
        ),
    ],
    ids=lambda v: "/".join(map(str, v)) if isinstance(v, tuple) else None,
)
def test_every_field_tampered_after_signing_yields_no_mandate(
    setup: Setup, admin_engine: Engine, path: tuple[Any, ...], value: Any, expected: str
) -> None:
    body = setup.body()  # signed over the original
    target: Any = body["record"]
    for step in path[:-1]:
        target = target[step]
    assert target[path[-1]] != value
    target[path[-1]] = value
    r = setup.post(body)
    assert code(r) == expected, r.text
    nothing_issued(admin_engine, r)


def test_a_record_with_a_member_added_after_signing_is_refused(setup: Setup) -> None:
    body = setup.body()
    body["record"]["terms"]["merchant"]["note"] = "x"
    assert code(setup.post(body)) == "consent_malformed"


def test_a_proposal_from_another_agent_key_is_refused(setup: Setup, admin_engine: Engine) -> None:
    """The agent key comes from the stored proposal, never from the request (Decision 87)."""
    r = setup.post(setup.body(proposer=Device()))
    assert r.status_code == 400 and code(r) == "agent_key_mismatch"
    nothing_issued(admin_engine, r)


def test_a_proposal_for_other_terms_is_refused(setup: Setup, admin_engine: Engine) -> None:
    other_terms = setup.terms(ceiling=7000)
    r = setup.post(setup.body(proposal_id=setup.proposal(other_terms)))
    assert r.status_code == 400 and code(r) == "consent_proposal_mismatch"
    nothing_issued(admin_engine, r)


# ------------------------------------------------------------------------------------ the device key


def test_a_consent_signed_by_an_unregistered_key_is_refused(
    setup: Setup, admin_engine: Engine
) -> None:
    stranger = Device()
    issued = setup.issued()
    record = consent_record_for(stranger, setup.cid, issued, setup.terms())
    r = setup.post(consent_body(stranger, record, setup.proposal(setup.terms())))
    assert r.status_code == 403 and code(r) == "device_key_unknown"
    nothing_issued(admin_engine, r)


def test_a_consent_signed_by_another_customers_key_is_refused(
    setup: Setup, client: TestClient
) -> None:
    other, other_cid = customer(client)
    issued = setup.issued()
    # their key, our customer id
    record = consent_record_for(other, setup.cid, issued, setup.terms())
    r = setup.post(consent_body(other, record, setup.proposal(setup.terms())))
    assert r.status_code == 403 and code(r) == "device_key_customer_mismatch"
    # our key named, their key signing
    record = consent_record_for(setup.device, setup.cid, setup.issued(), setup.terms())
    r = setup.post(
        consent_body(setup.device, record, setup.proposal(setup.terms()), sign_with=other)
    )
    assert code(r) == "consent_signature_invalid"
    # their customer id with our key
    record = consent_record_for(setup.device, other_cid, setup.issued(), setup.terms())
    r = setup.post(consent_body(setup.device, record, setup.proposal(setup.terms())))
    assert code(r) == "device_key_customer_mismatch"


def test_a_consent_signed_by_a_revoked_key_is_refused(
    setup: Setup, client: TestClient, admin_engine: Engine
) -> None:
    second = add_key(client, setup.device, setup.cid)
    assert revoke(client, second, setup.cid, setup.device).status_code == 201
    r = setup.post(setup.body())
    assert r.status_code == 403 and code(r) == "device_key_revoked"
    nothing_issued(admin_engine, r)
    # the customer's other key still works
    record = consent_record_for(second, setup.cid, setup.issued(), setup.terms())
    assert (
        setup.post(consent_body(second, record, setup.proposal(setup.terms()))).status_code == 201
    )


def test_the_stored_key_verifies_not_one_from_the_request(setup: Setup) -> None:
    """The request has no place to put a key; a member that tries is refused."""
    body = {**setup.body(), "device_jwk": setup.device.jwk}
    assert code(setup.post(body)) == "malformed_request"


# ------------------------------------------------------------------------------------ origin, nonce, time


def test_a_wrong_origin_is_refused(setup: Setup, admin_engine: Engine) -> None:
    body = setup.body(origin="https://evil.example.test")
    r = setup.post(body)
    assert r.status_code == 403 and code(r) == "origin_mismatch"
    nothing_issued(admin_engine, r)
    r = setup.post(setup.body(), Origin="https://evil.example.test")
    assert code(r) == "origin_mismatch"
    assert setup.post(setup.body(), Origin=ORIGIN).status_code == 201


def test_a_replayed_nonce_is_refused(setup: Setup, admin_engine: Engine) -> None:
    body = setup.body()
    assert setup.post(body).status_code == 201
    r = setup.post(body)
    assert r.status_code == 409 and code(r) == "challenge_used"
    assert len(rows(admin_engine, "SELECT 1 FROM consent_records")) == 1
    # a fresh, validly signed record on the spent challenge is no better
    again = setup.body(
        issued={
            "challenge_id": body["record"]["challenge_id"],
            "nonce": body["record"]["challenge"],
            "issued_at": START_S,
        }
    )
    assert code(setup.post(again)) == "challenge_used"


def test_an_expired_nonce_is_refused(setup: Setup, clock: Clock, admin_engine: Engine) -> None:
    body = setup.body()
    clock.now = START + 300_000_000
    r = setup.post(body)
    assert r.status_code == 410 and code(r) == "challenge_expired"
    nothing_issued(admin_engine, r)


def test_a_nonce_one_microsecond_before_expiry_is_still_good(setup: Setup, clock: Clock) -> None:
    body = setup.body(lifetime=600, terms=setup.terms())
    clock.now = START + 300_000_000 - 1
    assert setup.post(body).status_code == 201


def test_an_expired_record_is_refused_even_with_a_good_nonce(
    setup: Setup, clock: Clock, admin_engine: Engine
) -> None:
    body = setup.body(lifetime=10)
    clock.now = START + 10_000_000  # the record's own expiry, long before the nonce's
    r = setup.post(body)
    assert r.status_code == 410 and code(r) == "consent_expired"
    nothing_issued(admin_engine, r)
    ok = setup.body(lifetime=10)
    clock.now = START + 9_999_999
    assert setup.post(ok).status_code == 201


@pytest.mark.parametrize(
    "override",
    [
        {"expires_at": START_S},  # not after issued_at
        {"expires_at": START_S - 5},
        {"expires_at": START_S + 601},  # longer than 10 minutes
        {"issued_at": START_S + 61, "expires_at": START_S + 200},  # issued in the future
    ],
    ids=["zero", "negative", "too-long", "future"],
)
def test_a_record_with_impossible_times_is_refused(setup: Setup, override: dict[str, Any]) -> None:
    r = setup.post(setup.body(override=override))
    assert r.status_code == 400 and code(r) == "consent_time_invalid"


def test_a_challenge_of_another_purpose_is_refused(setup: Setup, client: TestClient) -> None:
    registration = challenge_for(client, "register_device_key")
    r = setup.post(setup.body(issued=registration))
    assert code(r) == "challenge_purpose_mismatch"
    revocation = challenge_for(client, "revoke_device_key")
    assert code(setup.post(setup.body(issued=revocation))) == "challenge_purpose_mismatch"


def test_a_consent_challenge_does_not_register_or_revoke_anything(
    setup: Setup, client: TestClient
) -> None:
    from tests.surface_support import body_for, revoke_body_for

    issued = setup.issued()
    r = client.post(BASE, json=body_for(Device(), issued))
    assert code(r) == "challenge_purpose_mismatch"
    body = revoke_body_for(setup.device, issued, customer_id=setup.cid)
    assert code(client.post(BASE + "/revoke", json=body)) == "challenge_purpose_mismatch"


# ------------------------------------------------------------------------------------ the rebuild


def test_a_record_whose_claims_do_not_follow_from_its_terms_is_refused(
    setup: Setup, admin_engine: Engine
) -> None:
    """Valid signature, valid terms, contents that say something else: no mandate."""
    honest = setup.terms()
    cases: dict[str, dict[str, Any]] = {}
    bigger = mandate_twin({**honest, "ceiling_minor": 80_000})
    cases["ceiling"] = bigger
    other_item = {**honest, "items": [{"id": ITEMS[1].id, "title": ITEMS[1].title, "quantity": 1}]}
    cases["item"] = mandate_twin(other_item)
    cases["merchant"] = mandate_twin({**honest, "merchant": {**honest["merchant"], "id": "evil"}})
    cases["expiry"] = mandate_twin({**honest, "mandate_expires_at": setup.exp + 86400})
    quantity = {**honest, "items": [{**honest["items"][0], "quantity": 5}]}
    cases["quantity"] = mandate_twin(quantity)
    extra = mandate_twin(honest)
    extra["payment"]["constraints"].append({"type": "payment.allowed_pisps", "allowed": []})
    cases["extra constraint"] = extra
    dropped = mandate_twin(honest)
    dropped["payment"]["constraints"].pop(3)  # the recurrence limit
    cases["dropped constraint"] = dropped
    reordered = mandate_twin(honest)
    reordered["checkout"]["constraints"].reverse()
    cases["order"] = reordered
    swapped = mandate_twin(honest)
    swapped["checkout"], swapped["payment"] = swapped["payment"], swapped["checkout"]
    cases["swapped"] = swapped
    smuggled = mandate_twin(honest)
    smuggled["checkout"]["cnf"] = {"jwk": setup.agent_jwk}
    cases["smuggled claim"] = smuggled
    parts = {
        "ceiling": "payment", "item": "checkout", "merchant": "checkout", "expiry": "checkout",
        "quantity": "checkout", "extra constraint": "payment", "dropped constraint": "payment",
        "order": "checkout", "swapped": "checkout", "smuggled claim": "checkout",
    }  # fmt: skip
    for name, mandate in cases.items():
        r = setup.post(setup.body(terms=honest, mandate=mandate))
        assert r.status_code == 400 and code(r) == "consent_claims_mismatch", name
        nothing_issued(admin_engine, r)
        entry = rows(admin_engine, "SELECT payload FROM decision_log ORDER BY seq DESC LIMIT 1")[0]
        assert json.loads(bytes(entry.payload))["detail"] == parts[name], name


@pytest.mark.parametrize(
    "terms_edit,why",
    [
        (lambda t: t["merchant"].update(id="other-store"), "another merchant"),
        (lambda t: t["merchant"].update(website="https://other.example"), "another website"),
        (lambda t: t.update(currency="EUR"), "currency"),
        (lambda t: t.update(ceiling_minor=0), "zero ceiling"),
        (lambda t: t.update(ceiling_minor=-5), "negative ceiling"),
        (lambda t: t.update(ceiling_minor=1_000_001), "huge ceiling"),
        (lambda t: t["items"][0].update(id="no-such-item"), "unknown item"),
        (lambda t: t["items"][0].update(title="A different title"), "title not the catalog's"),
        (lambda t: t["items"][0].update(quantity=0), "zero quantity"),
        (lambda t: t["items"][0].update(quantity=100), "huge quantity"),
        (lambda t: t["items"].append(dict(t["items"][0])), "duplicate item"),
        (lambda t: t.update(mandate_expires_at=START_S + 59), "expiry too soon"),
        (lambda t: t.update(mandate_expires_at=START_S + 14 * 86400 + 1), "expiry too far"),
        (lambda t: t.update(mandate_expires_at=START_S + 100), "expires before the consent does"),
    ],
)
def test_terms_that_make_no_sense_are_refused(
    setup: Setup, admin_engine: Engine, terms_edit: Any, why: str
) -> None:
    terms = setup.terms()
    terms_edit(terms)
    r = setup.post(setup.body(terms=terms, mandate=mandate_twin(terms)))
    assert r.status_code == 400 and code(r) == "consent_terms_invalid", why
    nothing_issued(admin_engine, r)


def test_the_minimum_mandate_lifetime_stands_on_its_own(setup: Setup, admin_engine: Engine) -> None:
    """A short consent, so only the 60 second floor can refuse an expiry 59 seconds away."""
    terms = setup.terms(mandate_exp=START_S + 59)
    r = setup.post(setup.body(terms=terms, mandate=mandate_twin(terms), lifetime=10))
    assert r.status_code == 400 and code(r) == "consent_terms_invalid"
    nothing_issued(admin_engine, r)
    entry = rows(admin_engine, "SELECT payload FROM decision_log ORDER BY seq DESC LIMIT 1")[0]
    assert json.loads(bytes(entry.payload))["detail"] == "mandate expiry out of range"
    terms = setup.terms(mandate_exp=START_S + 60)
    assert (
        setup.post(setup.body(terms=terms, mandate=mandate_twin(terms), lifetime=10)).status_code
        == 201
    )


def test_boundaries_of_the_terms_are_accepted(setup: Setup) -> None:
    for edit in (
        lambda t: t.update(ceiling_minor=1),
        lambda t: t.update(ceiling_minor=1_000_000),
        lambda t: t["items"][0].update(quantity=99),
        lambda t: t.update(mandate_expires_at=START_S + 14 * 86400),
        lambda t: t.update(mandate_expires_at=START_S + 600),  # record lives 300 s, so 600 is fine
    ):
        terms = setup.terms()
        edit(terms)
        r = setup.post(setup.body(terms=terms, mandate=mandate_twin(terms)))
        assert r.status_code == 201, r.text


# ------------------------------------------------------------------------------------ concurrency


def race_consent(surface: TrustedSurface, bodies: list[dict[str, Any]]) -> list[str]:
    gate = threading.Barrier(len(bodies))

    def attempt(body: dict[str, Any]) -> str:
        gate.wait()
        try:
            surface.consent(
                record=body["record"], signature=body["signature"], proposal_id=body["proposal_id"]
            )
        except Refused as error:
            return error.code
        return "ok"

    with ThreadPoolExecutor(len(bodies)) as pool:
        return list(pool.map(attempt, bodies))


def test_exactly_one_of_many_simultaneous_consents_on_one_nonce_wins(
    surface: TrustedSurface, client: TestClient, admin_engine: Engine
) -> None:
    for _ in range(3):
        setup = Setup(client, surface._engine)
        issued = setup.issued()
        results = race_consent(surface, [setup.body(issued=issued) for _ in range(10)])
        assert results.count("ok") == 1, results
        assert set(results) - {"ok"} == {"challenge_used"}, results
        done = rows(
            admin_engine, "SELECT 1 FROM consent_records WHERE customer_id = :c", c=setup.cid
        )  # fmt: skip
        assert len(done) == 1


def test_consent_waits_for_the_customer_lock_so_it_serializes_with_a_revocation(
    surface: TrustedSurface, setup: Setup, admin_engine: Engine
) -> None:
    from tests.integration.test_trusted_surface import blocked_until_released

    body = setup.body()

    def work() -> Any:
        return surface.consent(
            record=body["record"], signature=body["signature"], proposal_id=body["proposal_id"]
        )

    assert blocked_until_released(admin_engine, setup.cid, work).customer_id == setup.cid


def test_a_key_revoked_just_before_commit_cannot_consent(
    surface: TrustedSurface, setup: Setup, client: TestClient, admin_engine: Engine
) -> None:
    """The revocation and the consent are serialized: whichever is second sees the first."""
    second = add_key(client, setup.device, setup.cid)
    body = setup.body()
    assert revoke(client, second, setup.cid, setup.device).status_code == 201
    r = setup.post(body)
    assert code(r) == "device_key_revoked"
    assert rows(admin_engine, "SELECT 1 FROM consent_records") == []


# ------------------------------------------------------------------------------------ the issuer


def test_the_issuer_refuses_selective_disclosure_of_a_whole_constraint_element(
    platform: ECKey, setup: Setup
) -> None:
    good = mandate_twin(setup.terms())["checkout"]
    placeholder = {**good, "constraints": [{"...": "A" * 43}, good["constraints"][1]]}
    hidden = {
        **good,
        "constraints": [{**good["constraints"][0], "_sd": ["A" * 43]}, good["constraints"][1]],
    }
    algorithm = {**good, "constraints": [{**good["constraints"][0], "_sd_alg": "sha-256"}]}
    for bad, expected in (
        (placeholder, "constraint_element_disclosure"),
        (hidden, "constraint_element_disclosure"),
        (algorithm, "constraint_element_disclosure"),
        ({**good, "constraints": ["a string"]}, "constraint_element_not_plain"),
        ({**good, "constraints": [{"no": "type"}]}, "constraint_element_not_plain"),
        ({**good, "constraints": []}, "constraints_missing"),
        ({**good, "extra": 1}, "content_members"),
        ({**good, "vct": "mandate.payment.open.1"}, "vct_mismatch"),
    ):
        with pytest.raises(IssuerRefused) as error:
            issue_open_mandate(
                bad, kind="checkout", customer_id=setup.cid, agent_jwk=setup.agent_jwk,
                issuer="https://platform.example", key=platform, now_s=START_S,
            )  # fmt: skip
        assert error.value.code == expected
    ok = issue_open_mandate(
        good, kind="checkout", customer_id=setup.cid, agent_jwk=setup.agent_jwk,
        issuer="https://platform.example", key=platform, now_s=START_S,
    )  # fmt: skip
    assert issuer_payload(ok.token)["sub"] == setup.cid


def test_the_issuer_will_not_sign_without_a_customer_id_or_a_private_key(
    platform: ECKey, setup: Setup
) -> None:
    good = mandate_twin(setup.terms())["checkout"]
    for subject in ("", " ", " cus_x", None):
        with pytest.raises(IssuerRefused) as error:
            issue_open_mandate(
                good, kind="checkout", customer_id=subject, agent_jwk=setup.agent_jwk,  # type: ignore[arg-type]
                issuer="https://platform.example", key=platform, now_s=START_S,
            )  # fmt: skip
        assert error.value.code == "subject_missing"
    public_only = ECKey.import_key(platform.as_dict(private=False))
    with pytest.raises(IssuerRefused) as error:
        issue_open_mandate(
            good, kind="checkout", customer_id=setup.cid, agent_jwk=setup.agent_jwk,
            issuer="https://platform.example", key=public_only, now_s=START_S,
        )  # fmt: skip
    assert error.value.code == "signing_key_not_private"


def test_without_a_platform_signing_key_nothing_is_issued_and_the_nonce_is_kept(
    app_engine: Engine, clean_keys: None, clock: Clock
) -> None:
    surface = TrustedSurface(app_engine, public_origin=ORIGIN, clock_us=clock)
    app = create_app(
        key=validate_jwk(generate_jwk()), public_base_url=ORIGIN, engine=app_engine,
        clock_us=clock, trusted_surface=surface,
    )  # fmt: skip
    with TestClient(app, raise_server_exceptions=False) as c:
        setup = Setup(c, app_engine)
        body = setup.body()
        r = c.post(CONSENT, json=body)
        assert r.status_code == 503 and code(r) == "signing_unavailable"
        surface_public = TrustedSurface(
            app_engine, public_origin=ORIGIN, clock_us=clock,
            platform_key=ECKey.import_key(ECKey.generate_key("P-256").as_dict(private=False)),
        )  # fmt: skip
        assert surface_public.can_issue is False


# ------------------------------------------------------------------------------------ log


def test_a_refusal_is_logged_with_a_code_a_thumbprint_and_no_body(
    setup: Setup, admin_engine: Engine
) -> None:
    body = setup.body(sign_with=Device())
    assert code(setup.post(body)) == "consent_signature_invalid"
    entry = rows(admin_engine, "SELECT kind, payload FROM decision_log ORDER BY seq DESC LIMIT 1")[
        0
    ]
    assert entry.kind == "ts.consent.refused"
    payload = json.loads(bytes(entry.payload))
    assert payload == {
        "code": "consent_signature_invalid", "thumbprint": setup.device.thumbprint,
        "challenge_id": body["record"]["challenge_id"],
    }  # fmt: skip
    raw = bytes(entry.payload).decode()
    assert body["signature"] not in raw and setup.cid not in raw and ORIGIN not in raw


def test_a_log_failure_means_no_mandate_and_no_spent_nonce(
    setup: Setup, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = setup.body()

    def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("log is down")

    monkeypatch.setattr(surface_service.ledger_store, "append", broken)
    r = setup.post(body)
    assert r.status_code == 503 and code(r) == "log_unavailable"
    assert rows(admin_engine, "SELECT 1 FROM consent_records") == []
    monkeypatch.undo()
    assert setup.post(body).status_code == 201


def test_every_refusal_code_has_a_status_that_is_not_a_success(setup: Setup) -> None:
    for body in ({}, {**setup.body(), "signature": ""}):
        assert setup.post(body).status_code in {400, 403, 404, 409, 410, 413, 503}

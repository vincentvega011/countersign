# ruff: noqa: F811
"""The agent channel: propose, consent, fetch (Decision 87), against the real Postgres.

An agent signs a server challenge with its own key to file a proposal, the customer consents to that
proposal by id, and the agent proves the same key to fetch what was issued. Every wrong key, replay,
expiry and stolen id is refused with a stable code and leaks nothing.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine

from tests.integration.test_consent import (  # noqa: F401  (fixtures)
    CONSENT,
    PROPOSALS,
    Setup,
    client,
    platform,
    setup,
    surface,
)
from tests.integration.test_trusted_surface import challenge_for, code, customer, rows
from tests.surface_support import (
    Device,
    consent_body,
    consent_record_for,
    fetch_body_for,
    proposal_body_for,
    proposal_of,
)

FIFTEEN_MIN_US = 15 * 60 * 1_000_000


def propose(setup: Setup, terms: dict[str, Any] | None = None, **kw: Any) -> Any:
    terms = terms or setup.terms()
    issued = challenge_for(setup.client, "agent_proposal")
    return setup.client.post(
        PROPOSALS,
        json=proposal_body_for(
            kw.pop("agent", setup.agent_device), issued, proposal_of(terms), **kw
        ),
    )


def consent(setup: Setup, proposal_id: str, **kw: Any) -> Any:
    terms = setup.terms()
    issued = setup.issued()
    record = consent_record_for(setup.device, setup.cid, issued, terms)
    return setup.post(consent_body(setup.device, record, proposal_id, **kw))


def fetch(setup: Setup, proposal_id: str, signer: Device | None = None, **kw: Any) -> Any:
    issued = challenge_for(setup.client, "agent_fetch")
    body = fetch_body_for(signer or setup.agent_device, issued, proposal_id, **kw)
    return setup.client.post(f"{PROPOSALS}/{proposal_id}/mandates", json=body), body


# ------------------------------------------------------------------------------------ the good path


def test_propose_view_consent_and_fetch(setup: Setup) -> None:
    r = propose(setup)
    assert r.status_code == 201, r.text
    pid = r.json()["proposal_id"]
    assert pid.startswith("prp_") and len(pid) == 20  # short and opaque
    view = setup.client.get(f"{PROPOSALS}/{pid}").json()
    assert view["items"] == proposal_of(setup.terms())["items"]
    assert view["agent_jwk"] == setup.agent_jwk and view["ceiling_minor"] == 8000
    issued = consent(setup, pid)
    assert issued.status_code == 201, issued.text
    got, _ = fetch(setup, pid)
    assert got.status_code == 200, got.text
    out = got.json()
    assert out["checkout_mandate"] == issued.json()["checkout_mandate"]
    assert out["payment_mandate"] == issued.json()["payment_mandate"]
    assert out["customer_id"] == setup.cid


def test_the_agent_gets_nothing_before_the_customer_consents_and_the_challenge_survives(
    setup: Setup,
) -> None:
    pid = propose(setup).json()["proposal_id"]
    pending, body = fetch(setup, pid)
    assert pending.status_code == 409 and code(pending) == "consent_pending"
    consent(setup, pid)
    again = setup.client.post(
        f"{PROPOSALS}/{pid}/mandates", json=body
    )  # the same challenge, unspent
    assert again.status_code == 200


# ------------------------------------------------------------------------------------ who may fetch


def test_a_different_agent_key_cannot_fetch(setup: Setup) -> None:
    pid = propose(setup).json()["proposal_id"]
    consent(setup, pid)
    thief = Device()
    # Signing as itself, naming itself: the record is not the one the stored key signs.
    r, _ = fetch(setup, pid, signer=thief)
    assert r.status_code == 400 and code(r) == "proof_invalid"
    # Signing a record that names the real agent with the wrong key.
    r, _ = fetch(setup, pid, signer=thief, agent=setup.agent_device)
    assert code(r) == "proof_invalid"
    assert "checkout_mandate" not in r.text


def test_the_customer_device_key_cannot_fetch_either(setup: Setup) -> None:
    pid = propose(setup).json()["proposal_id"]
    consent(setup, pid)
    r, _ = fetch(setup, pid, signer=setup.device, agent=setup.agent_device)
    assert code(r) == "proof_invalid"


def test_a_stolen_proposal_id_is_worthless_without_the_key(
    setup: Setup, client: TestClient
) -> None:
    pid = propose(setup).json()["proposal_id"]
    consent(setup, pid)
    other = Setup(client)
    for signer in (other.agent_device, other.device):
        r, _ = fetch(other, pid, signer=signer)
        assert code(r) == "proof_invalid"
    r = client.post(f"{PROPOSALS}/{pid}/mandates", json={})
    assert r.status_code == 400 and code(r) == "malformed_request"


def test_a_replayed_fetch_challenge_is_refused(setup: Setup) -> None:
    pid = propose(setup).json()["proposal_id"]
    consent(setup, pid)
    first, body = fetch(setup, pid)
    assert first.status_code == 200
    replay = setup.client.post(f"{PROPOSALS}/{pid}/mandates", json=body)
    assert replay.status_code == 409 and code(replay) == "challenge_used"


def test_a_fetch_signature_is_bound_to_its_proposal_challenge_purpose_and_origin(
    setup: Setup,
) -> None:
    pid = propose(setup).json()["proposal_id"]
    other_pid = propose(setup).json()["proposal_id"]
    consent(setup, pid)
    consent(setup, other_pid)
    issued = challenge_for(setup.client, "agent_fetch")
    # signed for the other proposal
    body = fetch_body_for(setup.agent_device, issued, other_pid)
    assert code(setup.client.post(f"{PROPOSALS}/{pid}/mandates", json=body)) == "proof_invalid"
    # signed over another origin
    body = fetch_body_for(
        setup.agent_device,
        challenge_for(setup.client, "agent_fetch"),
        pid,
        origin="https://evil.example.test",
    )
    body["origin"] = setup.client.base_url and "https://surface.example.test"
    assert code(setup.client.post(f"{PROPOSALS}/{pid}/mandates", json=body)) == "proof_invalid"
    # a challenge of another purpose
    wrong = challenge_for(setup.client, "agent_proposal")
    body = fetch_body_for(setup.agent_device, wrong, pid)
    assert (
        code(setup.client.post(f"{PROPOSALS}/{pid}/mandates", json=body))
        == "challenge_purpose_mismatch"
    )
    # a record whose purpose is the proposal's, not the fetch's
    body = fetch_body_for(
        setup.agent_device, challenge_for(setup.client, "agent_fetch"), pid,
        override={"purpose": "countersign.agent.proposal.v1"},
    )  # fmt: skip
    assert code(setup.client.post(f"{PROPOSALS}/{pid}/mandates", json=body)) == "proof_invalid"


def test_fetching_an_unknown_proposal_is_not_found(setup: Setup) -> None:
    r, _ = fetch(setup, "prp_AAAAAAAAAAAAAAAA")
    assert r.status_code == 404 and code(r) == "proposal_unknown"
    r, _ = fetch(setup, "nope")
    assert code(r) == "proposal_unknown"


# ------------------------------------------------------------------------------------ expiry and single use


def test_an_expired_proposal_cannot_be_shown_or_consented_but_issued_mandates_stay_fetchable(
    setup: Setup, clock: Any
) -> None:
    pid = propose(setup).json()["proposal_id"]
    stale = propose(setup).json()["proposal_id"]
    consent(setup, pid)
    clock.now += FIFTEEN_MIN_US + 1
    shown = setup.client.get(f"{PROPOSALS}/{stale}")
    assert shown.status_code == 410 and code(shown) == "proposal_expired"
    r = consent(setup, stale)
    assert code(r) == "proposal_expired"
    got, _ = fetch(setup, pid)
    assert got.status_code == 200  # issued before it expired: the agent still collects it
    pending, _ = fetch(setup, stale)
    assert code(pending) == "proposal_expired"


def test_a_proposal_backs_one_consent(setup: Setup, admin_engine: Engine) -> None:
    pid = propose(setup).json()["proposal_id"]
    assert consent(setup, pid).status_code == 201
    second = consent(setup, pid)
    assert second.status_code == 409 and code(second) == "proposal_used"
    shown = setup.client.get(f"{PROPOSALS}/{pid}")
    assert code(shown) == "proposal_used"
    assert (
        len(rows(admin_engine, "SELECT 1 FROM consent_records WHERE customer_id = :c", c=setup.cid))
        == 1
    )


def test_many_simultaneous_consents_on_one_proposal_issue_once(
    setup: Setup, surface: Any, admin_engine: Engine
) -> None:
    pid = propose(setup).json()["proposal_id"]
    bodies = []
    for _ in range(8):
        record = consent_record_for(setup.device, setup.cid, setup.issued(), setup.terms())
        bodies.append(consent_body(setup.device, record, pid))
    gate = threading.Barrier(len(bodies))

    def attempt(body: dict[str, Any]) -> str:
        gate.wait()
        from countersign.trusted_surface import Refused

        try:
            surface.consent(
                record=body["record"], signature=body["signature"], proposal_id=body["proposal_id"]
            )
        except Refused as error:
            return error.code
        return "ok"

    with ThreadPoolExecutor(len(bodies)) as pool:
        results = list(pool.map(attempt, bodies))
    assert results.count("ok") == 1 and set(results) - {"ok"} == {"proposal_used"}, results
    assert (
        len(rows(admin_engine, "SELECT 1 FROM consent_records WHERE customer_id = :c", c=setup.cid))
        == 1
    )


def test_consent_for_an_unknown_or_malformed_proposal_is_refused(setup: Setup) -> None:
    for bad in ("prp_AAAAAAAAAAAAAAAA", "nope", "", 5, None):
        r = consent(setup, bad)  # type: ignore[arg-type]
        assert code(r) in {"proposal_unknown", "malformed_request"}, (bad, r.text)


# ------------------------------------------------------------------------------------ creating a proposal


def test_a_proposal_needs_the_agent_key_to_sign_a_fresh_challenge(setup: Setup) -> None:
    terms = setup.terms()
    # signed by another key than the one named
    assert code(propose(setup, sign_with=Device())) == "proof_invalid"
    # a signature over a different proposal
    issued = challenge_for(setup.client, "agent_proposal")
    body = proposal_body_for(setup.agent_device, issued, proposal_of(terms))
    body["proposal"] = {**body["proposal"], "ceiling_minor": 99}
    assert code(setup.client.post(PROPOSALS, json=body)) == "proof_invalid"
    # a replayed challenge
    issued = challenge_for(setup.client, "agent_proposal")
    body = proposal_body_for(setup.agent_device, issued, proposal_of(terms))
    assert setup.client.post(PROPOSALS, json=body).status_code == 201
    assert code(setup.client.post(PROPOSALS, json=body)) == "challenge_used"
    # another purpose's challenge, a wrong origin, and a wrong record purpose
    wrong = challenge_for(setup.client, "consent_open_mandates")
    body = proposal_body_for(setup.agent_device, wrong, proposal_of(terms))
    assert code(setup.client.post(PROPOSALS, json=body)) == "challenge_purpose_mismatch"
    issued = challenge_for(setup.client, "agent_proposal")
    body = proposal_body_for(
        setup.agent_device, issued, proposal_of(terms), origin="https://evil.example.test"
    )
    assert code(setup.client.post(PROPOSALS, json=body)) == "origin_mismatch"
    body = proposal_body_for(
        setup.agent_device, challenge_for(setup.client, "agent_proposal"), proposal_of(terms),
        override={"purpose": "countersign.agent.fetch.v1"},
    )  # fmt: skip
    assert code(setup.client.post(PROPOSALS, json=body)) == "proof_invalid"


def test_a_proposal_with_a_private_or_odd_key_is_refused(setup: Setup) -> None:
    terms = setup.terms()
    for bad in ({**setup.agent_jwk, "d": "x" * 43}, {**setup.agent_jwk, "alg": "ES256"}, "x", None):
        issued = challenge_for(setup.client, "agent_proposal")
        body = proposal_body_for(
            setup.agent_device, issued, proposal_of(terms), body_override={"agent_jwk": bad}
        )
        assert code(setup.client.post(PROPOSALS, json=body)).startswith("jwk_")


def test_a_proposal_that_means_nothing_is_refused(setup: Setup) -> None:
    good = proposal_of(setup.terms())
    items = good["items"]
    cases = [
        {**good, "ceiling_minor": 0},
        {**good, "ceiling_minor": 10_000_000},
        {**good, "currency": "EUR"},
        {**good, "mandate_expires_at": 1},
        {**good, "mandate_expires_at": good["mandate_expires_at"] + 90 * 86400},
        {**good, "items": []},
        {**good, "items": [{"id": "not-in-catalog", "quantity": 1}]},
        {**good, "items": [items[0], items[0]]},
        {**good, "items": [{**items[0], "quantity": 0}]},
        {**good, "items": [{**items[0], "quantity": True}]},
        {**good, "extra": 1},
        {k: v for k, v in good.items() if k != "currency"},
        {**good, "items": [{**items[0], "title": "text from an agent"}]},
    ]
    for proposal in cases:
        issued = challenge_for(setup.client, "agent_proposal")
        body = proposal_body_for(setup.agent_device, issued, proposal)
        r = setup.client.post(PROPOSALS, json=body)
        assert r.status_code == 400 and code(r) == "proposal_invalid", (proposal, r.text)


def test_proposal_routes_reject_bad_bodies(setup: Setup) -> None:
    for raw, media in (("{}", "application/json"), ("{", "application/json"), ("{}", "text/plain")):
        r = setup.client.post(PROPOSALS, content=raw, headers={"Content-Type": media})
        assert r.status_code == 400 and code(r) == "malformed_request"
    r = setup.client.get(f"{PROPOSALS}/nope")
    assert r.status_code == 404 and code(r) == "proposal_unknown"


def test_the_proposal_view_never_shows_agent_authored_text(setup: Setup) -> None:
    pid = propose(setup).json()["proposal_id"]
    view = setup.client.get(f"{PROPOSALS}/{pid}").json()
    assert set(view) == {
        "proposal_id", "items", "ceiling_minor", "currency", "mandate_expires_at", "agent_jwk",
        "expires_us",
    }  # fmt: skip
    assert all(set(item) == {"id", "quantity"} for item in view["items"])
    _ = customer  # the enrolment helper is part of the harness
    assert CONSENT.endswith("/consent")

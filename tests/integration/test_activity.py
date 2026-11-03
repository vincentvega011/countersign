# ruff: noqa: F811
"""My agent activity: a device-proven read session and a separately signed revoke (Decisions 91, 92)."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from tests.integration.test_agent_channel import consent, propose
from tests.integration.test_consent import (  # noqa: F401  (fixtures)
    Setup,
    client,
    platform,
    setup,
    surface,
)
from tests.integration.test_trusted_surface import add_key, challenge_for, code, revoke, rows
from tests.surface_support import (
    ORIGIN,
    Device,
    mandate_revoke_body,
    read_body,
)


@pytest.fixture(autouse=True)
def _payments_start_empty(clean_payments: None) -> None:
    """The payment tables are not touched by the key fixtures; start each test with none."""


SESSION = "/trusted-surface/activity/session"
LIST = "/trusted-surface/activity"
REVOKE = "/trusted-surface/activity/revoke"
FIVE_MIN_US = 5 * 60 * 1_000_000


def open_mandate_for(setup: Setup, **kw: Any) -> str:
    pid = propose(setup, **kw).json()["proposal_id"]
    r = consent(setup, pid)
    assert r.status_code == 201, r.text
    return str(r.json()["open_mandate"])


def session(setup: Setup, **kw: Any) -> Any:
    issued = challenge_for(setup.client, "activity_read")
    device = kw.pop("device", setup.device)
    body = read_body(device, issued, kw.pop("cid", setup.cid), **kw)
    return setup.client.post(SESSION, json=body)


def token_of(setup: Setup) -> str:
    r = session(setup)
    assert r.status_code == 201, r.text
    return str(r.json()["token"])


def listing(setup: Setup, token: str | None) -> Any:
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    return setup.client.get(LIST, headers=headers)


def revoke_mandate(setup: Setup, open_mandate: str, **kw: Any) -> Any:
    issued = challenge_for(setup.client, "revoke_open_mandate")
    device = kw.pop("device", setup.device)
    body = mandate_revoke_body(device, issued, kw.pop("cid", setup.cid), open_mandate, **kw)
    return setup.client.post(REVOKE, json=body)


def state_of(setup: Setup, token: str, open_mandate: str) -> str:
    found = [m for m in listing(setup, token).json()["mandates"] if m["id"] == open_mandate]
    assert len(found) == 1
    return str(found[0]["state"])


# ------------------------------------------------------------------------------------ reading


def test_the_list_needs_a_session_proven_by_the_device_key(setup: Setup) -> None:
    mandate = open_mandate_for(setup)
    assert listing(setup, None).status_code == 401
    assert code(listing(setup, None)) == "session_unknown"
    for bad in ("", "x", "ats_" + "A" * 43, setup.cid):
        r = listing(setup, bad)
        assert r.status_code == 401 and code(r) == "session_unknown"
    token = token_of(setup)
    r = listing(setup, token)
    assert r.status_code == 200
    body = r.json()
    assert body["customer_id"] == setup.cid
    (item,) = body["mandates"]
    assert item["id"] == mandate and item["state"] == "unused" and item["purchase"] is None
    assert item["ceiling_minor"] == 8000 and item["currency"] == "USD"
    assert item["agent_thumbprint"] == setup.agent_device.thumbprint and item["exp"] == setup.exp


def test_the_session_token_is_opaque_and_only_its_hash_is_stored(
    setup: Setup, admin_engine: Engine
) -> None:
    token = token_of(setup)
    assert token.startswith("ats_") and len(token) == 47
    stored = rows(admin_engine, "SELECT token_hash FROM activity_sessions")
    assert [r.token_hash for r in stored] == [hashlib.sha256(token.encode()).hexdigest()]
    assert token not in str(rows(admin_engine, "SELECT * FROM activity_sessions"))


def test_a_session_expires_five_minutes_after_it_was_issued(setup: Setup, clock: Any) -> None:
    token = token_of(setup)
    clock.now += FIVE_MIN_US - 1
    assert listing(setup, token).status_code == 200
    clock.now += 1
    r = listing(setup, token)
    assert r.status_code == 401 and code(r) == "session_expired"


def test_a_token_lists_only_its_own_customers_mandates(setup: Setup, client: TestClient) -> None:
    mine = open_mandate_for(setup)
    other = Setup(client, setup.engine)
    theirs = open_mandate_for(other)
    mine_list = listing(setup, token_of(setup)).json()["mandates"]
    their_list = listing(other, token_of(other)).json()["mandates"]
    assert [m["id"] for m in mine_list] == [mine] and [m["id"] for m in their_list] == [theirs]


def test_a_session_needs_a_live_registered_key_and_a_fresh_challenge(
    setup: Setup, client: TestClient
) -> None:
    stranger = Device()
    assert code(session(setup, device=stranger)) == "device_key_unknown"
    other = Setup(client, setup.engine)
    assert code(session(setup, device=other.device)) == "device_key_customer_mismatch"
    # signed by another key, over another purpose's record, another origin, another customer
    assert code(session(setup, sign_with=other.device)) == "proof_invalid"
    assert (
        code(session(setup, override={"purpose": "countersign.open-mandate.revoke.v1"}))
        == "proof_invalid"
    )
    assert code(session(setup, origin="https://evil.example.test")) == "origin_mismatch"
    issued = challenge_for(client, "activity_read")
    body = read_body(setup.device, issued, setup.cid)
    assert client.post(SESSION, json=body).status_code == 201
    assert code(client.post(SESSION, json=body)) == "challenge_used"
    wrong = challenge_for(client, "register_device_key")
    assert (
        code(client.post(SESSION, json=read_body(setup.device, wrong, setup.cid)))
        == "challenge_purpose_mismatch"
    )


def test_a_revoked_device_key_cannot_open_or_keep_a_session(
    setup: Setup, client: TestClient
) -> None:
    second = add_key(client, setup.device, setup.cid)
    token = token_of(setup)
    assert revoke(client, second, setup.cid, setup.device).status_code == 201
    r = listing(setup, token)
    assert r.status_code == 403 and code(r) == "device_key_revoked"
    assert code(session(setup)) == "device_key_revoked"


# ------------------------------------------------------------------------------------ states


def test_expired_in_flight_used_and_revoked_states(
    setup: Setup, admin_engine: Engine, clock: Any
) -> None:
    unused = open_mandate_for(setup)
    flying = open_mandate_for(setup)
    used = open_mandate_for(setup)
    with admin_engine.begin() as conn:
        for cid, mandate, state in (
            ("chk_flying", flying, "authorized"),
            ("chk_used", used, "captured"),
        ):
            conn.execute(
                text(
                    "INSERT INTO open_payment_mandates (digest, currency, created_us) VALUES (:m, 'USD', 1)"
                ),
                {"m": mandate},
            )
            conn.execute(
                text(
                    "INSERT INTO spend_entries (id, mandate_digest, checkout_id, amount_minor, "
                    "currency, state, refunded_minor, created_us, updated_us) VALUES "
                    "(:s, :m, :c, 7900, 'USD', :st, 0, 1, 1)"
                ),
                {
                    "s": "sp_" + cid,
                    "m": mandate,
                    "c": cid,
                    "st": "in_flight" if state != "captured" else "captured",
                },
            )
            conn.execute(
                text(
                    "INSERT INTO payment_attempts (checkout_id, reservation_handle, spend_id, "
                    "mandate_digest, state, mode, custom_id, created_us, updated_us, capture_id, receipt) "
                    "VALUES (:c, 'h', :s, :m, :st, 'redirect', 'cs1.x', 1, :u, :cap, :rec)"
                ),
                {"c": cid, "s": "sp_" + cid, "m": mandate, "st": state, "u": 1_800_000_000_000_000,
                 "cap": "CAP123" if state == "captured" else None,
                 "rec": "receipt" if state == "captured" else None},
            )  # fmt: skip
    token = token_of(setup)
    states = {m["id"]: m for m in listing(setup, token).json()["mandates"]}
    assert states[unused]["state"] == "unused"
    assert states[flying]["state"] == "in_flight"
    assert states[used]["state"] == "used"
    assert states[used]["purchase"] == {
        "checkout_id": "chk_used", "capture_id": "CAP123", "amount_minor": 7900,
        "currency": "USD", "at_us": 1_800_000_000_000_000,
    }  # fmt: skip
    assert revoke_mandate(setup, unused).status_code == 201
    assert state_of(setup, token, unused) == "revoked"
    clock.now += 8 * 86400 * 1_000_000
    token = token_of(setup)
    assert state_of(setup, token, flying) == "in_flight"  # a payment under way is not "expired"
    assert state_of(setup, token, used) == "used"


def test_an_unused_mandate_past_its_expiry_is_expired(setup: Setup, clock: Any) -> None:
    mandate = open_mandate_for(setup)
    clock.now += 8 * 86400 * 1_000_000
    assert state_of(setup, token_of(setup), mandate) == "expired"


# ------------------------------------------------------------------------------------ revoking


def test_revoking_needs_its_own_signature_not_the_bearer_token(
    setup: Setup, admin_engine: Engine
) -> None:
    mandate = open_mandate_for(setup)
    token = token_of(setup)
    # The bearer token alone: no signature at all.
    r = setup.client.post(
        REVOKE, json={"open_mandate": mandate, "customer_id": setup.cid},
        headers={"Authorization": f"Bearer {token}"},
    )  # fmt: skip
    assert r.status_code == 400 and code(r) == "malformed_request"
    # The token plus a body that names the mandate but carries a signature over something else.
    issued = challenge_for(setup.client, "revoke_open_mandate")
    body = mandate_revoke_body(
        setup.device, issued, setup.cid, mandate, override={"open_mandate": "A" * 43}
    )
    r = setup.client.post(REVOKE, json=body, headers={"Authorization": f"Bearer {token}"})
    assert code(r) == "proof_invalid"
    # A read-record signature does not revoke.
    body = mandate_revoke_body(
        setup.device,
        challenge_for(setup.client, "revoke_open_mandate"),
        setup.cid,
        mandate,
        override={"purpose": "countersign.activity.read.v1"},
    )
    assert code(setup.client.post(REVOKE, json=body)) == "proof_invalid"
    # Another device's signature.
    assert code(revoke_mandate(setup, mandate, sign_with=Device())) == "proof_invalid"
    assert rows(admin_engine, "SELECT 1 FROM open_mandate_revocations") == []
    assert state_of(setup, token, mandate) == "unused"


def test_a_signature_for_one_mandate_cannot_revoke_another(
    setup: Setup, admin_engine: Engine
) -> None:
    one, two = open_mandate_for(setup), open_mandate_for(setup)
    issued = challenge_for(setup.client, "revoke_open_mandate")
    body = mandate_revoke_body(setup.device, issued, setup.cid, one)
    body["open_mandate"] = two
    assert code(setup.client.post(REVOKE, json=body)) == "proof_invalid"
    assert rows(admin_engine, "SELECT 1 FROM open_mandate_revocations") == []


def test_another_customers_mandate_cannot_be_revoked(
    setup: Setup, client: TestClient, admin_engine: Engine
) -> None:
    other = Setup(client, setup.engine)
    theirs = open_mandate_for(other)
    r = revoke_mandate(setup, theirs)  # our key, our id, their mandate
    assert r.status_code == 404 and code(r) == "open_mandate_unknown"
    assert code(revoke_mandate(setup, "A" * 43)) == "open_mandate_unknown"  # same answer as none
    r = revoke_mandate(setup, theirs, device=other.device)  # their key, our id
    assert code(r) == "device_key_customer_mismatch"
    r = revoke_mandate(setup, theirs, device=other.device, cid=other.cid, sign_with=setup.device)
    assert code(r) == "proof_invalid"
    assert rows(admin_engine, "SELECT 1 FROM open_mandate_revocations") == []
    assert state_of(other, token_of(other), theirs) == "unused"


def test_revoke_is_idempotent_and_its_challenge_is_single_use(
    setup: Setup, admin_engine: Engine
) -> None:
    mandate = open_mandate_for(setup)
    first = revoke_mandate(setup, mandate)
    assert first.status_code == 201 and first.json() == {
        "open_mandate": mandate, "revoked": True, "new_revocation": True,
    }  # fmt: skip
    second = revoke_mandate(setup, mandate)
    assert second.status_code == 200 and second.json()["new_revocation"] is False
    issued = challenge_for(setup.client, "revoke_open_mandate")
    body = mandate_revoke_body(setup.device, issued, setup.cid, mandate)
    assert setup.client.post(REVOKE, json=body).status_code == 200
    assert code(setup.client.post(REVOKE, json=body)) == "challenge_used"
    assert len(rows(admin_engine, "SELECT 1 FROM open_mandate_revocations")) == 1
    proof = rows(
        admin_engine,
        "SELECT customer_id, signer_thumbprint, signature FROM open_mandate_revocations",
    )[0]
    assert (
        proof.customer_id == setup.cid
        and proof.signer_thumbprint == setup.device.thumbprint
        and proof.signature
    )


@pytest.mark.parametrize(
    ("state", "expected"),
    [("capturing", "in_flight"), ("unresolved", "in_flight"), ("captured", "already_used")],
)
def test_revoking_a_mandate_with_a_payment_under_way_or_done_changes_nothing(
    setup: Setup, admin_engine: Engine, state: str, expected: str
) -> None:
    mandate = open_mandate_for(setup)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO payment_attempts (checkout_id, reservation_handle, spend_id, "
                "mandate_digest, state, mode, custom_id, created_us, updated_us, capture_id, receipt) "
                "VALUES (:c, 'h', :s, :m, :st, 'redirect', 'cs1.x', 1, 1, :cap, :rec)"
            ),
            {"c": "chk_" + state, "s": "sp_" + state, "m": mandate, "st": state, "cap": "C" if state == "captured" else None,
             "rec": "r" if state == "captured" else None},
        )  # fmt: skip
    r = revoke_mandate(setup, mandate)
    assert r.status_code == 409 and code(r) == expected
    assert rows(admin_engine, "SELECT 1 FROM open_mandate_revocations") == []
    assert state_of(setup, token_of(setup), mandate) in {"in_flight", "used"}


def test_a_revoked_mandate_stops_the_purchase_at_the_gate_row_lock(
    setup: Setup, admin_engine: Engine
) -> None:
    """The activity revoke writes the same row the gate and the Credential Provider read."""
    from countersign.openmandates import revoked_in

    mandate = open_mandate_for(setup)
    assert revoke_mandate(setup, mandate).status_code == 201
    with setup.engine.connect() as conn:
        assert revoked_in(conn, [mandate])


def test_every_refusal_is_logged_before_the_answer(setup: Setup, admin_engine: Engine) -> None:
    mandate = open_mandate_for(setup)
    listing(setup, None)
    session(setup, device=Device())
    revoke_mandate(setup, mandate, sign_with=Device())
    kinds = {r.kind for r in rows(admin_engine, "SELECT DISTINCT kind FROM decision_log")}
    assert {"ts.activity.read.refused", "ts.activity.refused", "ts.mandate.revoke.refused"} <= kinds
    revoke_mandate(setup, mandate)
    assert "ts.mandate.revoked" in {
        r.kind for r in rows(admin_engine, "SELECT DISTINCT kind FROM decision_log")
    }


def test_malformed_bodies_are_refused(setup: Setup) -> None:
    for path in (SESSION, REVOKE):
        for raw, media in (
            ("{}", "application/json"),
            ("{", "application/json"),
            ("{}", "text/plain"),
        ):
            r = setup.client.post(path, content=raw, headers={"Content-Type": media})
            assert r.status_code == 400 and code(r) == "malformed_request"
    _ = (ORIGIN, time)

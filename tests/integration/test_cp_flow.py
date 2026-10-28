"""Credential Provider end to end against the PayPal simulator and the real Postgres.

The runtime connects as the restricted application role (`app_engine`), so every statement the
Credential Provider issues is one that role is allowed to issue.
"""

from __future__ import annotations

import re

import pytest
from sqlalchemy import Engine, select

from countersign.canonical import sd_hash
from countersign.cp import (
    CpApprovalRequired,
    CpAuthorized,
    CpPending,
    CpRejected,
    custom_id_for,
    evidence_reference,
)
from countersign.ledger.store import entries_for_checkout, verify_log
from countersign.merchant import receipts
from countersign.tables import payment_attempts, reservations, spend_entries
from tests.cp_support import CpWorld, make_world


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> CpWorld:
    return make_world(app_engine)


def attempt(world: CpWorld, checkout_id: str | None = None):  # type: ignore[no-untyped-def]
    with world.engine.connect() as conn:
        return conn.execute(
            select(payment_attempts).where(
                payment_attempts.c.checkout_id == (checkout_id or world.checkout.id)
            )
        ).one()


def spend(world: CpWorld):  # type: ignore[no-untyped-def]
    with world.engine.connect() as conn:
        return conn.execute(select(spend_entries)).all()


def reservation_rows(world: CpWorld):  # type: ignore[no-untyped-def]
    with world.engine.connect() as conn:
        return conn.execute(select(reservations).where(reservations.c.role == "cp")).all()


def test_redirect_happy_path_authorizes_once_and_captures_nothing(world: CpWorld) -> None:
    m = world.mandates()
    started = world.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=world.checkout
    )
    assert isinstance(started, CpApprovalRequired)
    assert started.approval_url.startswith("https://www.sandbox.paypal.com/")

    # The order was created exactly as specified.
    (create,) = [o for o in world.sim.orders.values()]
    unit = create["request"]["purchase_units"][0]
    assert create["request"]["intent"] == "AUTHORIZE"
    assert unit["invoice_id"] == world.checkout.id
    expected_custom = custom_id_for(
        evidence_reference(
            checkout_hash=m.payment.token and _hash_of(m),
            checkout_mandate_digest=sd_hash(_final_link(m.checkout_mandate)),
            payment_mandate_digest=sd_hash(_final_link(m.payment_token)),
        )
    )
    assert unit["custom_id"] == expected_custom
    assert unit["amount"]["value"] == "85.00" and unit["amount"]["currency_code"] == "USD"
    assert attempt(world).state == "order_created"
    (entry,) = spend(world)
    assert (entry.state, entry.amount_minor) == ("in_flight", 8500)

    # Before approval nothing is authorized.
    pending = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(pending, CpPending) and world.sim.count("/authorize") == 0

    world.sim.approve(started.order_id)
    done = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(done, CpAuthorized)
    assert done.amount.minor == 8500 and done.custom_id == expected_custom
    assert world.sim.count("/authorize") == 1 and world.sim.count("/capture") == 0
    assert attempt(world).state == "authorized"
    assert world.sim.authorizations[done.authorization_id]["status"] == "CREATED"

    # A double submit does not authorize again.
    again = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(again, CpAuthorized) and again.authorization_id == done.authorization_id
    assert world.sim.count("/authorize") == 1

    # Every mutating call carried the deterministic Request-Id, within the 108 limit.
    ids = [rid for method, _, rid in world.sim.calls if method == "POST" and rid]
    assert ids and all(
        re.fullmatch(r"cs1\.[a-z_]+\.[A-Za-z0-9_-]{43}", i) and len(i) <= 108 for i in ids
    )

    # The decisions and each PayPal call are in a verified chain, written by the application role.
    with world.engine.connect() as conn:
        kinds = [e.kind for e in entries_for_checkout(conn, world.checkout.id)]
        assert verify_log(conn).ok
    assert kinds[0] == "cp.reserved"
    for needed in ("cp.paypal.create_order.started", "cp.paypal.create_order.finished",
                   "cp.order_created", "cp.paypal.authorize.started", "cp.paypal.authorize.finished",
                   "cp.authorized"):  # fmt: skip
        assert needed in kinds


def _final_link(token: str) -> str:
    from countersign.mandates import split_chain

    return split_chain(token)[-1].serialization


def _hash_of(m) -> str:  # type: ignore[no-untyped-def]
    from countersign.canonical import checkout_hash
    from countersign.merchant.authorization import checkout_jwt

    return checkout_hash(checkout_jwt(m.issued))


def test_a_rejection_signs_a_payment_receipt_and_creates_nothing(world: CpWorld) -> None:
    result = world.provider.start(payment_token=None, checkout_mandate=None, current=world.checkout)
    assert isinstance(result, CpRejected)
    claims = receipts.verify_receipt(
        result.receipt, [world.merchant_key.public_jwk], receipts.PAYMENT_RECEIPT_TYP
    )
    assert claims["status"] == "Error" and claims["error"] == "mandate_required"
    assert claims["payment_id"] == world.checkout.id
    assert world.sim.orders == {} and world.sim.calls == []
    assert reservation_rows(world) == [] and spend(world) == []


# ----- the vaulted path (sandbox only, docs/PROTOCOL.md 4.7) -----


def seed_vault(world: CpWorld, vault_id: str = "VAULT-SEED") -> None:
    from countersign.tables import payer_vault

    world.sim.vault_ids["seed"] = vault_id
    with world.engine.begin() as conn:
        conn.execute(
            payer_vault.insert().values(
                principal=world.keys.agent.thumbprint(), vault_id=vault_id, created_us=1
            )
        )


def test_vaulted_path_charges_the_stored_wallet_without_payer_approval(world: CpWorld) -> None:
    seed_vault(world)
    m = world.mandates()
    result = world.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=world.checkout
    )
    assert isinstance(result, CpAuthorized) and result.mode == "vault"
    (order,) = world.sim.orders.values()
    source = order["request"]["payment_source"]["paypal"]
    assert source == {
        "vault_id": "VAULT-SEED",
        "stored_credential": {
            "payment_initiator": "MERCHANT", "payment_type": "UNSCHEDULED", "usage": "SUBSEQUENT",
        },
    }  # fmt: skip
    assert world.sim.count("/authorize") == 0  # created and authorized in one call, no approval
    assert len(world.sim.authorizations) == 1 and attempt(world).state == "authorized"


def test_vaulted_path_that_needs_payer_action_is_not_pretended_autonomous(world: CpWorld) -> None:
    seed_vault(world)
    world.sim.vault_needs_action = True
    m = world.mandates()
    result = world.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=world.checkout
    )
    assert isinstance(result, CpRejected) and result.reason == "vault_requires_payer_action"
    assert result.ucp_code == "payment_failed"
    assert attempt(world).state == "abandoned" and world.sim.authorizations == {}


def test_a_redirect_approval_can_enroll_the_wallet_for_later_purchases(
    app_engine: Engine, clean_payments: None
) -> None:
    world = make_world(app_engine, enroll_vault=True)
    m = world.mandates(maximum=100_000)
    started = world.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=world.checkout
    )
    assert isinstance(started, CpApprovalRequired)
    (order,) = world.sim.orders.values()
    assert order["request"]["payment_source"]["paypal"]["attributes"]["vault"] == {
        "store_in_vault": "ON_SUCCESS", "usage_type": "MERCHANT", "customer_type": "CONSUMER",
    }  # fmt: skip
    world.sim.approve(started.order_id)
    assert isinstance(
        world.provider.finish(checkout_id=world.checkout.id, current=world.checkout), CpAuthorized
    )
    from countersign.tables import payer_vault

    with world.engine.connect() as conn:
        row = conn.execute(select(payer_vault)).one()
    assert row.principal == world.keys.agent.thumbprint() and row.vault_id.startswith("VAULT")


# ----- the authorization is verified, not trusted (vault path: create and authorize in one call) -----


def vault_start(world: CpWorld):  # type: ignore[no-untyped-def]
    seed_vault(world)
    m = world.mandates()
    return world.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=world.checkout
    )


@pytest.mark.parametrize(
    ("flag", "value", "reason"),
    [
        ("extra_auth", True, "authorization_count"),
        ("auth_status", "PENDING", "authorization_not_created"),
        ("auth_amount_override", "1.00", "authorization_differs"),
        ("vault_mutation", {"item_name": "Something else"}, "postauthorize_order_terms_differ"),
    ],
)
def test_an_authorization_that_does_not_match_is_voided(
    world: CpWorld, flag: str, value: object, reason: str
) -> None:
    setattr(world.sim, flag, value)
    result = vault_start(world)
    assert isinstance(result, CpRejected) and result.step == "C8" and result.reason == reason
    assert world.sim.authorizations and all(
        a["status"] == "VOIDED" for a in world.sim.authorizations.values()
    )  # everything PayPal holds is voided and confirmed
    assert attempt(world).state == "voided"


def test_an_order_that_is_not_approvable_is_not_authorized(world: CpWorld) -> None:
    m = world.mandates()
    started = world.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=world.checkout
    )
    assert isinstance(started, CpApprovalRequired)
    world.sim.orders[started.order_id]["status"] = "VOIDED"
    result = world.provider.finish(checkout_id=world.checkout.id, current=world.checkout)
    assert isinstance(result, CpRejected) and result.reason.startswith("order_not_approvable")
    assert world.sim.count("/authorize") == 0 and attempt(world).state == "abandoned"


def test_payment_and_checkout_mandates_of_different_modes_are_refused(world: CpWorld) -> None:
    from countersign.merchant.authorization import checkout_jwt
    from tests.mandate_issuer import issue_human_present

    m = world.mandates()
    human = issue_human_present(world.keys, checkout_jwt_value=checkout_jwt(m.issued))
    result = world.provider.start(
        payment_token=m.payment_token, checkout_mandate=human, current=world.checkout
    )
    assert isinstance(result, CpRejected)
    assert (result.step, result.reason) == ("C2", "modes_differ")


def test_a_constraint_result_that_is_merely_truthy_is_refused(world: CpWorld) -> None:
    class Truthy:
        satisfied = 1
        reason = "truthy"
        unresolved = False

    class Odd:
        def evaluate_payment(self, **_: object) -> object:
            return Truthy()

    world.provider._evaluator = Odd()  # type: ignore[assignment]
    m = world.mandates()
    result = world.provider.start(
        payment_token=m.payment_token, checkout_mandate=m.checkout_mandate, current=world.checkout
    )
    assert isinstance(result, CpRejected) and (result.step, result.reason) == (
        "C5",
        "constraint_violated",
    )
    assert world.sim.orders == {}

"""One test per Credential Provider verification step and failure (C1 to C6)."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine, select

from countersign.canonical import sd_hash
from countersign.cp import CpApprovalRequired, CpRejected
from countersign.ledger.store import entries_for_checkout
from countersign.merchant import receipts
from countersign.tables import reservations, spend_entries
from tests.constraint_fixtures import payment_constraints
from tests.cp_support import CpWorld, Mandates, make_world
from tests.mandate_issuer import NOW, Keys
from tests.merchant_support import make_checkout


@pytest.fixture
def world(app_engine: Engine, clean_payments: None) -> CpWorld:
    return make_world(app_engine)


def start(world: CpWorld, m: Mandates, **kw: Any) -> Any:
    return world.provider.start(
        payment_token=kw.get("payment_token", m.payment_token),
        checkout_mandate=kw.get("checkout_mandate", m.checkout_mandate),
        current=kw.get("current", m.current),
    )


def rows(world: CpWorld) -> tuple[int, int]:
    with world.engine.connect() as conn:
        return (
            len(conn.execute(select(reservations).where(reservations.c.role == "cp")).all()),
            len(conn.execute(select(spend_entries)).all()),
        )


def rejected(
    world: CpWorld, result: Any, step: str, reason: str, code: str, detail: str | None = None
) -> None:
    assert isinstance(result, CpRejected), result
    assert (result.step, result.reason, result.ucp_code) == (step, reason, code), result
    if detail is not None:
        assert result.detail == detail
    # A step before the PayPal call creates no order and holds no reservation or spend.
    assert world.sim.orders == {} and rows(world) == (0, 0) or step in ("C7", "C8")
    claims = receipts.verify_receipt(
        result.receipt, [world.merchant_key.public_jwk], receipts.PAYMENT_RECEIPT_TYP
    )
    assert claims["error"] == code and claims["error_description"] == reason
    with world.engine.connect() as conn:
        entries = entries_for_checkout(conn, world.checkout.id)
    assert any(e.kind == "cp.payment_mandate.rejected" for e in entries)


# ----- C1 -----


def test_c1_payment_token_missing(world: CpWorld) -> None:
    m = world.mandates()
    rejected(
        world, start(world, m, payment_token=None), "C1", "mandate_missing", "mandate_required"
    )
    rejected(world, start(world, m, payment_token=""), "C1", "mandate_missing", "mandate_required")


def test_c1_checkout_mandate_missing(world: CpWorld) -> None:
    m = world.mandates()
    rejected(
        world, start(world, m, checkout_mandate=None), "C1", "mandate_missing", "mandate_required"
    )


# ----- C2 chains -----


def tamper(token: str) -> str:
    index = len(token) // 2
    return token[:index] + ("A" if token[index] != "A" else "B") + token[index + 1 :]


def test_c2_bad_payment_chain(world: CpWorld) -> None:
    m = world.mandates()
    result = start(world, m, payment_token=tamper(m.payment_token))
    assert isinstance(result, CpRejected) and result.step == "C2"
    assert result.reason.startswith("payment:") and result.ucp_code == "mandate_invalid_signature"
    assert world.sim.orders == {} and rows(world) == (0, 0)


def test_c2_bad_checkout_chain(world: CpWorld) -> None:
    m = world.mandates()
    result = start(world, m, checkout_mandate=tamper(m.checkout_mandate))
    assert isinstance(result, CpRejected) and result.step == "C2"
    assert result.reason.startswith("checkout:")


def test_c2_wrong_vct(world: CpWorld) -> None:
    m = world.mandates(payment_kwargs={"open_vct": "mandate.checkout.open.1"})
    rejected(world, start(world, m), "C2", "payment:vct_mismatch", "mandate_invalid_signature")


def test_c2_payment_mandate_signed_by_an_untrusted_key(world: CpWorld) -> None:
    m = world.mandates(payment_kwargs={"issuer_signer": Keys().stranger})
    rejected(world, start(world, m), "C2", "payment:signature_invalid", "mandate_invalid_signature")


def test_c2_key_binding_by_another_key(world: CpWorld) -> None:
    m = world.mandates(payment_kwargs={"kb_signer": Keys().stranger})
    rejected(world, start(world, m), "C2", "payment:signature_invalid", "mandate_invalid_signature")


def test_c2_wrong_audience(world: CpWorld) -> None:
    m = world.mandates(payment_kwargs={"kb_aud": "merchant"})
    rejected(
        world, start(world, m), "C2", "payment:kb_audience_mismatch", "mandate_invalid_signature"
    )


def test_c2_expired_payment_mandate(world: CpWorld) -> None:
    m = world.mandates(payment_kwargs={"open_exp": NOW - 100})
    rejected(world, start(world, m), "C2", "payment:mandate_expired", "mandate_expired")


def test_c2_open_mandate_without_an_agent_key(world: CpWorld) -> None:
    m = world.mandates(payment_kwargs={"cnf": None})
    result = start(world, m)
    assert isinstance(result, CpRejected) and result.ucp_code == "agent_missing_key"


def test_c2_platform_without_a_key(app_engine: Engine, clean_payments: None) -> None:
    world = make_world(app_engine)
    from dataclasses import replace

    world.provider._config = replace(world.config, platform_key=None)
    m = world.mandates()
    rejected(world, start(world, m), "C2", "platform_key_missing", "agent_missing_key")


# ----- C3 transaction_id -----


def test_c3_transaction_id_not_equal_to_the_checkout_hash(world: CpWorld) -> None:
    m = world.mandates(transaction_id="x" * 43)
    rejected(world, start(world, m), "C3", "transaction_id_mismatch", "mandate_scope_mismatch")


def test_c3_payment_mandate_made_for_another_checkout(world: CpWorld) -> None:
    other = make_checkout(checkout_id="chk_" + "b" * 22)
    mine = world.mandates()
    theirs = world.mandates(checkout=other, nonce="nonce-other")
    result = start(world, mine, payment_token=theirs.payment_token)
    rejected(world, result, "C3", "transaction_id_mismatch", "mandate_scope_mismatch")


def test_c3_checkout_hash_claim_not_equal_to_the_embedded_jwt(world: CpWorld) -> None:
    m = world.mandates(checkout_kwargs={"checkout_hash_value": "x" * 43})
    rejected(world, start(world, m), "C3", "checkout_hash_mismatch", "mandate_scope_mismatch")


def test_c3_checkout_jwt_withheld(world: CpWorld) -> None:
    m = world.mandates(checkout_kwargs={"omit_checkout_jwt": True})
    rejected(world, start(world, m), "C3", "checkout_jwt_unavailable", "mandate_scope_mismatch")


# ----- C4 payee, amount, currency -----


def test_c4_payee_is_another_merchant(world: CpWorld) -> None:
    m = world.mandates(values={"payee": {"id": "m-evil", "name": "Evil"}})
    rejected(world, start(world, m), "C4", "payee_mismatch", "mandate_scope_mismatch")


@pytest.mark.parametrize("amount", [8499, 8501, 1, 85_000, 8500.0])
def test_c4_amount_differs_from_the_checkout_total(world: CpWorld, amount: int) -> None:
    m = world.mandates(values={"payment_amount": {"amount": amount, "currency": "USD"}})
    rejected(world, start(world, m), "C4", "amount_mismatch", "mandate_scope_mismatch")


def test_c4_currency_differs_from_the_checkout_currency(world: CpWorld) -> None:
    m = world.mandates(values={"payment_amount": {"amount": 8500, "currency": "EUR"}})
    rejected(world, start(world, m), "C4", "currency_mismatch", "mandate_scope_mismatch")


@pytest.mark.parametrize(
    "amount", [{"amount": 85.0, "currency": "USD"}, {"amount": True, "currency": "USD"}, "85"]
)
def test_c4_payment_amount_must_be_exact_integer_minor_units(world: CpWorld, amount: Any) -> None:
    m = world.mandates(values={"payment_amount": amount})
    result = start(world, m)
    assert isinstance(result, CpRejected) and result.step == "C4"


# ----- C5 constraints -----


def test_c5_constraint_violation(world: CpWorld) -> None:
    m = world.mandates(
        constraints=lambda d: [
            c | ({"max": 100} if c["type"] == "payment.amount_range" else {})
            for c in payment_constraints(d)
        ]
    )
    rejected(world, start(world, m), "C5", "constraint_violated", "mandate_scope_mismatch",
             "payment.amount_range:above_max")  # fmt: skip


def test_c5_budget_exceeded(world: CpWorld) -> None:
    m = world.mandates(
        constraints=lambda d: [
            c | ({"max": 5000} if c["type"] == "payment.budget" else {})
            for c in payment_constraints(d, 10_000)
        ]
    )
    rejected(world, start(world, m), "C5", "constraint_violated", "mandate_scope_mismatch",
             "payment.budget:over_budget")  # fmt: skip


def test_c5_earlier_spend_under_the_same_open_mandate_counts(world: CpWorld) -> None:
    m = world.mandates(maximum=10_000)
    digest = sd_hash(m.payment.open_token)
    with world.engine.begin() as conn:
        world.ledger.lock(conn, digest, "USD")
        world.ledger.reserve(
            conn, spend_id="sp_old", digest=digest, checkout_id="chk_old",
            amount_minor=2000, currency="USD",
        )  # fmt: skip
        world.ledger.capture(conn, "sp_old")
    result = start(world, m)
    assert isinstance(result, CpRejected)
    assert (result.step, result.reason, result.detail) == (
        "C5", "constraint_violated", "payment.budget:over_budget",
    )  # fmt: skip
    assert world.sim.orders == {} and rows(world) == (0, 1)  # only the earlier spend exists


def test_c5_recurrence_other_than_once_is_unresolved(world: CpWorld) -> None:
    m = world.mandates(
        constraints=lambda d: [
            c | ({"max_occurrences": 3} if c["type"] == "payment.agent_recurrence" else {})
            for c in payment_constraints(d)
        ]
    )
    rejected(world, start(world, m), "C5", "constraint_unresolved", "mandate_scope_mismatch",
             "unresolved_constraint")  # fmt: skip


def test_c5_unknown_constraint_type_fails_closed(world: CpWorld) -> None:
    m = world.mandates(constraints=lambda d: [*payment_constraints(d), {"type": "acme.x"}])
    rejected(world, start(world, m), "C5", "constraint_unresolved", "mandate_scope_mismatch")


def test_c5_reference_to_another_checkout_mandate(world: CpWorld) -> None:
    m = world.mandates(constraints=lambda d: payment_constraints("A" * 43))
    rejected(world, start(world, m), "C5", "constraint_violated", "mandate_scope_mismatch",
             "payment.reference:checkout_mandate_not_referenced")  # fmt: skip


# ----- C6 single use -----


def second_checkout(n: str = "b") -> Any:
    return make_checkout(checkout_id="chk_" + n * 22)


def test_c6_nonce_replay(world: CpWorld) -> None:
    first = world.mandates(nonce="shared")
    assert isinstance(start(world, first), CpApprovalRequired)
    other = second_checkout()
    second = world.mandates(checkout=other, nonce="shared")
    result = world.provider.start(
        payment_token=second.payment_token, checkout_mandate=second.checkout_mandate, current=other
    )
    assert isinstance(result, CpRejected)
    assert (result.step, result.reason) == ("C6", "nonce_replayed")


def test_c6_open_mandate_already_in_flight(world: CpWorld) -> None:
    first = world.mandates(maximum=100_000)  # a budget that is not the reason for the refusal
    assert isinstance(start(world, first), CpApprovalRequired)
    other = second_checkout()
    second = world.mandates(
        checkout=other, nonce="second",
        reuse_open_payment=first.payment.open_token,
        reuse_checkout_open=first.checkout.open_token,
    )  # fmt: skip
    result = world.provider.start(
        payment_token=second.payment_token, checkout_mandate=second.checkout_mandate, current=other
    )
    assert isinstance(result, CpRejected)
    assert (result.step, result.reason) == ("C6", "open_mandate_in_use")
    assert len(world.sim.orders) == 1  # no second PayPal order


def test_c6_checkout_reuse(world: CpWorld) -> None:
    assert isinstance(start(world, world.mandates()), CpApprovalRequired)
    again = world.mandates(nonce="another-nonce")  # a re-signed checkout, new mandates, same id
    result = start(world, again)
    assert isinstance(result, CpRejected)
    assert (result.step, result.reason) == ("C6", "checkout_hash_reused")
    assert len(world.sim.orders) == 1

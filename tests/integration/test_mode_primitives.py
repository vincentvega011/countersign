"""The two storage switches behind `ABL_NO_GLOBAL_NONCE` and `ABL_NO_BUDGET_RECON`, on Postgres.

Each switch changes one thing, and only in the place the composition root gives it to: with it unset
the original global memory and the reconciled view are in force.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, select

from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.reservations import (
    REASON_NONCE_REPLAYED,
    AlreadyReservedError,
    ReservationRequest,
)
from countersign.tables import reservations
from tests.mode_support import reset

NONCE = ("thumb", "credential-provider", "nonce-1")


@pytest.fixture(autouse=True)
def clean(admin_engine: Engine) -> None:
    reset(admin_engine)


def request(checkout: str, *, digest: str = "open-digest") -> ReservationRequest:
    return ReservationRequest(checkout, f"hash-of-{checkout}", digest, NONCE)


def test_the_global_store_refuses_a_replayed_nonce_and_a_reused_open_mandate(
    app_engine: Engine,
) -> None:
    store = PostgresReservationStore(app_engine, "cp")
    store.reserve(request("chk_1"))
    with pytest.raises(AlreadyReservedError) as refused:
        store.reserve(request("chk_2"))
    assert refused.value.reason == REASON_NONCE_REPLAYED


def test_the_session_scoped_store_forgets_other_sessions_but_not_its_own(
    app_engine: Engine,
) -> None:
    store = PostgresReservationStore(app_engine, "cp", session_scoped=True)
    store.reserve(request("chk_1"))
    store.reserve(request("chk_2"))  # same nonce, same open mandate, another session: accepted
    with pytest.raises(AlreadyReservedError):
        store.reserve(request("chk_1"))  # the same session twice is still refused
    with app_engine.connect() as conn:
        rows = conn.execute(select(reservations).order_by(reservations.c.checkout_id)).all()
    # The nonce itself is stored untouched, so the gate's nonce comparison is unaffected.
    assert [r.nonce_value for r in rows] == ["nonce-1", "nonce-1"]

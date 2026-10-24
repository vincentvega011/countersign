"""Checkout session storage: the application role's grants and the immutability trigger."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from countersign.canonical.models import Checkout, Item
from countersign.canonical.money import Money
from countersign.protocols.ucp import store
from countersign.protocols.ucp.checkout_state import Status

CID = "chk_" + "A" * 22


def _record(status: Status = Status.READY_FOR_COMPLETE) -> store.CheckoutRecord:
    item = Item(id="sku-1", title="Thing", price=Money("USD", 250))
    return store.CheckoutRecord(
        checkout=Checkout.from_lines(CID, "USD", [("li_1", item, 1)]),
        status=status,
        version=1,
        next_line_seq=2,
        catalog_hash=b"\x01" * 32,
        created_us=1_000,
        updated_us=1_000,
        expires_us=2_000,
    )


@pytest.fixture
def row(app_engine: Engine, clean_checkouts: None) -> store.CheckoutRecord:
    record = _record()
    with app_engine.begin() as conn:
        store.insert_record(conn, record)
    return record


def test_the_application_role_cannot_delete_or_truncate(app_engine: Engine, row: object) -> None:
    for sql in ("DELETE FROM checkout_sessions", "TRUNCATE checkout_sessions"):
        with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
            conn.execute(text(sql))


def test_the_application_role_can_select_insert_and_update(
    app_engine: Engine, row: store.CheckoutRecord
) -> None:
    with app_engine.begin() as conn:
        got = store.load(conn, CID)
        assert got is not None and got.checkout.terms() == row.checkout.terms()
        store.save(conn, got.advanced(now_us=5, status=Status.CANCELED))


def test_a_final_checkout_cannot_be_changed_by_anyone(
    app_engine: Engine, admin_engine: Engine, row: store.CheckoutRecord
) -> None:
    with app_engine.begin() as conn:
        loaded = store.load(conn, CID)
        assert loaded is not None
        store.save(conn, loaded.advanced(now_us=5, status=Status.COMPLETED))
    for engine in (app_engine, admin_engine):
        with pytest.raises(DBAPIError, match="final"), engine.begin() as conn:
            conn.execute(
                text("UPDATE checkout_sessions SET status = 'ready_for_complete', version = 3")
            )


@pytest.mark.parametrize(
    "assignment",
    [
        "version = version",
        "version = version + 2",
        "version = version - 1",
        "id = 'chk_BBBBBBBBBBBBBBBBBBBBBB', version = version + 1",
        "created_us = 7, version = version + 1",
    ],
)
def test_an_update_must_advance_the_version_by_one_and_keep_identity(
    app_engine: Engine, row: object, assignment: str
) -> None:
    with pytest.raises(DBAPIError), app_engine.begin() as conn:
        conn.execute(text(f"UPDATE checkout_sessions SET {assignment}"))


def test_a_stale_writer_is_refused(app_engine: Engine, row: store.CheckoutRecord) -> None:
    with app_engine.begin() as conn:
        first = store.load(conn, CID)
        assert first is not None
        store.save(conn, first.advanced(now_us=5))
    with pytest.raises(store.VersionConflict), app_engine.begin() as conn:
        store.save(conn, first.advanced(now_us=6))  # also version 2: the row is already at 2


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE checkout_sessions SET status = 'bogus', version = version + 1",
        "UPDATE checkout_sessions SET expires_us = created_us, version = version + 1",
        "UPDATE checkout_sessions SET catalog_hash = '\\x00', version = version + 1",
        "UPDATE checkout_sessions SET next_line_seq = 0, version = version + 1",
    ],
)
def test_constraints_refuse_invalid_rows(app_engine: Engine, row: object, sql: str) -> None:
    with pytest.raises(DBAPIError), app_engine.begin() as conn:
        conn.execute(text(sql))


def test_a_malformed_id_is_refused_on_insert(app_engine: Engine, clean_checkouts: None) -> None:
    item = Item(id="sku-1", title="Thing", price=Money("USD", 250))
    bad = Checkout.from_lines("not-a-checkout-id", "USD", [("li_1", item, 1)])
    record = _record()
    record = store.CheckoutRecord(**{**record.__dict__, "checkout": bad})
    with pytest.raises(DBAPIError), app_engine.begin() as conn:
        store.insert_record(conn, record)

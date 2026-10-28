"""The database contract behind single use and the budget: grants, triggers and store parity."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from countersign.constraints import BudgetError, SpendView
from countersign.cp.ledger import SpendLedger
from countersign.merchant.pg_reservations import PostgresReservationStore
from countersign.merchant.reservations import (
    AlreadyReservedError,
    InMemoryReservationStore,
    ReservationError,
    ReservationRequest,
)


def request(n: int = 1, *, scope: bool = True, digest: str | None = None) -> ReservationRequest:
    return ReservationRequest(
        f"chk_{n}",
        f"hash_{n}",
        digest or f"digest_{n}",
        ("thumb", "aud", f"nonce_{n}") if scope else None,
    )


@pytest.fixture(params=["memory", "postgres-merchant", "postgres-cp"])
def store(request: pytest.FixtureRequest, app_engine: Engine, clean_payments: None):  # type: ignore[no-untyped-def]
    if request.param == "memory":
        return InMemoryReservationStore()
    return PostgresReservationStore(app_engine, request.param.split("-")[1])


# ----- the Postgres store honours the same contract as the in-memory one -----


def test_each_key_is_unique_on_its_own(store) -> None:  # type: ignore[no-untyped-def]
    store.reserve(request(1))
    cases = {
        "checkout_hash_reused": ReservationRequest("chk_2", "hash_1", "digest_2", ("t", "a", "n2")),
        "checkout_hash_reused ": ReservationRequest(
            "chk_1", "hash_2", "digest_2", ("t", "a", "n2")
        ),
        "nonce_replayed": ReservationRequest(
            "chk_2", "hash_2", "digest_2", ("thumb", "aud", "nonce_1")
        ),
        "open_mandate_in_use": ReservationRequest("chk_2", "hash_2", "digest_1", ("t", "a", "n2")),
    }
    for reason, clash in cases.items():
        with pytest.raises(AlreadyReservedError) as taken:
            store.reserve(clash)
        assert taken.value.reason == reason.strip()


def test_a_refused_reservation_takes_none_of_its_other_keys(store) -> None:  # type: ignore[no-untyped-def]
    store.reserve(request(1))
    with pytest.raises(AlreadyReservedError):
        store.reserve(ReservationRequest("chk_2", "hash_2", "digest_1", ("t", "a", "n2")))
    store.reserve(ReservationRequest("chk_2", "hash_2", "digest_2", ("t", "a", "n2")))


def test_abort_frees_everything_release_frees_only_the_mandate(store) -> None:  # type: ignore[no-untyped-def]
    aborted = store.reserve(request(1))
    store.abort(aborted)
    released = store.reserve(request(1))
    store.release(released)
    with pytest.raises(AlreadyReservedError) as taken:
        store.reserve(request(1))
    assert taken.value.reason == "checkout_hash_reused"  # id, hash and nonce stay consumed
    store.reserve(ReservationRequest("chk_9", "hash_9", "digest_1", None))  # the mandate is free


def test_consume_is_permanent_and_an_ended_reservation_cannot_end_again(store) -> None:  # type: ignore[no-untyped-def]
    reservation = store.reserve(request(1))
    store.consume(reservation)
    with pytest.raises(AlreadyReservedError):
        store.reserve(ReservationRequest("chk_9", "hash_9", "digest_1", None))
    for end in (store.abort, store.release, store.consume):
        with pytest.raises(ReservationError):
            end(reservation)


def test_human_present_reservations_have_no_nonce_key(store) -> None:  # type: ignore[no-untyped-def]
    store.reserve(request(1, scope=False))
    store.reserve(request(2, scope=False))  # two reservations without a nonce do not collide


def test_the_roles_are_separate_namespaces(app_engine: Engine, clean_payments: None) -> None:
    merchant = PostgresReservationStore(app_engine, "merchant")
    cp = PostgresReservationStore(app_engine, "cp")
    merchant.reserve(request(1))
    cp.reserve(request(1))  # same keys, other role: no clash
    with pytest.raises(ValueError):
        PostgresReservationStore(app_engine, "gate")


def test_twenty_parallel_reservations_of_one_key_set_make_one(
    app_engine: Engine, clean_payments: None
) -> None:
    store = PostgresReservationStore(app_engine, "cp")
    barrier = threading.Barrier(20)

    def go(n: int) -> bool:
        barrier.wait()
        try:
            store.reserve(ReservationRequest(f"chk_{n}", "same-hash", f"digest_{n}", None))
        except AlreadyReservedError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=20) as pool:
        assert sum(pool.map(go, range(20))) == 1


# ----- database-level uniqueness, independent of the store code -----


def insert(conn, handle: str, **overrides) -> None:  # type: ignore[no-untyped-def]
    values = {
        "handle": handle, "role": "cp", "checkout_id": "chk_a", "checkout_hash": "hash_a",
        "mandate_digest": "digest_a", "nonce_thumbprint": "t", "nonce_audience": "a",
        "nonce_value": "n", "state": "reserved", "created_us": 1, "updated_us": 1,
    }  # fmt: skip
    values.update(overrides)
    conn.execute(
        text(
            "INSERT INTO reservations (handle, role, checkout_id, checkout_hash, mandate_digest, "
            "nonce_thumbprint, nonce_audience, nonce_value, state, created_us, updated_us) "
            "VALUES (:handle, :role, :checkout_id, :checkout_hash, :mandate_digest, "
            ":nonce_thumbprint, :nonce_audience, :nonce_value, :state, :created_us, :updated_us)"
        ),
        values,
    )


@pytest.mark.parametrize(
    "clash",
    [
        {
            "checkout_hash": "other",
            "mandate_digest": "other",
            "nonce_value": "other",
        },  # same checkout id
        {"checkout_id": "chk_b", "mandate_digest": "other", "nonce_value": "other"},  # same hash
        {"checkout_id": "chk_b", "checkout_hash": "other", "mandate_digest": "other"},  # same nonce
        {"checkout_id": "chk_b", "checkout_hash": "other", "nonce_value": "other"},  # same mandate
    ],
)
def test_the_database_refuses_each_duplicate_key(
    app_engine: Engine, clean_payments: None, clash: dict[str, str]
) -> None:
    with app_engine.begin() as conn:
        insert(conn, "h1")
    with pytest.raises(IntegrityError), app_engine.begin() as conn:
        insert(conn, "h2", **clash)


def test_checkout_hash_alone_is_not_what_makes_a_checkout_unique(
    app_engine: Engine, clean_payments: None
) -> None:
    """Two presentations of one checkout id with different hashes (a re-signed checkout) still clash."""
    with app_engine.begin() as conn:
        insert(conn, "h1")
    with pytest.raises(IntegrityError), app_engine.begin() as conn:
        insert(conn, "h2", checkout_hash="a-different-hash", mandate_digest="d2", nonce_value="n2")


def test_reservation_triggers_forbid_illegal_changes(
    app_engine: Engine, clean_payments: None
) -> None:
    with app_engine.begin() as conn:
        insert(conn, "h1")
    for sql in (
        "UPDATE reservations SET checkout_id = 'x' WHERE handle = 'h1'",
        "UPDATE reservations SET nonce_value = 'x' WHERE handle = 'h1'",
        "UPDATE reservations SET state = 'reserved' WHERE handle = 'h1'",
    ):
        with pytest.raises(DBAPIError), app_engine.begin() as conn:
            conn.execute(text(sql))
    with app_engine.begin() as conn:
        conn.execute(text("UPDATE reservations SET state = 'released' WHERE handle = 'h1'"))
    for state in ("reserved", "consumed", "aborted"):
        with pytest.raises(DBAPIError), app_engine.begin() as conn:
            conn.execute(text(f"UPDATE reservations SET state = '{state}' WHERE handle = 'h1'"))


# ----- the application role cannot rewrite history -----


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM reservations",
        "DELETE FROM spend_entries",
        "DELETE FROM open_payment_mandates",
        "DELETE FROM payment_attempts",
        "DELETE FROM payer_vault",
        "TRUNCATE reservations",
        "TRUNCATE spend_entries",
        "UPDATE decision_log SET kind = 'x'",
        "DELETE FROM decision_log",
        "TRUNCATE decision_log",
    ],
)
def test_the_application_role_has_no_update_delete_or_truncate_where_history_lives(
    app_engine: Engine, clean_payments: None, sql: str
) -> None:
    with pytest.raises(DBAPIError) as caught, app_engine.begin() as conn:
        conn.execute(text(sql))
    assert "permission denied" in str(caught.value).lower()


# ----- the spend ledger is add-only in the database -----


def test_the_ledger_follows_the_add_only_rules(app_engine: Engine, clean_payments: None) -> None:
    ledger = SpendLedger()
    with app_engine.begin() as conn:
        ledger.lock(conn, "d", "USD")
        ledger.reserve(
            conn, spend_id="a", digest="d", checkout_id="c1", amount_minor=4000, currency="USD"
        )
        ledger.reserve(
            conn, spend_id="b", digest="d", checkout_id="c2", amount_minor=1000, currency="USD"
        )
        assert ledger.view(conn, "d", "USD") == SpendView("USD", 0, 5000)
        ledger.capture(conn, "a")
        ledger.void(conn, "b")
        assert ledger.view(conn, "d", "USD") == SpendView("USD", 4000, 0)
        ledger.refund(conn, "a", 4000)
        assert ledger.view(conn, "d", "USD") == SpendView(
            "USD", 4000, 0
        )  # a refund restores nothing


@pytest.mark.parametrize(
    "event",
    [
        lambda g, c: g.capture(c, "nope"),
        lambda g, c: g.void(c, "nope"),
        lambda g, c: g.refund(c, "nope", 1),
        lambda g, c: g.reserve(
            c, spend_id="x", digest="d", checkout_id="c9", amount_minor=0, currency="USD"
        ),
        lambda g, c: g.reserve(
            c, spend_id="a", digest="d", checkout_id="c9", amount_minor=5, currency="USD"
        ),
        lambda g, c: g.reserve(
            c, spend_id="x", digest="d", checkout_id="c1", amount_minor=5, currency="USD"
        ),
        lambda g, c: (g.capture(c, "a"), g.void(c, "a")),
        lambda g, c: (g.capture(c, "a"), g.capture(c, "a")),
        lambda g, c: (g.capture(c, "a"), g.refund(c, "a", 4001)),
        lambda g, c: g.refund(c, "a", 1),  # refund before capture
        lambda g, c: g.lock(c, "d", "EUR"),
    ],
)
def test_every_other_transition_is_refused(app_engine: Engine, clean_payments: None, event) -> None:  # type: ignore[no-untyped-def]
    ledger = SpendLedger()
    with app_engine.begin() as conn:
        ledger.lock(conn, "d", "USD")
        ledger.reserve(
            conn, spend_id="a", digest="d", checkout_id="c1", amount_minor=4000, currency="USD"
        )
    with pytest.raises(BudgetError), app_engine.begin() as conn:
        event(ledger, conn)


def test_spend_triggers_hold_even_for_raw_sql(app_engine: Engine, clean_payments: None) -> None:
    ledger = SpendLedger()
    with app_engine.begin() as conn:
        ledger.lock(conn, "d", "USD")
        ledger.reserve(
            conn, spend_id="a", digest="d", checkout_id="c1", amount_minor=4000, currency="USD"
        )
        ledger.capture(conn, "a")
        ledger.refund(conn, "a", 1000)
    for sql in (
        "UPDATE spend_entries SET state = 'in_flight' WHERE id = 'a'",
        "UPDATE spend_entries SET state = 'voided' WHERE id = 'a'",
        "UPDATE spend_entries SET amount_minor = 1 WHERE id = 'a'",
        "UPDATE spend_entries SET refunded_minor = 0 WHERE id = 'a'",
        "UPDATE spend_entries SET refunded_minor = 4001 WHERE id = 'a'",
    ):
        with pytest.raises(DBAPIError), app_engine.begin() as conn:
            conn.execute(text(sql))


def test_attempt_triggers(app_engine: Engine, clean_payments: None) -> None:
    with app_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO payment_attempts (checkout_id, reservation_handle, spend_id, mandate_digest, "
                "state, mode, custom_id, created_us, updated_us) VALUES "
                "('c', 'h', 's', 'd', 'reserved', 'redirect', 'cs1.x', 1, 1)"
            )
        )
        conn.execute(text("UPDATE payment_attempts SET order_id = 'O1', state = 'order_created'"))
    for sql in (
        "UPDATE payment_attempts SET order_id = 'O2'",
        "UPDATE payment_attempts SET custom_id = 'other'",
        "UPDATE payment_attempts SET spend_id = 'other'",
    ):
        with pytest.raises(DBAPIError), app_engine.begin() as conn:
            conn.execute(text(sql))
    with app_engine.begin() as conn:
        conn.execute(text("UPDATE payment_attempts SET state = 'voided'"))
    with pytest.raises(DBAPIError), app_engine.begin() as conn:
        conn.execute(text("UPDATE payment_attempts SET state = 'authorized'"))


def test_a_reservation_is_only_loaded_by_its_own_role(
    app_engine: Engine, clean_payments: None
) -> None:
    merchant = PostgresReservationStore(app_engine, "merchant")
    cp = PostgresReservationStore(app_engine, "cp")
    held = merchant.reserve(request(1))
    with app_engine.connect() as conn:
        assert merchant.load(conn, held.handle) is not None
        assert cp.load(conn, held.handle) is None

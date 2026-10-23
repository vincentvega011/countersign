"""The decision log against the real Postgres: grants, tamper detection, concurrency, constraints."""

from __future__ import annotations

import hashlib
import threading
from datetime import UTC, date, datetime

import psycopg.errors
import pytest
from alembic import command
from conftest import LedgerDb, alembic_config, create_database, drop_database, scratch_urls
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from countersign.canonical import canonicalize
from countersign.ledger import verify_inclusion
from countersign.ledger.chain import GENESIS_PREV
from countersign.ledger.merkle import MerkleError, merkle_root
from countersign.ledger.store import (
    ADVISORY_LOCK_KEY,
    anchor_of,
    append,
    checkout_proof,
    checkout_root,
    day_proof,
    day_root,
    entries_for_checkout,
    head,
    read_entries,
    verify_log,
)

POLICY = hashlib.sha256(b"policy v1").digest()
DAY = date(2026, 10, 23)
DAY_START_US = int(datetime(2026, 10, 23, tzinfo=UTC).timestamp()) * 1_000_000


def fill(engine: Engine, n: int, *, checkout: str = "chk_1") -> list:
    entries = []
    for i in range(1, n + 1):
        with engine.begin() as conn:
            entries.append(
                append(
                    conn,
                    kind="G-FETCH" if i % 2 else "G-AMOUNT",
                    payload={"n": i},
                    policy_hash=POLICY,
                    checkout_id=checkout if i % 4 else None,
                    ts_us=DAY_START_US + i * 1_000_000,
                )
            )
    return entries


# ---- the migration and the grants ----


def test_the_application_role_holds_insert_and_select_only(
    ledger_db: LedgerDb, admin_engine: Engine
):
    with admin_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                "WHERE table_name = 'decision_log' AND table_schema = 'public'"
            )
        ).all()
    by_grantee: dict[str, set[str]] = {}
    for grantee, privilege in rows:
        by_grantee.setdefault(grantee, set()).add(privilege)
    assert by_grantee[ledger_db.role] == {"INSERT", "SELECT"}
    assert "PUBLIC" not in by_grantee


@pytest.mark.usefixtures("clean_log")
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE decision_log SET kind = 'X-REWRITTEN'",
        "UPDATE decision_log SET payload = '{}'::bytea WHERE seq = 1",
        "DELETE FROM decision_log",
        "DELETE FROM decision_log WHERE seq = 1",
        "TRUNCATE decision_log",
        "DROP TABLE decision_log",
        "ALTER TABLE decision_log DROP COLUMN payload",
        "ALTER TABLE decision_log DISABLE TRIGGER ALL",
        "CREATE TRIGGER t BEFORE INSERT ON decision_log FOR EACH ROW EXECUTE FUNCTION now()",
        "SELECT * FROM alembic_version",
    ],
)
def test_the_application_role_cannot_rewrite_or_remove_history(statement: str, app_engine: Engine):
    fill(app_engine, 2)
    with pytest.raises(ProgrammingError) as info, app_engine.begin() as conn:
        conn.execute(text(statement))
    assert isinstance(
        info.value.orig, (psycopg.errors.InsufficientPrivilege, psycopg.errors.WrongObjectType)
    ), type(info.value.orig)
    with app_engine.connect() as conn:
        assert len(read_entries(conn)) == 2  # nothing changed


@pytest.mark.usefixtures("clean_log")
def test_the_application_role_cannot_grant_itself_more(
    ledger_db: LedgerDb, app_engine: Engine, admin_engine: Engine
):
    """GRANT by a role without the grant option does not error in Postgres (it only warns), so the
    property to check is that no privilege was added."""
    fill(app_engine, 1)
    with app_engine.begin() as conn:
        conn.execute(text(f'GRANT UPDATE, DELETE ON decision_log TO "{ledger_db.role}"'))
        conn.execute(text("GRANT UPDATE ON decision_log TO PUBLIC"))
    with admin_engine.connect() as conn:
        privileges = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_name = 'decision_log' AND grantee = :r"
                ),
                {"r": ledger_db.role},
            )
        }
        public = conn.execute(
            text(
                "SELECT count(*) FROM information_schema.role_table_grants "
                "WHERE table_name = 'decision_log' AND grantee = 'PUBLIC'"
            )
        ).scalar()
    assert privileges == {"INSERT", "SELECT"} and public == 0
    with pytest.raises(ProgrammingError), app_engine.begin() as conn:
        conn.execute(text("UPDATE decision_log SET kind = 'X-REWRITTEN'"))


@pytest.mark.usefixtures("clean_log")
def test_the_application_role_can_append_and_read(app_engine: Engine):
    entries = fill(app_engine, 3)
    with app_engine.connect() as conn:
        assert [e.seq for e in read_entries(conn)] == [1, 2, 3]
        assert verify_log(conn).ok
        assert head(conn) == entries[-1]


def test_downgrade_and_upgrade_again(server_url: str):
    name, url = scratch_urls(server_url)
    role = "cs_mig_" + name[-8:]
    create_database(server_url, name)
    try:
        config = alembic_config(url, role)
        command.upgrade(config, "head")
        engine = create_engine(url)
        with engine.connect() as conn:
            assert (
                conn.execute(text("SELECT to_regclass('public.decision_log')")).scalar() is not None
            )
        command.downgrade(config, "base")
        with engine.connect() as conn:
            assert conn.execute(text("SELECT to_regclass('public.decision_log')")).scalar() is None
        command.upgrade(config, "head")  # the role already exists: must not fail
        engine.dispose()
    finally:
        drop_database(server_url, name, role)


def test_the_role_name_is_validated(server_url: str):
    name, url = scratch_urls(server_url)
    create_database(server_url, name)
    try:
        with pytest.raises(RuntimeError, match="lowercase identifier"):
            command.upgrade(alembic_config(url, 'x"; DROP TABLE y; --'), "head")
    finally:
        drop_database(server_url, name, None)


# ---- append, read, roots, proofs ----


@pytest.mark.usefixtures("clean_log")
def test_payload_is_stored_as_the_exact_jcs_bytes(app_engine: Engine):
    payload = {"b": 2, "a": [1, {"z": "é", "y": True}], "n": None}
    with app_engine.begin() as conn:
        entry = append(conn, kind="CP.AUTHORIZE", payload=payload, policy_hash=POLICY)
    with app_engine.connect() as conn:
        stored = read_entries(conn)[0]
    assert stored == entry
    assert stored.payload == canonicalize(payload)
    assert stored.prev_hash == GENESIS_PREV and stored.seq == 1


@pytest.mark.usefixtures("clean_log")
def test_checkout_root_and_proofs(app_engine: Engine):
    entries = fill(app_engine, 11)
    mine = [e for e in entries if e.checkout_id == "chk_1"]
    with app_engine.connect() as conn:
        root = checkout_root(conn, "chk_1")
        assert root.scope == "checkout:chk_1" and root.size == len(mine)
        assert root.root == merkle_root([e.entry_hash for e in mine])
        assert [e.seq for e in entries_for_checkout(conn, "chk_1")] == [e.seq for e in mine]
        for entry in mine:
            r, proof = checkout_proof(conn, "chk_1", entry.seq)
            assert r == root and verify_inclusion(entry.entry_hash, proof, r.root)
        with pytest.raises(MerkleError):
            checkout_proof(conn, "chk_1", entries[3].seq)  # seq 4 has no checkout
        empty = checkout_root(conn, "nobody")
        assert empty.size == 0 and empty.root == merkle_root([])


@pytest.mark.usefixtures("clean_log")
def test_day_root_covers_the_utc_day_only(app_engine: Engine):
    edge = [
        (DAY_START_US - 1, "before"),
        (DAY_START_US, "start"),
        (DAY_START_US + 86_400_000_000 - 1, "last-microsecond"),
        (DAY_START_US + 86_400_000_000, "next-day"),
    ]
    inside = []
    for ts, label in edge:
        with app_engine.begin() as conn:
            e = append(conn, kind="EDGE", payload={"label": label}, policy_hash=POLICY, ts_us=ts)
        if label in {"start", "last-microsecond"}:
            inside.append(e)
    with app_engine.connect() as conn:
        root = day_root(conn, DAY)
        assert root.scope == "day:2026-10-23" and root.size == 2
        assert root.root == merkle_root([e.entry_hash for e in inside])
        for e in inside:
            r, proof = day_proof(conn, DAY, e.seq)
            assert verify_inclusion(e.entry_hash, proof, r.root)
        assert day_root(conn, date(2026, 10, 25)).size == 0


@pytest.mark.usefixtures("clean_log")
def test_a_root_changes_when_history_is_changed_by_an_administrator(
    app_engine: Engine, admin_engine: Engine
):
    entries = fill(app_engine, 8)
    with app_engine.connect() as conn:
        before = checkout_root(conn, "chk_1").root
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE decision_log SET payload = :p WHERE seq = 2"), {"p": b"{}"})
    with app_engine.connect() as conn:
        assert checkout_root(conn, "chk_1").root == before  # roots hash entry hashes...
        assert not verify_log(conn).ok  # ...so verification is what exposes the edit
    assert entries[1].seq == 2


# ---- tamper detection on the real table ----


def break_of(engine: Engine, **kwargs):
    with engine.connect() as conn:
        result = verify_log(conn, **kwargs)
    assert not result.ok and result.first_break is not None
    return result.first_break


@pytest.mark.usefixtures("clean_log")
def test_modification_is_detected(app_engine: Engine, admin_engine: Engine):
    fill(app_engine, 10)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE decision_log SET payload = :p WHERE seq = 6"), {"p": b'{"n":999}'}
        )
    found = break_of(app_engine)
    assert (found.index, found.seq, found.code) == (5, 6, "payload_hash_mismatch")


@pytest.mark.usefixtures("clean_log")
@pytest.mark.parametrize(
    "column, assignment, code",
    [
        ("kind", "kind = 'G-OTHER'", "entry_hash_mismatch"),
        ("checkout_id", "checkout_id = 'chk_other'", "entry_hash_mismatch"),
        ("ts_us", "ts_us = ts_us + 1", "entry_hash_mismatch"),
        ("policy_hash", "policy_hash = decode(repeat('ab', 32), 'hex')", "entry_hash_mismatch"),
        ("prev_hash", "prev_hash = decode(repeat('cd', 32), 'hex')", "prev_mismatch"),
        ("entry_hash", "entry_hash = decode(repeat('ef', 32), 'hex')", "entry_hash_mismatch"),
    ],
)
def test_changing_any_column_is_detected(
    column, assignment, code, app_engine: Engine, admin_engine: Engine
):
    fill(app_engine, 8)
    with admin_engine.begin() as conn:
        conn.execute(text(f"UPDATE decision_log SET {assignment} WHERE seq = 4"))
    found = break_of(app_engine)
    assert (found.index, found.code) == (3, code)


@pytest.mark.usefixtures("clean_log")
def test_deletion_is_detected(app_engine: Engine, admin_engine: Engine):
    fill(app_engine, 10)
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM decision_log WHERE seq = 5"))
    found = break_of(app_engine)
    assert found.index == 4 and found.code == "seq_unexpected"


@pytest.mark.usefixtures("clean_log")
def test_deleting_the_newest_entries_is_detected_only_against_an_anchor(
    app_engine: Engine, admin_engine: Engine
):
    fill(app_engine, 10)
    with app_engine.connect() as conn:
        anchor = anchor_of(conn)
    assert anchor is not None and anchor.seq == 10
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM decision_log WHERE seq > 6"))
    with app_engine.connect() as conn:
        assert verify_log(conn).ok  # a consistent prefix
    found = break_of(app_engine, anchor=anchor)
    assert found.code == "truncated"


@pytest.mark.usefixtures("clean_log")
def test_anchor_mismatch_is_detected_inside_the_log(app_engine: Engine, admin_engine: Engine):
    fill(app_engine, 6)
    with app_engine.connect() as conn:
        anchor = anchor_of(conn)
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE decision_log"))
    fill(app_engine, 8, checkout="chk_rewritten")  # a different but self-consistent history
    with app_engine.connect() as conn:
        assert verify_log(conn).ok
    assert break_of(app_engine, anchor=anchor).code == "anchor_mismatch"


@pytest.mark.usefixtures("clean_log")
def test_insertion_of_a_validly_linked_forgery_is_detected(
    app_engine: Engine, admin_engine: Engine
):
    from countersign.ledger import make_entry

    entries = fill(app_engine, 8)
    forged = make_entry(
        seq=5,
        prev_hash=entries[3].entry_hash,
        ts_us=entries[3].ts_us,
        checkout_id="chk_1",
        kind="G-FETCH",
        payload=b'{"forged":true}',
        policy_hash=POLICY,
    )
    with admin_engine.begin() as conn:
        # Make room at seq 5 and point the old fifth entry at the forgery.
        conn.execute(text("UPDATE decision_log SET seq = seq + 1000 WHERE seq > 4"))
        conn.execute(text("UPDATE decision_log SET seq = seq - 999 WHERE seq > 1000"))
        conn.execute(
            text("UPDATE decision_log SET prev_hash = :h WHERE seq = 6"), {"h": forged.entry_hash}
        )
        conn.execute(
            text(
                "INSERT INTO decision_log (seq, ts_us, checkout_id, kind, payload, payload_hash, "
                "policy_hash, prev_hash, entry_hash) VALUES "
                "(5, :ts, :cid, :kind, :payload, :ph, :pol, :prev, :eh)"
            ),
            {
                "ts": forged.ts_us,
                "cid": forged.checkout_id,
                "kind": forged.kind,
                "payload": forged.payload,
                "ph": forged.payload_hash,
                "pol": forged.policy_hash,
                "prev": forged.prev_hash,
                "eh": forged.entry_hash,
            },
        )
    found = break_of(app_engine)
    # The forged entry is itself valid; the entry after it no longer matches its own hash.
    assert found.index == 5 and found.code == "entry_hash_mismatch"


@pytest.mark.usefixtures("clean_log")
def test_inserting_a_second_child_of_an_existing_entry_is_refused_by_the_database(
    app_engine: Engine, admin_engine: Engine
):
    from countersign.ledger import make_entry

    entries = fill(app_engine, 4)
    forged = make_entry(
        seq=5,
        prev_hash=entries[2].entry_hash,  # entry 3 already has a child
        ts_us=entries[2].ts_us,
        checkout_id=None,
        kind="G-FETCH",
        payload=b"{}",
        policy_hash=POLICY,
    )
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO decision_log (seq, ts_us, kind, payload, payload_hash, policy_hash, "
                "prev_hash, entry_hash) VALUES (5, :ts, :kind, :payload, :ph, :pol, :prev, :eh)"
            ),
            {
                "ts": forged.ts_us,
                "kind": forged.kind,
                "payload": forged.payload,
                "ph": forged.payload_hash,
                "pol": forged.policy_hash,
                "prev": forged.prev_hash,
                "eh": forged.entry_hash,
            },
        )


@pytest.mark.usefixtures("clean_log")
def test_reordering_is_detected(app_engine: Engine, admin_engine: Engine):
    fill(app_engine, 8)
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE decision_log SET seq = 1000 WHERE seq = 3"))
        conn.execute(text("UPDATE decision_log SET seq = 3 WHERE seq = 4"))
        conn.execute(text("UPDATE decision_log SET seq = 4 WHERE seq = 1000"))
    found = break_of(app_engine)
    assert found.index == 2 and found.code == "prev_mismatch"


@pytest.mark.usefixtures("clean_log")
def test_verification_in_batches_reports_the_global_index(app_engine: Engine, admin_engine: Engine):
    fill(app_engine, 10)
    with app_engine.connect() as conn:
        assert verify_log(conn, batch_size=3).ok
        assert verify_log(conn, batch_size=1).ok
        assert verify_log(conn, batch_size=10).ok
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE decision_log SET kind = 'X-TAMPERED' WHERE seq = 8"))
    with app_engine.connect() as conn:
        for size in (1, 3, 4, 7, 100):
            result = verify_log(conn, batch_size=size)
            assert result.first_break is not None and result.first_break.index == 7, size


# ---- concurrency and database-level backstops ----


@pytest.mark.usefixtures("clean_log")
def test_concurrent_appends_form_one_consistent_chain(app_engine: Engine):
    workers, each = 8, 25
    errors: list[BaseException] = []
    barrier = threading.Barrier(workers)

    def work(worker: int) -> None:
        try:
            barrier.wait()
            for i in range(each):
                with app_engine.begin() as conn:
                    append(
                        conn,
                        kind="DECISION",
                        payload={"worker": worker, "i": i},
                        policy_hash=POLICY,
                        checkout_id=f"chk_{worker % 3}",
                    )
        except BaseException as exc:  # noqa: BLE001  (collected and re-raised below)
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(w,)) for w in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors[0]

    with app_engine.connect() as conn:
        entries = read_entries(conn)
        assert [e.seq for e in entries] == list(range(1, workers * each + 1))
        assert verify_log(conn).ok
    assert len({e.prev_hash for e in entries}) == len(entries)  # no two entries share a parent
    assert len({e.entry_hash for e in entries}) == len(entries)
    seen = {(e.payload) for e in entries}
    assert len(seen) == workers * each  # nothing lost, nothing duplicated


@pytest.mark.usefixtures("clean_log")
def test_the_unique_constraints_refuse_a_fork_even_without_the_lock(
    admin_engine: Engine, app_engine: Engine
):
    entries = fill(app_engine, 2)
    sql = text(
        "INSERT INTO decision_log (seq, ts_us, checkout_id, kind, payload, payload_hash, "
        "policy_hash, prev_hash, entry_hash) VALUES (:seq, 1, NULL, 'K', '{}'::bytea, :h, :h, :prev, :eh)"
    )
    h = hashlib.sha256(b"x").digest()
    base = {"h": h, "prev": entries[1].entry_hash, "eh": hashlib.sha256(b"new").digest()}
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(sql, {**base, "seq": 2})  # duplicate seq
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(
            sql, {**base, "seq": 3, "prev": entries[0].entry_hash}
        )  # second child of entry 1
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(sql, {**base, "seq": 3, "eh": entries[0].entry_hash})  # duplicate entry hash


@pytest.mark.usefixtures("clean_log")
@pytest.mark.parametrize(
    "column, value",
    [
        ("seq", "0"),
        ("ts_us", "-1"),
        ("kind", "'has space'"),
        ("kind", "''"),
        ("checkout_id", "''"),
        ("checkout_id", "repeat('x', 128)"),
        ("payload", "''::bytea"),
        ("payload_hash", "decode('00', 'hex')"),
        ("policy_hash", "decode('00', 'hex')"),
        ("prev_hash", "decode('00', 'hex')"),
        ("entry_hash", "decode('00', 'hex')"),
    ],
)
def test_check_constraints_refuse_malformed_rows(column: str, value: str, admin_engine: Engine):
    good = {
        "seq": "1",
        "ts_us": "1",
        "checkout_id": "NULL",
        "kind": "'K'",
        "payload": "'{}'::bytea",
        "payload_hash": "decode(repeat('01', 32), 'hex')",
        "policy_hash": "decode(repeat('02', 32), 'hex')",
        "prev_hash": "decode(repeat('03', 32), 'hex')",
        "entry_hash": "decode(repeat('04', 32), 'hex')",
    }
    good[column] = value
    columns = ", ".join(good)
    values = ", ".join(good.values())
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(text(f"INSERT INTO decision_log ({columns}) VALUES ({values})"))


@pytest.mark.usefixtures("clean_log")
def test_a_rolled_back_transaction_leaves_no_entry_and_no_gap(app_engine: Engine):
    class Boom(Exception):
        pass

    with pytest.raises(Boom), app_engine.begin() as conn:
        append(conn, kind="DECISION", payload={"n": 1}, policy_hash=POLICY)
        raise Boom
    with app_engine.begin() as conn:
        entry = append(conn, kind="DECISION", payload={"n": 2}, policy_hash=POLICY)
    assert entry.seq == 1 and entry.prev_hash == GENESIS_PREV


@pytest.mark.usefixtures("clean_log")
def test_an_invalid_append_changes_nothing_and_does_not_block_the_next(app_engine: Engine):
    from countersign.ledger import LedgerFormatError

    with pytest.raises(LedgerFormatError), app_engine.begin() as conn:
        append(conn, kind="bad kind", payload={"n": 1}, policy_hash=POLICY)
    with pytest.raises(LedgerFormatError), app_engine.begin() as conn:
        append(conn, kind="OK", payload=[1, 2], policy_hash=POLICY)  # type: ignore[arg-type]
    with pytest.raises(LedgerFormatError), app_engine.begin() as conn:
        append(conn, kind="OK", payload={"n": float("nan")}, policy_hash=POLICY)
    with app_engine.begin() as conn:
        assert append(conn, kind="OK", payload={"n": 1}, policy_hash=POLICY).seq == 1


def test_the_advisory_lock_key_is_a_valid_bigint():
    assert 0 < ADVISORY_LOCK_KEY < 2**63

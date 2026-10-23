"""The decision log in Postgres: append, read, verify, Merkle roots and inclusion proofs.

Security reasoning. Appends are serialized by a transaction-level advisory lock taken before the
head is read, so concurrent writers form one chain and never a fork; the primary key on `seq` and
the unique constraint on `prev_hash` are the database-level backstop if the lock were ever skipped.
The application role holds INSERT and SELECT on the table and nothing else (the migration), so a
compromised application cannot rewrite history; changes made by an administrator are caught by
`verify_log`. `payload` is stored as the exact JCS bytes in a `bytea` column, because a `jsonb`
column would normalize the document and break the payload hash.

`append` runs in the caller's transaction and holds the lock until that transaction ends, so the
caller should commit promptly. If the surrounding transaction rolls back, the entry disappears with
it; INV-12 callers therefore append in a transaction that commits before the response is sent.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import (
    BigInteger,
    Column,
    Connection,
    LargeBinary,
    MetaData,
    Row,
    Table,
    Text,
    insert,
    select,
    text,
)

from countersign.canonical.jcs import JcsError, canonicalize
from countersign.ledger.chain import (
    GENESIS_PREV,
    Anchor,
    Break,
    LedgerFormatError,
    LogEntry,
    VerifyResult,
    make_entry,
    verify_chain,
)
from countersign.ledger.merkle import (
    InclusionProof,
    MerkleError,
    MerkleRoot,
    inclusion_proof,
    merkle_root,
)

ADVISORY_LOCK_KEY = 0x636F756E74657273  # "counters": one lock for the whole log

decision_log = Table(
    "decision_log",
    MetaData(),
    Column("seq", BigInteger, primary_key=True, autoincrement=False),
    Column("ts_us", BigInteger, nullable=False),
    Column("checkout_id", Text),
    Column("kind", Text, nullable=False),
    Column("payload", LargeBinary, nullable=False),
    Column("payload_hash", LargeBinary, nullable=False),
    Column("policy_hash", LargeBinary, nullable=False),
    Column("prev_hash", LargeBinary, nullable=False),
    Column("entry_hash", LargeBinary, nullable=False),
)


def _entry(row: Row[Any]) -> LogEntry:
    return LogEntry(
        seq=row.seq,
        ts_us=row.ts_us,
        checkout_id=row.checkout_id,
        kind=row.kind,
        payload=bytes(row.payload),
        payload_hash=bytes(row.payload_hash),
        policy_hash=bytes(row.policy_hash),
        prev_hash=bytes(row.prev_hash),
        entry_hash=bytes(row.entry_hash),
    )


def append(
    conn: Connection,
    *,
    kind: str,
    payload: Mapping[str, Any],
    policy_hash: bytes,
    checkout_id: str | None = None,
    ts_us: int | None = None,
) -> LogEntry:
    """Append one entry to the chain and return it."""
    if not isinstance(payload, Mapping):
        raise LedgerFormatError("payload must be a JSON object")
    try:
        payload_bytes = canonicalize(dict(payload))
    except JcsError as exc:
        raise LedgerFormatError(f"payload has no canonical form: {exc}") from exc
    conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADVISORY_LOCK_KEY})
    head = conn.execute(
        select(decision_log.c.seq, decision_log.c.entry_hash)
        .order_by(decision_log.c.seq.desc())
        .limit(1)
    ).first()
    seq, prev_hash = (1, GENESIS_PREV) if head is None else (head.seq + 1, bytes(head.entry_hash))
    entry = make_entry(
        seq=seq,
        prev_hash=prev_hash,
        ts_us=time.time_ns() // 1000 if ts_us is None else ts_us,
        checkout_id=checkout_id,
        kind=kind,
        payload=payload_bytes,
        policy_hash=policy_hash,
    )
    conn.execute(
        insert(decision_log).values(
            seq=entry.seq,
            ts_us=entry.ts_us,
            checkout_id=entry.checkout_id,
            kind=entry.kind,
            payload=entry.payload,
            payload_hash=entry.payload_hash,
            policy_hash=entry.policy_hash,
            prev_hash=entry.prev_hash,
            entry_hash=entry.entry_hash,
        )
    )
    return entry


def read_entries(
    conn: Connection, *, after_seq: int = 0, limit: int | None = None
) -> list[LogEntry]:
    query = select(decision_log).where(decision_log.c.seq > after_seq).order_by(decision_log.c.seq)
    if limit is not None:
        query = query.limit(limit)
    return [_entry(r) for r in conn.execute(query)]


def head(conn: Connection) -> LogEntry | None:
    row = conn.execute(select(decision_log).order_by(decision_log.c.seq.desc()).limit(1)).first()
    return None if row is None else _entry(row)


def anchor_of(conn: Connection) -> Anchor | None:
    """The newest entry as an `Anchor`, to be stored somewhere the writer cannot change."""
    newest = head(conn)
    return None if newest is None else Anchor(newest.seq, newest.entry_hash)


def entries_for_checkout(conn: Connection, checkout_id: str) -> list[LogEntry]:
    query = (
        select(decision_log)
        .where(decision_log.c.checkout_id == checkout_id)
        .order_by(decision_log.c.seq)
    )
    return [_entry(r) for r in conn.execute(query)]


def _day_bounds_us(day: date) -> tuple[int, int]:
    start = datetime(day.year, day.month, day.day, tzinfo=UTC)
    end = start + timedelta(days=1)
    return int(start.timestamp()) * 1_000_000, int(end.timestamp()) * 1_000_000


def entries_for_day(conn: Connection, day: date) -> list[LogEntry]:
    """Entries whose timestamp falls in the UTC day, in sequence order."""
    start, end = _day_bounds_us(day)
    query = (
        select(decision_log)
        .where(decision_log.c.ts_us >= start, decision_log.c.ts_us < end)
        .order_by(decision_log.c.seq)
    )
    return [_entry(r) for r in conn.execute(query)]


def verify_log(
    conn: Connection, *, anchor: Anchor | None = None, batch_size: int = 1000
) -> VerifyResult:
    """Verify the whole table, in batches, and report the first broken link."""
    expected_seq, prev_hash, checked = 1, GENESIS_PREV, 0
    while True:
        rows = read_entries(conn, after_seq=expected_seq - 1, limit=batch_size)
        if not rows:
            break
        result = verify_chain(rows, first_seq=expected_seq, prev_hash=prev_hash)
        if not result.ok and result.first_break is not None:
            found = result.first_break
            index = checked + found.index
            return VerifyResult(False, index, Break(index, found.seq, found.code, found.message))
        checked += len(rows)
        expected_seq += len(rows)
        prev_hash = rows[-1].entry_hash
        if len(rows) < batch_size:
            break
    if anchor is not None:
        newest = expected_seq - 1
        if anchor.seq > newest:
            message = f"the log ends at seq {newest} but the anchor is at seq {anchor.seq}"
            return VerifyResult(False, checked, Break(checked, None, "truncated", message))
        stored = conn.execute(
            select(decision_log.c.entry_hash).where(decision_log.c.seq == anchor.seq)
        ).scalar_one_or_none()
        if stored is None or bytes(stored) != anchor.entry_hash:
            message = f"entry at seq {anchor.seq} differs from the anchor"
            index = anchor.seq - 1
            return VerifyResult(False, index, Break(index, anchor.seq, "anchor_mismatch", message))
    return VerifyResult(True, checked, None)


def _root(scope: str, entries: list[LogEntry]) -> MerkleRoot:
    return MerkleRoot(scope, len(entries), merkle_root([e.entry_hash for e in entries]))


def _proof(scope: str, entries: list[LogEntry], seq: int) -> tuple[MerkleRoot, InclusionProof]:
    for index, entry in enumerate(entries):
        if entry.seq == seq:
            hashes = [e.entry_hash for e in entries]
            return _root(scope, entries), inclusion_proof(hashes, index)
    raise MerkleError(f"seq {seq} is not in {scope}")


def checkout_root(conn: Connection, checkout_id: str) -> MerkleRoot:
    return _root(f"checkout:{checkout_id}", entries_for_checkout(conn, checkout_id))


def day_root(conn: Connection, day: date) -> MerkleRoot:
    return _root(f"day:{day.isoformat()}", entries_for_day(conn, day))


def checkout_proof(
    conn: Connection, checkout_id: str, seq: int
) -> tuple[MerkleRoot, InclusionProof]:
    return _proof(f"checkout:{checkout_id}", entries_for_checkout(conn, checkout_id), seq)


def day_proof(conn: Connection, day: date, seq: int) -> tuple[MerkleRoot, InclusionProof]:
    return _proof(f"day:{day.isoformat()}", entries_for_day(conn, day), seq)

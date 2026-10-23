"""The hash-chained decision log: entries, hashing and verification. No database in this module.

Security reasoning. Every decision, PayPal call, webhook and gate result is appended before the
response returns (INV-12), so the log is the record a dispute or an audit relies on. It must show
tampering, which means each entry commits to everything before it:

    entry_hash = SHA-256("cs.log.v1" 0x00 || prev || seq || ts || checkout_id || kind
                         || payload_hash || policy_hash)

Each component has a fixed width or a length prefix, so two different entries can never encode to
the same bytes (("ab", "c") and ("a", "bc") hash differently). `checkout_id` and `kind` are inside
the hash, not only in the payload, because the per-checkout Merkle tree groups entries by them: a
tamper that moved an entry between checkouts must not leave the chain valid.

What verification detects: any change to an entry (the first broken link is that entry), deletion,
insertion and reordering (a sequence number or `prev` link no longer matches). What it cannot
detect alone: someone who rewrites the whole chain from some point on, or removes the newest
entries, produces a log that is internally consistent. Both are caught by comparing against an
`Anchor` (the newest `seq` and `entry_hash`) or a Merkle root that was published or stored
somewhere the attacker could not reach. This is a tamper-evident log, not a blockchain.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Sequence
from dataclasses import dataclass, replace

from countersign.canonical.hashing import domain_hash

LOG_DOMAIN = "cs.log.v1"
PAYLOAD_DOMAIN = "cs.log.payload.v1"
HASH_LEN = 32
GENESIS_PREV = bytes(HASH_LEN)
MAX_INT64 = 2**63 - 1
MAX_CHECKOUT_ID_BYTES = 127

_KIND = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")


class LedgerFormatError(ValueError):
    """An entry or one of its fields is malformed. Nothing is appended."""

    code = "ledger_format_invalid"


@dataclass(frozen=True, slots=True)
class LogEntry:
    """One row of the log. `payload` is the JCS bytes of the logged JSON object."""

    seq: int
    ts_us: int  # microseconds since the Unix epoch, UTC
    checkout_id: str | None
    kind: str
    payload: bytes
    payload_hash: bytes
    policy_hash: bytes
    prev_hash: bytes
    entry_hash: bytes


@dataclass(frozen=True, slots=True)
class Anchor:
    """The newest entry as held somewhere the log's writer cannot change."""

    seq: int
    entry_hash: bytes


@dataclass(frozen=True, slots=True)
class Break:
    """The first broken link: where it is and why."""

    index: int  # position in the sequence that was verified
    seq: int | None  # the sequence number the entry claims, when it has one
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    checked: int  # entries verified before the break, or all of them
    first_break: Break | None


# ---- encoding and hashing ----


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def payload_hash_of(payload: bytes) -> bytes:
    return domain_hash(PAYLOAD_DOMAIN, payload)


def entry_hash_input(
    *,
    prev_hash: bytes,
    seq: int,
    ts_us: int,
    checkout_id: str | None,
    kind: str,
    payload_hash: bytes,
    policy_hash: bytes,
) -> bytes:
    """The unambiguous byte string the entry hash is taken over."""
    if checkout_id is None:
        scope = b"\x00"
    else:
        scope = b"\x01" + _length_prefixed(checkout_id.encode("utf-8"))
    return b"".join(
        (
            prev_hash,
            _u64(seq),
            _u64(ts_us),
            scope,
            _length_prefixed(kind.encode("utf-8")),
            payload_hash,
            policy_hash,
        )
    )


def compute_entry_hash(
    *,
    prev_hash: bytes,
    seq: int,
    ts_us: int,
    checkout_id: str | None,
    kind: str,
    payload_hash: bytes,
    policy_hash: bytes,
) -> bytes:
    return domain_hash(
        LOG_DOMAIN,
        entry_hash_input(
            prev_hash=prev_hash,
            seq=seq,
            ts_us=ts_us,
            checkout_id=checkout_id,
            kind=kind,
            payload_hash=payload_hash,
            policy_hash=policy_hash,
        ),
    )


def field_problem(entry: LogEntry) -> str | None:
    """Why an entry's fields cannot be hashed, or None. Used by `make_entry` and by `verify_chain`."""
    if type(entry.seq) is not int or not 1 <= entry.seq <= MAX_INT64:
        return "seq must be an integer from 1 to 2^63 - 1"
    if type(entry.ts_us) is not int or not 0 <= entry.ts_us <= MAX_INT64:
        return "ts_us must be an integer from 0 to 2^63 - 1"
    if entry.checkout_id is not None:
        if type(entry.checkout_id) is not str or not entry.checkout_id:
            return "checkout_id must be None or a non-empty string"
        try:
            if len(entry.checkout_id.encode("utf-8")) > MAX_CHECKOUT_ID_BYTES:
                return "checkout_id is longer than 127 bytes"
        except UnicodeEncodeError:
            return "checkout_id is not valid Unicode text"
    if type(entry.kind) is not str or not _KIND.fullmatch(entry.kind):
        return "kind must be 1 to 64 characters of letters, digits and . _ : -"
    if type(entry.payload) is not bytes:
        return "payload must be bytes"
    for name in ("payload_hash", "policy_hash", "prev_hash", "entry_hash"):
        value = getattr(entry, name)
        if type(value) is not bytes or len(value) != HASH_LEN:
            return f"{name} must be {HASH_LEN} bytes"
    return None


def make_entry(
    *,
    seq: int,
    prev_hash: bytes,
    ts_us: int,
    checkout_id: str | None,
    kind: str,
    payload: bytes,
    policy_hash: bytes,
) -> LogEntry:
    """Build an entry with its hashes. `payload` is the JCS bytes of a JSON object."""
    payload_hash = payload_hash_of(payload) if type(payload) is bytes else b""
    draft = LogEntry(
        seq=seq,
        ts_us=ts_us,
        checkout_id=checkout_id,
        kind=kind,
        payload=payload,
        payload_hash=payload_hash,
        policy_hash=policy_hash,
        prev_hash=prev_hash,
        entry_hash=bytes(HASH_LEN),
    )
    problem = field_problem(draft)
    if problem:
        raise LedgerFormatError(problem)
    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        seq=seq,
        ts_us=ts_us,
        checkout_id=checkout_id,
        kind=kind,
        payload_hash=payload_hash,
        policy_hash=policy_hash,
    )
    return replace(draft, entry_hash=entry_hash)


# ---- verification ----


def _check_entry(
    entry: LogEntry, expected_seq: int, expected_prev: bytes
) -> tuple[str, str] | None:
    """The first problem with an entry as a link in the chain, as (code, message)."""
    problem = field_problem(entry)
    if problem:
        return "field_invalid", problem
    if entry.seq != expected_seq:
        return "seq_unexpected", f"expected seq {expected_seq}, found {entry.seq}"
    if entry.prev_hash != expected_prev:
        return "prev_mismatch", "prev_hash does not match the previous entry"
    if entry.payload_hash != payload_hash_of(entry.payload):
        return "payload_hash_mismatch", "payload does not match payload_hash"
    recomputed = compute_entry_hash(
        prev_hash=entry.prev_hash,
        seq=entry.seq,
        ts_us=entry.ts_us,
        checkout_id=entry.checkout_id,
        kind=entry.kind,
        payload_hash=entry.payload_hash,
        policy_hash=entry.policy_hash,
    )
    if entry.entry_hash != recomputed:
        return "entry_hash_mismatch", "entry_hash does not match the entry's fields"
    return None


def verify_chain(
    entries: Sequence[LogEntry],
    *,
    first_seq: int = 1,
    prev_hash: bytes = GENESIS_PREV,
    anchor: Anchor | None = None,
) -> VerifyResult:
    """Verify consecutive entries and report the first broken link.

    `first_seq` and `prev_hash` say what the first entry must be, so a later slice of the log can
    be verified on its own. With an `anchor`, the newest known entry must be present and equal.
    """
    expected_seq = first_seq
    expected_prev = prev_hash
    for index, entry in enumerate(entries):
        found = _check_entry(entry, expected_seq, expected_prev)
        if found:
            code, message = found
            seq = entry.seq if type(entry.seq) is int else None
            return VerifyResult(False, index, Break(index, seq, code, message))
        expected_seq += 1
        expected_prev = entry.entry_hash
    if anchor is not None:
        newest = first_seq + len(entries) - 1
        if anchor.seq > newest:
            message = f"the log ends at seq {newest} but the anchor is at seq {anchor.seq}"
            return VerifyResult(
                False, len(entries), Break(len(entries), None, "truncated", message)
            )
        if anchor.seq >= first_seq:
            index = anchor.seq - first_seq
            if entries[index].entry_hash != anchor.entry_hash:
                message = f"entry at seq {anchor.seq} differs from the anchor"
                return VerifyResult(
                    False, index, Break(index, anchor.seq, "anchor_mismatch", message)
                )
    return VerifyResult(True, len(entries), None)

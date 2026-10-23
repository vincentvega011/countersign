"""Decision log chain: hashing layout and detection of every kind of tampering (no database)."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import replace

import pytest

from countersign.canonical import canonicalize
from countersign.ledger import (
    GENESIS_PREV,
    Anchor,
    LedgerFormatError,
    LogEntry,
    compute_entry_hash,
    make_entry,
    verify_chain,
)
from countersign.ledger.chain import payload_hash_of

POLICY = hashlib.sha256(b"policy v1").digest()
T0 = 1_760_000_000_000_000


def build(n: int, *, checkout: str | None = "chk_1") -> list[LogEntry]:
    entries: list[LogEntry] = []
    prev = GENESIS_PREV
    for i in range(1, n + 1):
        entry = make_entry(
            seq=i,
            prev_hash=prev,
            ts_us=T0 + i * 1000,
            checkout_id=checkout if i % 3 else None,
            kind="G-FETCH" if i % 2 else "G-AMOUNT",
            payload=canonicalize({"n": i, "note": f"entry {i}"}),
            policy_hash=POLICY,
        )
        entries.append(entry)
        prev = entry.entry_hash
    return entries


def reference_hash(e: LogEntry) -> bytes:
    """The documented layout written out with hashlib only, independent of the library helpers."""
    scope = (
        b"\x00"
        if e.checkout_id is None
        else b"\x01" + struct.pack(">I", len(e.checkout_id.encode())) + e.checkout_id.encode()
    )
    kind = e.kind.encode()
    body = (
        e.prev_hash
        + struct.pack(">QQ", e.seq, e.ts_us)
        + scope
        + struct.pack(">I", len(kind))
        + kind
        + e.payload_hash
        + e.policy_hash
    )
    return hashlib.sha256(b"cs.log.v1\x00" + body).digest()


# ---- hashing ----


def test_entry_hash_matches_the_documented_layout():
    for entry in build(6):
        assert entry.entry_hash == reference_hash(entry)
        assert (
            entry.payload_hash == hashlib.sha256(b"cs.log.payload.v1\x00" + entry.payload).digest()
        )


def test_genesis_is_32_zero_bytes_and_seq_starts_at_one():
    first = build(1)[0]
    assert GENESIS_PREV == bytes(32)
    assert first.seq == 1 and first.prev_hash == GENESIS_PREV


def test_the_encoding_is_unambiguous():
    base = {
        "prev_hash": bytes(32),
        "seq": 1,
        "ts_us": 5,
        "payload_hash": bytes(32),
        "policy_hash": bytes(32),
    }
    h1 = compute_entry_hash(checkout_id="ab", kind="c", **base)
    h2 = compute_entry_hash(checkout_id="a", kind="bc", **base)
    assert h1 != h2
    h3 = compute_entry_hash(checkout_id=None, kind="ab", **base)
    h4 = compute_entry_hash(checkout_id="ab", kind="ab", **base)
    assert h3 != h4


def test_every_field_is_inside_the_hash():
    base = build(1)[0]
    args = {
        "prev_hash": base.prev_hash,
        "seq": base.seq,
        "ts_us": base.ts_us,
        "checkout_id": base.checkout_id,
        "kind": base.kind,
        "payload_hash": base.payload_hash,
        "policy_hash": base.policy_hash,
    }
    assert compute_entry_hash(**args) == base.entry_hash
    changes = {
        "prev_hash": hashlib.sha256(b"x").digest(),
        "seq": 2,
        "ts_us": base.ts_us + 1,
        "checkout_id": "other",
        "kind": "OTHER",
        "payload_hash": hashlib.sha256(b"y").digest(),
        "policy_hash": hashlib.sha256(b"z").digest(),
    }
    for name, value in changes.items():
        assert compute_entry_hash(**{**args, name: value}) != base.entry_hash, name


@pytest.mark.parametrize(
    "overrides",
    [
        {"seq": 0},
        {"seq": -1},
        {"seq": 2**63},
        {"seq": True},
        {"ts_us": -1},
        {"ts_us": 2**63},
        {"ts_us": 1.5},
        {"kind": ""},
        {"kind": "has space"},
        {"kind": "x" * 65},
        {"kind": "é"},
        {"checkout_id": ""},
        {"checkout_id": "x" * 128},
        {"checkout_id": 5},
        {"policy_hash": b"short"},
        {"prev_hash": b"\x00" * 31},
        {"payload": "text"},
    ],
)
def test_make_entry_rejects_malformed_fields(overrides):
    args = {
        "seq": 1,
        "prev_hash": GENESIS_PREV,
        "ts_us": T0,
        "checkout_id": "c",
        "kind": "K",
        "payload": b"{}",
        "policy_hash": POLICY,
    }
    args.update(overrides)
    with pytest.raises(LedgerFormatError):
        make_entry(**args)


def test_entries_are_immutable():
    entry = build(1)[0]
    with pytest.raises(AttributeError):
        entry.seq = 9  # type: ignore[misc]


# ---- verification: the intact chain ----


def test_an_intact_chain_verifies():
    chain = build(10)
    result = verify_chain(chain)
    assert result.ok and result.checked == 10 and result.first_break is None


def test_an_empty_chain_verifies():
    assert verify_chain([]).ok


def test_a_slice_verifies_with_its_starting_point():
    chain = build(10)
    assert verify_chain(chain[4:], first_seq=5, prev_hash=chain[3].entry_hash).ok
    assert not verify_chain(chain[4:]).ok  # a slice is not a chain from genesis


# ---- detection ----


def first_break(entries, **kwargs):
    result = verify_chain(entries, **kwargs)
    assert not result.ok and result.first_break is not None
    return result.first_break


@pytest.mark.parametrize(
    "field, value, code",
    [
        ("payload", b'{"n":99}', "payload_hash_mismatch"),
        ("payload_hash", hashlib.sha256(b"x").digest(), "payload_hash_mismatch"),
        ("policy_hash", hashlib.sha256(b"other policy").digest(), "entry_hash_mismatch"),
        ("ts_us", T0 + 1, "entry_hash_mismatch"),
        ("kind", "G-OTHER", "entry_hash_mismatch"),
        ("checkout_id", "chk_other", "entry_hash_mismatch"),
        ("prev_hash", hashlib.sha256(b"x").digest(), "prev_mismatch"),
        ("entry_hash", hashlib.sha256(b"x").digest(), "entry_hash_mismatch"),
        ("seq", 99, "seq_unexpected"),
    ],
)
def test_modifying_any_field_breaks_the_chain_at_that_entry(field, value, code):
    chain = build(8)
    target = 4
    chain[target] = replace(chain[target], **{field: value})
    found = first_break(chain)
    assert found.index == target and found.code == code


def test_moving_an_entry_to_another_checkout_is_detected():
    chain = build(6)
    chain[1] = replace(chain[1], checkout_id="chk_other")
    assert first_break(chain).index == 1


def test_deleting_an_entry_is_detected_where_it_was():
    for victim in (0, 3, 6):
        chain = build(8)
        del chain[victim]
        found = first_break(chain)
        assert found.index == victim
        assert found.code in {"seq_unexpected", "prev_mismatch"}


def test_deleting_the_newest_entries_needs_an_anchor():
    chain = build(8)
    anchor = Anchor(chain[-1].seq, chain[-1].entry_hash)
    shortened = chain[:5]
    assert verify_chain(shortened).ok  # an internally consistent prefix
    found = first_break(shortened, anchor=anchor)
    assert found.code == "truncated" and found.index == 5


def test_deleting_everything_against_an_anchor():
    chain = build(3)
    found = first_break([], anchor=Anchor(3, chain[-1].entry_hash))
    assert found.code == "truncated"


def test_inserting_an_entry_is_detected():
    chain = build(8)
    forged = make_entry(
        seq=4,
        prev_hash=chain[2].entry_hash,  # a perfectly linked forgery
        ts_us=T0,
        checkout_id="chk_1",
        kind="G-FETCH",
        payload=b'{"forged":true}',
        policy_hash=POLICY,
    )
    tampered = chain[:3] + [forged] + chain[3:]
    found = first_break(tampered)
    assert found.index == 4 and found.code == "seq_unexpected"  # the entry after the insertion


def test_inserting_garbage_is_detected_at_the_insertion():
    chain = build(5)
    junk = replace(chain[1], seq=3)
    tampered = chain[:2] + [junk] + chain[2:]
    assert first_break(tampered).index == 2


def test_reordering_is_detected():
    chain = build(8)
    chain[2], chain[3] = chain[3], chain[2]
    assert first_break(chain).index == 2
    chain = build(8)
    chain.reverse()
    assert first_break(chain).index == 0


def test_duplicating_and_replaying_entries_is_detected():
    chain = build(5)
    assert first_break(chain + [chain[2]]).index == 5
    assert first_break(chain[:3] + [chain[2]] + chain[3:]).index == 3


def test_rehashing_one_modified_entry_is_caught_by_the_next_one():
    chain = build(8)
    target = 3
    forged = make_entry(
        seq=chain[target].seq,
        prev_hash=chain[target].prev_hash,
        ts_us=chain[target].ts_us,
        checkout_id=chain[target].checkout_id,
        kind=chain[target].kind,
        payload=b'{"rewritten":true}',
        policy_hash=chain[target].policy_hash,
    )
    chain[target] = forged
    found = first_break(chain)
    assert found.index == target + 1 and found.code == "prev_mismatch"


def test_rehashing_the_newest_entry_needs_an_anchor():
    chain = build(5)
    anchor = Anchor(chain[-1].seq, chain[-1].entry_hash)
    forged = make_entry(
        seq=5,
        prev_hash=chain[3].entry_hash,
        ts_us=chain[4].ts_us,
        checkout_id=chain[4].checkout_id,
        kind=chain[4].kind,
        payload=b'{"rewritten":true}',
        policy_hash=POLICY,
    )
    chain[4] = forged
    assert verify_chain(chain).ok
    found = first_break(chain, anchor=anchor)
    assert found.code == "anchor_mismatch" and found.seq == 5


def test_a_fully_rewritten_chain_is_internally_valid_but_not_against_an_anchor():
    original = build(6)
    anchor = Anchor(6, original[-1].entry_hash)
    rewritten = build(6, checkout="chk_rewritten")
    assert verify_chain(rewritten).ok
    assert first_break(rewritten, anchor=anchor).code == "anchor_mismatch"


def test_an_anchor_inside_the_log_must_match_exactly():
    chain = build(6)
    good = Anchor(3, chain[2].entry_hash)
    assert verify_chain(chain, anchor=good).ok
    bad = Anchor(3, hashlib.sha256(b"no").digest())
    assert first_break(chain, anchor=bad).code == "anchor_mismatch"


def test_anchors_below_a_slice_are_not_checked():
    chain = build(6)
    assert verify_chain(
        chain[3:], first_seq=4, prev_hash=chain[2].entry_hash, anchor=Anchor(2, bytes(32))
    ).ok


def test_corrupt_rows_are_reported_not_raised():
    chain = build(4)
    chain[2] = replace(chain[2], prev_hash=b"short")
    found = first_break(chain)
    assert found.index == 2 and found.code == "field_invalid"
    chain = build(4)
    chain[1] = replace(chain[1], seq="2")  # type: ignore[arg-type]
    assert first_break(chain).code == "field_invalid"
    chain = build(4)
    chain[1] = replace(chain[1], payload=None)  # type: ignore[arg-type]
    assert first_break(chain).code == "field_invalid"


def test_payload_hash_helper_is_domain_separated():
    assert payload_hash_of(b"x") != hashlib.sha256(b"x").digest()

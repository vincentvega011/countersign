"""Properties of the decision log chain and the Merkle trees (no database)."""

from __future__ import annotations

import hashlib
from dataclasses import replace

from hypothesis import assume, given
from hypothesis import strategies as st

from countersign.canonical import canonicalize
from countersign.ledger import (
    GENESIS_PREV,
    Anchor,
    InclusionProof,
    LogEntry,
    compute_entry_hash,
    inclusion_proof,
    make_entry,
    merkle_root,
    verify_chain,
    verify_inclusion,
)
from countersign.ledger.chain import payload_hash_of

POLICY = hashlib.sha256(b"policy").digest()
ASCII_ID = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-", min_size=1, max_size=12)
KINDS = st.sampled_from(
    ["G-FETCH", "G-AMOUNT", "G-TERMS", "WEBHOOK", "CP.AUTHORIZE", "decision:v1"]
)
payloads = st.dictionaries(
    st.text(alphabet="abcdef", min_size=1, max_size=4), st.integers(-1000, 1000), max_size=4
)


@st.composite
def chains(draw, min_size: int = 1, max_size: int = 12) -> list[LogEntry]:
    n = draw(st.integers(min_value=min_size, max_value=max_size))
    entries: list[LogEntry] = []
    prev = GENESIS_PREV
    ts = draw(st.integers(min_value=0, max_value=2**40))
    for seq in range(1, n + 1):
        ts += draw(st.integers(min_value=0, max_value=10_000))
        entry = make_entry(
            seq=seq,
            prev_hash=prev,
            ts_us=ts,
            checkout_id=draw(st.one_of(st.none(), ASCII_ID)),
            kind=draw(KINDS),
            payload=canonicalize(draw(payloads)),
            policy_hash=POLICY,
        )
        entries.append(entry)
        prev = entry.entry_hash
    return entries


def flip_byte(data: bytes, position: int, delta: int) -> bytes:
    position %= len(data)
    return data[:position] + bytes([data[position] ^ delta]) + data[position + 1 :]


def flip_int_byte(value: int, position: int, delta: int) -> int:
    raw = value.to_bytes(8, "big")
    return int.from_bytes(flip_byte(raw, position, delta), "big")


def flip_text_byte(text: str, position: int, delta: int) -> str:
    raw = text.encode()
    return flip_byte(raw, position, delta).decode("latin-1")


BYTES_FIELDS = ["payload", "payload_hash", "policy_hash", "prev_hash", "entry_hash"]
INT_FIELDS = ["seq", "ts_us"]


@given(chains(), st.data())
def test_any_single_byte_change_to_an_entry_breaks_verification_at_that_entry(chain, data):
    index = data.draw(st.integers(min_value=0, max_value=len(chain) - 1))
    field = data.draw(st.sampled_from([*BYTES_FIELDS, *INT_FIELDS, "kind", "checkout_id"]))
    position = data.draw(st.integers(min_value=0, max_value=63))
    delta = data.draw(st.integers(min_value=1, max_value=255))
    entry = chain[index]
    if field in BYTES_FIELDS:
        assume(len(getattr(entry, field)) > 0)
        changed = replace(entry, **{field: flip_byte(getattr(entry, field), position, delta)})
    elif field in INT_FIELDS:
        changed = replace(entry, **{field: flip_int_byte(getattr(entry, field), position, delta)})
    elif field == "kind":
        changed = replace(entry, kind=flip_text_byte(entry.kind, position, delta))
    elif entry.checkout_id is None:
        changed = replace(entry, checkout_id="x")  # one byte added
    else:
        changed = replace(entry, checkout_id=flip_text_byte(entry.checkout_id, position, delta))
    assume(changed != entry)
    tampered = [*chain[:index], changed, *chain[index + 1 :]]
    result = verify_chain(tampered)
    assert not result.ok and result.first_break is not None
    assert result.first_break.index == index, (field, result.first_break)


@given(chains())
def test_every_prefix_and_slice_of_an_intact_chain_verifies(chain):
    for k in range(len(chain) + 1):
        assert verify_chain(chain[:k]).ok
    for start in range(len(chain)):
        prev = chain[start - 1].entry_hash if start else GENESIS_PREV
        assert verify_chain(chain[start:], first_seq=start + 1, prev_hash=prev).ok


@given(chains(min_size=2), st.data())
def test_deleting_any_entry_but_the_newest_is_detected_where_it_was(chain, data):
    victim = data.draw(st.integers(min_value=0, max_value=len(chain) - 2))
    tampered = chain[:victim] + chain[victim + 1 :]
    result = verify_chain(tampered)
    assert not result.ok and result.first_break is not None
    assert result.first_break.index == victim


@given(chains(min_size=1), st.data())
def test_deleting_the_newest_entries_is_detected_by_the_anchor(chain, data):
    keep = data.draw(st.integers(min_value=0, max_value=len(chain) - 1))
    anchor = Anchor(chain[-1].seq, chain[-1].entry_hash)
    assert verify_chain(chain[:keep]).ok
    result = verify_chain(chain[:keep], anchor=anchor)
    assert not result.ok and result.first_break is not None
    assert result.first_break.code == "truncated"


@given(chains(min_size=2), st.data())
def test_swapping_any_two_entries_is_detected_at_the_first_of_them(chain, data):
    i = data.draw(st.integers(min_value=0, max_value=len(chain) - 2))
    j = data.draw(st.integers(min_value=i + 1, max_value=len(chain) - 1))
    tampered = list(chain)
    tampered[i], tampered[j] = tampered[j], tampered[i]
    result = verify_chain(tampered)
    assert not result.ok and result.first_break is not None
    assert result.first_break.index == i


@given(chains(min_size=2), st.data())
def test_inserting_a_validly_linked_forgery_is_detected_at_the_next_entry(chain, data):
    at = data.draw(st.integers(min_value=1, max_value=len(chain) - 1))
    forged = make_entry(
        seq=chain[at].seq,
        prev_hash=chain[at - 1].entry_hash,
        ts_us=chain[at].ts_us,
        checkout_id=chain[at].checkout_id,
        kind=chain[at].kind,
        payload=b'{"forged":1}',
        policy_hash=POLICY,
    )
    tampered = [*chain[:at], forged, *chain[at:]]
    result = verify_chain(tampered)
    assert not result.ok and result.first_break is not None
    assert result.first_break.index == at + 1


@given(chains(), st.data())
def test_rehashing_a_modified_entry_is_caught_by_its_successor_or_the_anchor(chain, data):
    index = data.draw(st.integers(min_value=0, max_value=len(chain) - 1))
    entry = chain[index]
    payload = canonicalize({"rewritten": data.draw(st.integers(0, 10**6))})
    assume(payload != entry.payload)
    payload_hash = payload_hash_of(payload)
    forged = replace(
        entry,
        payload=payload,
        payload_hash=payload_hash,
        entry_hash=compute_entry_hash(
            prev_hash=entry.prev_hash,
            seq=entry.seq,
            ts_us=entry.ts_us,
            checkout_id=entry.checkout_id,
            kind=entry.kind,
            payload_hash=payload_hash,
            policy_hash=entry.policy_hash,
        ),
    )
    tampered = [*chain[:index], forged, *chain[index + 1 :]]
    anchor = Anchor(chain[-1].seq, chain[-1].entry_hash)
    result = verify_chain(tampered)
    if index < len(chain) - 1:
        assert not result.ok and result.first_break is not None
        assert result.first_break.index == index + 1
    else:
        assert result.ok  # consistent on its own
    anchored = verify_chain(tampered, anchor=anchor)
    assert not anchored.ok


# ---- Merkle ----

hashes = st.binary(min_size=32, max_size=32)


@given(st.lists(hashes, min_size=1, max_size=70), st.data())
def test_proofs_verify_and_only_for_the_right_inputs(items, data):
    root = merkle_root(items)
    index = data.draw(st.integers(min_value=0, max_value=len(items) - 1))
    proof = inclusion_proof(items, index)
    assert verify_inclusion(items[index], proof, root)

    other = data.draw(hashes)
    assume(other != items[index])
    assert not verify_inclusion(other, proof, root)

    if proof.path:
        which = data.draw(st.integers(min_value=0, max_value=len(proof.path) - 1))
        position = data.draw(st.integers(min_value=0, max_value=31))
        delta = data.draw(st.integers(min_value=1, max_value=255))
        path = list(proof.path)
        path[which] = flip_byte(path[which], position, delta)
        assert not verify_inclusion(
            items[index], InclusionProof(index, proof.size, tuple(path)), root
        )

    wrong_index = data.draw(st.integers(min_value=0, max_value=len(items) + 3))
    assume(wrong_index != index)
    # With duplicate leaves, a proof is legitimately valid at every position holding that leaf.
    assume(wrong_index >= len(items) or items[wrong_index] != items[index])
    assert not verify_inclusion(
        items[index], InclusionProof(wrong_index, proof.size, proof.path), root
    )

    wrong_size = data.draw(st.integers(min_value=1, max_value=len(items) + 5))
    assume(wrong_size != proof.size)
    assert not verify_inclusion(items[index], InclusionProof(index, wrong_size, proof.path), root)

    position = data.draw(st.integers(min_value=0, max_value=31))
    delta = data.draw(st.integers(min_value=1, max_value=255))
    assert not verify_inclusion(items[index], proof, flip_byte(root, position, delta))


@given(st.lists(hashes, min_size=1, max_size=40), st.data())
def test_changing_reordering_or_resizing_the_leaves_changes_the_root(items, data):
    root = merkle_root(items)
    i = data.draw(st.integers(min_value=0, max_value=len(items) - 1))
    changed = list(items)
    changed[i] = flip_byte(items[i], data.draw(st.integers(0, 31)), data.draw(st.integers(1, 255)))
    assert merkle_root(changed) != root
    assert merkle_root([*items, items[-1]]) != root
    assert merkle_root(items[:-1]) != root
    if len(items) >= 2 and items[0] != items[1]:
        swapped = [items[1], items[0], *items[2:]]
        assert merkle_root(swapped) != root


@given(st.lists(hashes, min_size=1, max_size=40), st.lists(hashes, min_size=1, max_size=40))
def test_distinct_leaf_lists_have_distinct_roots(a, b):
    assume(a != b)
    assert merkle_root(a) != merkle_root(b)

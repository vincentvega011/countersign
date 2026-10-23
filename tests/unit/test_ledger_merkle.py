"""Merkle trees: the construction in docs/PROTOCOL.md Decision 15, checked against references."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from countersign.ledger import (
    GENESIS_PREV,
    InclusionProof,
    MerkleError,
    bind_size,
    inclusion_proof,
    leaf_hash,
    make_entry,
    merkle_root,
    node_hash,
    tree_hash,
    verify_inclusion,
)
from countersign.ledger.merkle import empty_root

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "ledger_vectors.json"


def h(i: int) -> bytes:
    return hashlib.sha256(b"entry-%d" % i).digest()


# Independent reference: explicit prefixes, slicing instead of index ranges.
def ref_leaf(x: bytes) -> bytes:
    return hashlib.sha256(b"cs.merkle.leaf.v1\x00" + x).digest()


def ref_node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"cs.merkle.node.v1\x00" + a + b).digest()


def ref_tree(items: list[bytes]) -> bytes:
    if not items:
        return hashlib.sha256(b"cs.merkle.empty.v1\x00").digest()
    if len(items) == 1:
        return ref_leaf(items[0])
    k = 1
    while k * 2 < len(items):
        k *= 2
    return ref_node(ref_tree(items[:k]), ref_tree(items[k:]))


def ref_root(items: list[bytes]) -> bytes:
    return hashlib.sha256(
        b"cs.merkle.root.v1\x00" + struct.pack(">Q", len(items)) + ref_tree(items)
    ).digest()


def rfc9162_verify(index: int, size: int, leaf: bytes, path: list[bytes], root: bytes) -> bool:
    """The iterative inclusion-proof verification of RFC 9162 section 2.1.3.2 (tree hash), then
    the leaf count is bound in, as Decision 15 requires."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and bind_size(size, r) == root


def test_domains_and_empty_tree():
    assert leaf_hash(h(1)) == ref_leaf(h(1))
    assert node_hash(h(1), h(2)) == ref_node(h(1), h(2))
    assert empty_root() == hashlib.sha256(b"cs.merkle.empty.v1\x00").digest()
    assert tree_hash([]) == empty_root()
    assert merkle_root([]) == ref_root([])


@pytest.mark.parametrize("n", range(1, 34))
def test_root_matches_the_reference(n):
    items = [h(i) for i in range(n)]
    assert merkle_root(items) == ref_root(items)


def test_single_leaf_tree_hash_is_the_leaf_hash():
    assert tree_hash([h(0)]) == ref_leaf(h(0))


def test_split_is_at_the_largest_power_of_two_below_n():
    items = [h(i) for i in range(5)]
    assert tree_hash(items) == ref_node(ref_tree(items[:4]), ref_leaf(items[4]))
    items = [h(i) for i in range(6)]
    assert tree_hash(items) == ref_node(ref_tree(items[:4]), ref_tree(items[4:]))


def test_odd_nodes_are_not_duplicated():
    a, b, c = h(1), h(2), h(3)
    assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])
    assert merkle_root([a]) != merkle_root([a, a])
    assert tree_hash([a, b, c]) != tree_hash([a, b, c, c])


def test_leaf_and_node_domains_are_separate():
    a, b = h(1), h(2)
    inner = node_hash(leaf_hash(a), leaf_hash(b))
    assert leaf_hash(inner) != inner
    # An interior node offered as a single leaf does not reproduce the two-leaf tree.
    assert tree_hash([a, b]) == inner
    assert tree_hash([inner]) == leaf_hash(inner) != inner


def test_order_and_content_matter():
    items = [h(i) for i in range(7)]
    root = merkle_root(items)
    assert merkle_root(list(reversed(items))) != root
    assert merkle_root(items[:-1]) != root
    for i in range(7):
        changed = list(items)
        changed[i] = h(100 + i)
        assert merkle_root(changed) != root


@pytest.mark.parametrize("n", range(1, 40))
def test_every_proof_verifies_in_every_tree_size(n):
    items = [h(i) for i in range(n)]
    root = merkle_root(items)
    for index in range(n):
        proof = inclusion_proof(items, index)
        assert proof.index == index and proof.size == n
        assert verify_inclusion(items[index], proof, root)
        assert rfc9162_verify(index, n, leaf_hash(items[index]), list(proof.path), root)


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 31])
def test_proof_length_is_the_path_depth(n):
    items = [h(i) for i in range(n)]
    for index in range(n):
        assert len(inclusion_proof(items, index).path) <= max(0, (n - 1).bit_length())


def test_wrong_leaf_index_size_root_or_path_fail():
    items = [h(i) for i in range(10)]
    root = merkle_root(items)
    proof = inclusion_proof(items, 6)
    assert verify_inclusion(items[6], proof, root)
    assert not verify_inclusion(items[5], proof, root)  # wrong leaf
    assert not verify_inclusion(items[6], InclusionProof(5, 10, proof.path), root)  # wrong index
    assert not verify_inclusion(items[6], InclusionProof(6, 11, proof.path), root)  # wrong size
    assert not verify_inclusion(items[6], InclusionProof(6, 9, proof.path), root)
    assert not verify_inclusion(items[6], InclusionProof(6, 16, proof.path), root)
    assert not verify_inclusion(items[6], proof, h(99))  # wrong root
    assert not verify_inclusion(items[6], InclusionProof(6, 10, proof.path[:-1]), root)  # short
    assert not verify_inclusion(items[6], InclusionProof(6, 10, (*proof.path, h(1))), root)  # long
    assert not verify_inclusion(items[6], InclusionProof(6, 10, proof.path[::-1]), root)
    flipped = bytes([proof.path[0][0] ^ 1]) + proof.path[0][1:]
    assert not verify_inclusion(items[6], InclusionProof(6, 10, (flipped, *proof.path[1:])), root)


def test_the_root_commits_to_the_leaf_count():
    # Same paths, different claimed sizes: a bare tree hash would accept both.
    items = [h(i) for i in range(10)]
    proof = inclusion_proof(items, 6)
    assert tree_hash(items) == tree_hash(items)
    assert not verify_inclusion(items[6], InclusionProof(6, 11, proof.path), merkle_root(items))
    assert merkle_root(items) != bind_size(11, tree_hash(items))


def test_a_proof_cannot_be_reused_in_a_larger_tree():
    items = [h(i) for i in range(4)]
    proof = inclusion_proof(items, 3)
    bigger = merkle_root(items + [h(9)])
    assert not verify_inclusion(items[3], proof, bigger)


def test_verify_returns_false_instead_of_raising_on_garbage():
    root = merkle_root([h(0)])
    assert not verify_inclusion(b"short", InclusionProof(0, 1, ()), root)
    assert not verify_inclusion(h(0), InclusionProof(0, 1, (b"short",)), root)
    assert not verify_inclusion(h(0), InclusionProof(-1, 1, ()), root)
    assert not verify_inclusion(h(0), InclusionProof(1, 1, ()), root)
    assert not verify_inclusion(h(0), InclusionProof(0, 0, ()), root)
    assert not verify_inclusion(h(0), InclusionProof(0, 1, ()), b"short")
    assert verify_inclusion(h(0), InclusionProof(0, 1, ()), root)


def test_building_a_proof_validates_its_input():
    with pytest.raises(MerkleError):
        inclusion_proof([h(0)], 1)
    with pytest.raises(MerkleError):
        inclusion_proof([], 0)
    with pytest.raises(MerkleError):
        inclusion_proof([b"short"], 0)
    with pytest.raises(MerkleError):
        merkle_root([b"short"])
    with pytest.raises(MerkleError):
        node_hash(b"x", h(1))


# ---- proof format ----


def test_proof_json_round_trip():
    items = [h(i) for i in range(11)]
    proof = inclusion_proof(items, 8)
    data = json.loads(json.dumps(proof.to_dict()))
    assert set(data) == {"v", "index", "size", "path"} and data["v"] == 1
    assert all("=" not in p and len(p) == 43 for p in data["path"])
    assert InclusionProof.from_dict(data) == proof


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(v=2),
        lambda d: d.update(v=True),
        lambda d: d.update(extra=1),
        lambda d: d.pop("size"),
        lambda d: d.update(index=-1),
        lambda d: d.update(index=99),
        lambda d: d.update(index=1.0),
        lambda d: d.update(size="11"),
        lambda d: d.update(path="x"),
        lambda d: d.update(path=[1]),
        lambda d: d.update(path=["!!!"]),
        lambda d: d.update(path=["AA"]),
        lambda d: d["path"].__setitem__(0, d["path"][0] + "="),
        lambda d: d["path"].__setitem__(
            0, d["path"][0][:-1] + ("B" if d["path"][0][-1] != "B" else "C")
        ),
    ],
)
def test_proof_json_is_parsed_strictly(mutate):
    data = inclusion_proof([h(i) for i in range(11)], 8).to_dict()
    mutate(data)
    with pytest.raises(MerkleError):
        InclusionProof.from_dict(data)


def test_non_mapping_proof_is_rejected():
    for bad in (None, [], "x", 5):
        with pytest.raises(MerkleError):
            InclusionProof.from_dict(bad)  # type: ignore[arg-type]


# ---- shared vectors for a future TypeScript verifier ----


def vectors() -> dict:
    entries = []
    prev = GENESIS_PREV
    policy = hashlib.sha256(b"policy v1").digest()
    spec = [
        (1, 1_760_000_000_000_000, "chk_1", "G-FETCH", {"order": "5O190127TN364715T"}),
        (2, 1_760_000_000_500_000, "chk_1", "G-AMOUNT", {"authorized": 7400}),
        (3, 1_760_000_001_000_000, None, "WEBHOOK", {"event": "PAYMENT.CAPTURE.COMPLETED"}),
    ]
    from countersign.canonical import canonicalize

    for seq, ts, checkout, kind, payload in spec:
        e = make_entry(
            seq=seq,
            prev_hash=prev,
            ts_us=ts,
            checkout_id=checkout,
            kind=kind,
            payload=canonicalize(payload),
            policy_hash=policy,
        )
        entries.append(e)
        prev = e.entry_hash
    log = [
        {
            "seq": e.seq,
            "ts_us": e.ts_us,
            "checkout_id": e.checkout_id,
            "kind": e.kind,
            "payload_hex": e.payload.hex(),
            "payload_hash_hex": e.payload_hash.hex(),
            "policy_hash_hex": e.policy_hash.hex(),
            "prev_hash_hex": e.prev_hash.hex(),
            "entry_hash_hex": e.entry_hash.hex(),
        }
        for e in entries
    ]
    trees = []
    for n in (0, 1, 2, 3, 5, 8, 9):
        leaves = [hashlib.sha256(bytes([i]) * 4).digest() for i in range(n)]
        trees.append(
            {
                "leaves_hex": [x.hex() for x in leaves],
                "root_hex": merkle_root(leaves).hex(),
                "proofs": [inclusion_proof(leaves, i).to_dict() for i in range(n)],
            }
        )
    return {
        "description": "Test vectors for docs/PROTOCOL.md Decision 15",
        "log": log,
        "trees": trees,
    }


def test_vectors_file_matches_the_implementation():
    # To regenerate after an intentional change:  uv run python -m tests.unit.test_ledger_merkle
    assert json.loads(VECTORS.read_text()) == vectors()


def test_vector_roots_match_the_reference():
    for tree in vectors()["trees"]:
        leaves = [bytes.fromhex(x) for x in tree["leaves_hex"]]
        assert tree["root_hex"] == ref_root(leaves).hex()


if __name__ == "__main__":
    VECTORS.write_text(json.dumps(vectors(), indent=2, sort_keys=True) + "\n")
    print(f"wrote {VECTORS}")


# ---- gaps found by mutation checking ----


def test_a_one_leaf_tree_accepts_only_the_empty_path():
    root = merkle_root([h(0)])
    assert verify_inclusion(h(0), InclusionProof(0, 1, ()), root)
    assert not verify_inclusion(h(0), InclusionProof(0, 1, (h(1),)), root)
    assert not verify_inclusion(h(0), InclusionProof(0, 1, (h(0), h(1))), root)


def test_a_proof_path_must_be_a_list():
    data = inclusion_proof([h(i) for i in range(4)], 1).to_dict()
    with_dict = {**data, "path": {p: 1 for p in data["path"]}}  # iterating a dict yields its keys
    with pytest.raises(MerkleError):
        InclusionProof.from_dict(with_dict)
    with pytest.raises(MerkleError):
        InclusionProof.from_dict({**data, "path": tuple(data["path"])})


@pytest.mark.parametrize("size", [-1, 2**64, True, 1.5, "1", None])
def test_the_bound_size_must_be_an_unsigned_64_bit_integer(size):
    with pytest.raises(MerkleError):
        bind_size(size, h(0))  # type: ignore[arg-type]
    assert bind_size(0, h(0)) != bind_size(1, h(0))
    assert bind_size(2**64 - 1, h(0))

"""Merkle trees over log entries: roots per scope and inclusion proofs. Defined in docs/PROTOCOL.md
Decision 15 so a verifier can be reimplemented in another language.

Construction (the tree shape and the proof algorithm are those of RFC 6962 and RFC 9162, with
Countersign's domain-separated hashes in place of the 0x00 and 0x01 prefix bytes):

    leaf(entry_hash)  = domain_hash("cs.merkle.leaf.v1", entry_hash)            # 32 bytes in
    node(left, right) = domain_hash("cs.merkle.node.v1", left || right)         # 64 bytes in
    tree([])          = domain_hash("cs.merkle.empty.v1", b"")
    tree([e])         = leaf(e)
    tree(es)          = node(tree(es[:k]), tree(es[k:]))   with k the largest power of two < len(es)
    root(es)          = domain_hash("cs.merkle.root.v1", u64be(len(es)) || tree(es))

Security reasoning. Leaves and interior nodes use different domains, so an interior node can never
be presented as a leaf (the second-preimage attack on naive Merkle trees). An odd node is never
paired with a copy of itself: the split is at a power of two, so [a, b, c] and [a, b, c, c] have
different roots (the duplicate-leaf ambiguity of the Bitcoin construction). Children are always
exactly 32 bytes, so `left || right` is unambiguous.

The published root includes the leaf count. A bare RFC 6962 tree hash does not authenticate its
size: an inclusion proof for index 6 of a 10-leaf tree also verifies when the claimed size is 11,
because the two paths have the same shape. Hashing the count into the root closes that, so a proof
only verifies for the size the root was made for. The verifier also rejects paths of the wrong
length.
"""

from __future__ import annotations

import base64
import binascii
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from countersign.canonical.hashing import b64url, domain_hash

LEAF_DOMAIN = "cs.merkle.leaf.v1"
NODE_DOMAIN = "cs.merkle.node.v1"
EMPTY_DOMAIN = "cs.merkle.empty.v1"
ROOT_DOMAIN = "cs.merkle.root.v1"
HASH_LEN = 32
PROOF_VERSION = 1


class MerkleError(ValueError):
    """Bad input to a Merkle function (wrong hash length, index out of range, malformed proof)."""

    code = "merkle_invalid"


@dataclass(frozen=True, slots=True)
class MerkleRoot:
    """A root with the scope it covers (for example `checkout:chk_1` or `day:2026-10-23`)."""

    scope: str
    size: int
    root: bytes


@dataclass(frozen=True, slots=True)
class InclusionProof:
    """Sibling hashes from the leaf up to the root, with the leaf's index and the tree size."""

    index: int
    size: int
    path: tuple[bytes, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": PROOF_VERSION,
            "index": self.index,
            "size": self.size,
            "path": [b64url(h) for h in self.path],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InclusionProof:
        if not isinstance(data, Mapping) or set(data) != {"v", "index", "size", "path"}:
            raise MerkleError("a proof has exactly the members v, index, size and path")
        if type(data["v"]) is not int or data["v"] != PROOF_VERSION:
            raise MerkleError("unsupported proof version")
        index, size, path = data["index"], data["size"], data["path"]
        if type(index) is not int or type(size) is not int or not 0 <= index < size:
            raise MerkleError("index and size must be integers with 0 <= index < size")
        if not isinstance(path, list):
            raise MerkleError("path must be an array")
        return cls(index, size, tuple(_decode_hash(x) for x in path))


def _decode_hash(text: object) -> bytes:
    if not isinstance(text, str):
        raise MerkleError("a path element must be a string")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise MerkleError("a path element is not base64url") from None
    if len(raw) != HASH_LEN or b64url(raw) != text:
        raise MerkleError("a path element must be a canonical 32 byte base64url string")
    return raw


def _check(value: bytes, what: str) -> bytes:
    if type(value) is not bytes or len(value) != HASH_LEN:
        raise MerkleError(f"{what} must be {HASH_LEN} bytes")
    return value


def leaf_hash(entry_hash: bytes) -> bytes:
    return domain_hash(LEAF_DOMAIN, _check(entry_hash, "entry hash"))


def node_hash(left: bytes, right: bytes) -> bytes:
    return domain_hash(NODE_DOMAIN, _check(left, "left child") + _check(right, "right child"))


def empty_root() -> bytes:
    return domain_hash(EMPTY_DOMAIN, b"")


def _split(n: int) -> int:
    """The largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _mth(leaves: Sequence[bytes], lo: int, hi: int) -> bytes:
    if hi - lo == 1:
        return leaves[lo]
    k = _split(hi - lo)
    return node_hash(_mth(leaves, lo, lo + k), _mth(leaves, lo + k, hi))


def bind_size(size: int, tree: bytes) -> bytes:
    """The published root: the tree hash with the leaf count hashed in."""
    if type(size) is not int or not 0 <= size < 2**64:
        raise MerkleError("size must be an unsigned 64-bit integer")
    return domain_hash(ROOT_DOMAIN, struct.pack(">Q", size) + _check(tree, "tree hash"))


def tree_hash(entry_hashes: Sequence[bytes]) -> bytes:
    """The RFC 6962 style tree hash, without the leaf count."""
    if not entry_hashes:
        return empty_root()
    return _mth([leaf_hash(h) for h in entry_hashes], 0, len(entry_hashes))


def merkle_root(entry_hashes: Sequence[bytes]) -> bytes:
    """The root over entry hashes in the given order, including the leaf count."""
    return bind_size(len(entry_hashes), tree_hash(entry_hashes))


def _path(leaves: Sequence[bytes], index: int, lo: int, hi: int) -> list[bytes]:
    if hi - lo == 1:
        return []
    k = _split(hi - lo)
    if index < lo + k:
        return [*_path(leaves, index, lo, lo + k), _mth(leaves, lo + k, hi)]
    return [*_path(leaves, index, lo + k, hi), _mth(leaves, lo, lo + k)]


def inclusion_proof(entry_hashes: Sequence[bytes], index: int) -> InclusionProof:
    """The proof that `entry_hashes[index]` is in the tree over `entry_hashes`."""
    if type(index) is not int or not 0 <= index < len(entry_hashes):
        raise MerkleError("index is outside the tree")
    leaves = [leaf_hash(h) for h in entry_hashes]
    return InclusionProof(index, len(leaves), tuple(_path(leaves, index, 0, len(leaves))))


def _root_from_path(index: int, size: int, leaf: bytes, path: Sequence[bytes]) -> bytes | None:
    """Recompute the root from a leaf and its path, or None if the path has the wrong length."""
    if size == 1:
        return leaf if not path else None
    if not path:
        return None
    k = _split(size)
    sibling, rest = path[-1], path[:-1]
    if index < k:
        inner = _root_from_path(index, k, leaf, rest)
        return None if inner is None else node_hash(inner, sibling)
    inner = _root_from_path(index - k, size - k, leaf, rest)
    return None if inner is None else node_hash(sibling, inner)


def verify_inclusion(entry_hash: bytes, proof: InclusionProof, root: bytes) -> bool:
    """True only if `entry_hash` at `proof.index` of a tree of `proof.size` leaves has this root."""
    try:
        if type(proof.index) is not int or type(proof.size) is not int:
            return False
        if not 0 <= proof.index < proof.size:
            return False
        if type(root) is not bytes or len(root) != HASH_LEN:
            return False
        for sibling in proof.path:
            _check(sibling, "path element")
        computed = _root_from_path(proof.index, proof.size, leaf_hash(entry_hash), proof.path)
    except MerkleError:
        return False
    return computed is not None and bind_size(proof.size, computed) == root

"""Decision log entries and RFC 6962 style inclusion proofs (docs/PROTOCOL.md Decision 15), recomputed."""

from __future__ import annotations

from typing import Any

from countersign_verify.crypto import Invalid, domain_hash, is_int, same, u32, u64, unb64


def _hash(text: object) -> bytes:
    raw = unb64(text)
    if len(raw) != 32:
        raise Invalid("log_hash_shape", "a log hash is not 32 bytes")
    return raw


def check_fields(entry: Any) -> None:
    """The members `entry_hash` reads have exact types: a non-negative integer `seq` and `ts_us`."""
    if not isinstance(entry, dict):
        raise Invalid("log_entry_shape", "a log entry is not an object")
    for name in ("seq", "ts_us"):
        value = entry.get(name)
        if not is_int(value) or value < 0:
            raise Invalid("log_entry_number", f"a log entry {name} is not a non-negative integer")
    checkout = entry.get("checkout_id")
    if checkout is not None and not isinstance(checkout, str):
        raise Invalid("log_entry_shape", "a log entry checkout_id is not text")
    for name in ("kind", "payload", "entry_hash", "prev_hash", "policy_hash"):
        if not isinstance(entry.get(name), str):
            raise Invalid("log_entry_shape", f"a log entry {name} is not text")


def entry_hash(entry: dict[str, Any]) -> bytes:
    """Recompute `entry_hash` from the entry's own fields; raises if its `payload_hash` is wrong."""
    check_fields(entry)
    payload = entry["payload"].encode("utf-8")
    payload_hash = domain_hash("cs.log.payload.v1", payload)
    checkout = entry["checkout_id"]
    scope = (
        b"\x00" if checkout is None else b"\x01" + u32(len(checkout.encode())) + checkout.encode()
    )
    kind = entry["kind"].encode()
    return domain_hash(
        "cs.log.v1",
        _hash(entry["prev_hash"]) + u64(entry["seq"]) + u64(entry["ts_us"]) + scope
        + u32(len(kind)) + kind + payload_hash + _hash(entry["policy_hash"]),
    )  # fmt: skip


def _leaf(e: bytes) -> bytes:
    return domain_hash("cs.merkle.leaf.v1", e)


def _node(left: bytes, right: bytes) -> bytes:
    return domain_hash("cs.merkle.node.v1", left + right)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _tree(hashes: list[bytes]) -> bytes:
    if len(hashes) == 1:
        return _leaf(hashes[0])
    k = _split(len(hashes))
    return _node(_tree(hashes[:k]), _tree(hashes[k:]))


def root_of(hashes: list[bytes]) -> bytes:
    tree = _tree(hashes) if hashes else domain_hash("cs.merkle.empty.v1", b"")
    return domain_hash("cs.merkle.root.v1", u64(len(hashes)) + tree)


def _from_path(index: int, size: int, leaf: bytes, path: list[bytes]) -> bytes:
    if size == 1:
        if path:
            raise Invalid("proof_path_length", "an inclusion path is too long")
        return leaf
    if not path:
        raise Invalid("proof_path_length", "an inclusion path is too short")
    k = _split(size)
    sibling, rest = path[-1], path[:-1]
    if index < k:
        return _node(_from_path(index, k, leaf, rest), sibling)
    return _node(sibling, _from_path(index - k, size - k, leaf, rest))


def check_inclusion(entry: bytes, proof: Any, root: bytes) -> None:
    if (
        not isinstance(proof, dict)
        or set(proof) != {"v", "index", "size", "path"}
        or not same(proof["v"], 1)
    ):
        raise Invalid("proof_shape", "a proof has the wrong shape")
    index, size, path = proof["index"], proof["size"], proof["path"]
    if not is_int(index) or not is_int(size) or not 0 <= index < size:
        raise Invalid("proof_position", "a proof has a bad index or size")
    if not isinstance(path, list):
        raise Invalid("proof_shape", "a proof path is not a list")
    top = _from_path(index, size, _leaf(entry), [_hash(h) for h in path])
    if domain_hash("cs.merkle.root.v1", u64(size) + top) != root:
        raise Invalid("proof_root", "an inclusion proof does not reach the root")


def root_of_subtree(hashes: list[bytes]) -> bytes:
    """The Merkle tree hash (no size binding) of a run of entry hashes: a sibling in an inclusion path."""
    return _tree(hashes)

"""Tamper demo for the decision log: modify, delete, insert and reorder entries, and show detection.

Runs in memory, with no database. It builds a log, takes the "anchor" (the newest entry) and the
Merkle root a careful operator would have stored elsewhere, then attacks copies of the log and
prints where verification reports the first broken link. Some attacks are only visible against
the stored anchor; the demo says so, because that is the honest limit of a hash chain.

Run:  uv run python scripts/tamper_demo.py        (or make tamper-demo)
Exit status is 0 only if every attack was detected as expected.
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import replace

from countersign.canonical import canonicalize
from countersign.ledger import (
    GENESIS_PREV,
    Anchor,
    LogEntry,
    inclusion_proof,
    make_entry,
    merkle_root,
    verify_chain,
    verify_inclusion,
)
from countersign.ledger.chain import compute_entry_hash, payload_hash_of

POLICY = hashlib.sha256(b"demo policy v1").digest()
T0 = 1_760_000_000_000_000


def build(n: int, tag: str = "") -> list[LogEntry]:
    steps = [
        "CP.VERIFY",
        "PAYPAL.CREATE",
        "PAYPAL.AUTHORIZE",
        "G-FETCH",
        "G-TERMS",
        "G-AMOUNT",
        "CAPTURE",
    ]
    entries: list[LogEntry] = []
    prev = GENESIS_PREV
    for i in range(1, n + 1):
        entry = make_entry(
            seq=i,
            prev_hash=prev,
            ts_us=T0 + i * 250_000,
            checkout_id="chk_demo" if i % 5 else None,
            kind=steps[(i - 1) % len(steps)],
            payload=canonicalize({"step": i, "amount": 7400, "note": f"{tag}entry {i}"}),
            policy_hash=POLICY,
        )
        entries.append(entry)
        prev = entry.entry_hash
    return entries


def rewrite(entry: LogEntry, **changes: object) -> LogEntry:
    """Change fields and recompute the entry's own hashes, as an attacker with the code would."""
    changed = replace(entry, **changes)  # type: ignore[arg-type]
    payload_hash = payload_hash_of(changed.payload)
    return replace(
        changed,
        payload_hash=payload_hash,
        entry_hash=compute_entry_hash(
            prev_hash=changed.prev_hash,
            seq=changed.seq,
            ts_us=changed.ts_us,
            checkout_id=changed.checkout_id,
            kind=changed.kind,
            payload_hash=payload_hash,
            policy_hash=changed.policy_hash,
        ),
    )


def swap(log: list[LogEntry], i: int, j: int) -> list[LogEntry]:
    out = list(log)
    out[i], out[j] = out[j], out[i]
    return out


def main() -> int:
    log = build(12)
    anchor = Anchor(log[-1].seq, log[-1].entry_hash)
    checkout_hashes = [e.entry_hash for e in log if e.checkout_id == "chk_demo"]
    stored_root = merkle_root(checkout_hashes)

    print("Decision log tamper demo (in memory)")
    print(
        f"  entries: {len(log)}   newest seq: {anchor.seq}   anchor: {anchor.entry_hash.hex()[:16]}..."
    )
    print(f"  checkout root (stored elsewhere): {stored_root.hex()[:16]}...")
    intact = verify_chain(log, anchor=anchor)
    print(f"  intact log verifies: {intact.ok}")
    if not intact.ok:
        return 1

    forged_linked = make_entry(
        seq=7,
        prev_hash=log[5].entry_hash,
        ts_us=log[5].ts_us,
        checkout_id="chk_demo",
        kind="G-AMOUNT",
        payload=canonicalize({"step": 7, "amount": 1, "note": "forged"}),
        policy_hash=POLICY,
    )
    rewritten_all = build(12, tag="rewritten ")

    attacks: list[tuple[str, list[LogEntry], bool, str | None]] = [
        # (name, tampered log, use anchor, expected first-break code or None when invisible)
        (
            "modify a payload (amount 7400 -> 1)",
            [
                *log[:6],
                replace(log[6], payload=canonicalize({"step": 7, "amount": 1, "note": "entry 7"})),
                *log[7:],
            ],
            False,
            "payload_hash_mismatch",
        ),
        (
            "modify a timestamp",
            [*log[:3], replace(log[3], ts_us=log[3].ts_us + 1), *log[4:]],
            False,
            "entry_hash_mismatch",
        ),
        (
            "move an entry to another checkout",
            [*log[:2], replace(log[2], checkout_id="chk_other"), *log[3:]],
            False,
            "entry_hash_mismatch",
        ),
        ("delete an entry from the middle", [*log[:5], *log[6:]], False, "seq_unexpected"),
        ("delete the first entry", log[1:], False, "seq_unexpected"),
        ("delete the newest entries (no anchor)", log[:8], False, None),
        ("delete the newest entries (with anchor)", log[:8], True, "truncated"),
        (
            "insert an entry with valid links",
            [*log[:6], forged_linked, *log[6:]],
            False,
            "seq_unexpected",
        ),
        ("reorder two entries", swap(log, 3, 4), False, "seq_unexpected"),
        ("replay an old entry at the end", [*log, log[2]], False, "seq_unexpected"),
        (
            "modify an entry and recompute its hash",
            [
                *log[:4],
                rewrite(log[4], payload=canonicalize({"step": 5, "amount": 1, "note": "x"})),
                *log[5:],
            ],
            False,
            "prev_mismatch",
        ),
        (
            "modify the newest entry and recompute its hash (no anchor)",
            [
                *log[:-1],
                rewrite(log[-1], payload=canonicalize({"step": 12, "amount": 1, "note": "x"})),
            ],
            False,
            None,
        ),
        (
            "modify the newest entry and recompute its hash (with anchor)",
            [
                *log[:-1],
                rewrite(log[-1], payload=canonicalize({"step": 12, "amount": 1, "note": "x"})),
            ],
            True,
            "anchor_mismatch",
        ),
        ("rebuild the whole log (no anchor)", rewritten_all, False, None),
        ("rebuild the whole log (with anchor)", rewritten_all, True, "anchor_mismatch"),
    ]

    print()
    print(f"  {'attack':<62} {'result':<10} first broken link")
    failures = 0
    for name, tampered, use_anchor, expected in attacks:
        result = verify_chain(tampered, anchor=anchor if use_anchor else None)
        if result.ok:
            outcome, detail = "NOT SEEN", "the log is internally consistent"
        else:
            assert result.first_break is not None
            b = result.first_break
            outcome, detail = "detected", f"entry {b.index} (seq {b.seq}): {b.code}"
        good = (expected is None and result.ok) or (
            expected is not None
            and not result.ok
            and result.first_break is not None
            and result.first_break.code == expected
        )
        failures += not good
        print(f"  {name:<62} {outcome:<10} {detail}" + ("" if good else "   <-- UNEXPECTED"))

    print()
    print("Merkle inclusion proof for one checkout entry")
    target = 2
    proof = inclusion_proof(checkout_hashes, target)
    ok_before = verify_inclusion(checkout_hashes[target], proof, stored_root)
    altered = replace(log[2], payload=canonicalize({"step": 3, "amount": 1, "note": "x"}))
    rehashed = rewrite(altered)
    ok_after = verify_inclusion(rehashed.entry_hash, proof, stored_root)
    print(f"  proof checks against the stored root:                 {ok_before}")
    print(f"  the same proof for an altered, re-hashed entry:       {ok_after}")
    failures += (not ok_before) or ok_after

    print()
    print(
        "Reading the table: a hash chain shows edits, deletions, insertions and reordering, but a\n"
        "consistent rewrite of the newest entries or of the whole log is only visible against an\n"
        "anchor or Merkle root stored where the writer cannot change it. This is a tamper-evident\n"
        "log, not a blockchain."
    )
    print(
        f"\n{'ALL ATTACKS BEHAVED AS EXPECTED' if not failures else f'{failures} UNEXPECTED RESULT(S)'}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

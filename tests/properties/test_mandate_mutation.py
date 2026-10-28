"""Mutation property: changing any single character of a valid signed credential must fail.

For each position of a valid chain the character is replaced; verification must raise a
`MandateError`. Any other exception type also fails the test (a crash is not a rejection).

Equivalent cases. In a plain SD-JWT stack, the last base64url character of a segment carries
unused bits, so changing them leaves the decoded bytes (and a signature) unchanged. Countersign's
decoder insists on canonical text (structure.decode_b64url), so those flips are rejected too and
there is NO position where a flip is harmless. `test_noncanonical_base64_is_the_only_equivalent_class`
documents that class and pins that it stays rejected, so it can never be listed as skipped.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from countersign.mandates import verify_chain
from countersign.mandates.errors import MandateError
from tests.mandate_issuer import CLOSED_VCT, NOW, OPEN_VCT, Issued, issue

POOL = "ABCxyz019-_.~ =+/\n\t\x00\x7f\u00e9\u20ac"
CHAINS = {kind: issue(kind) for kind in ("checkout", "payment")}


def _verify(issued: Issued, token: str) -> None:
    verify_chain(
        token,
        issuer_key=issued.keys.issuer,
        expected_vcts=[OPEN_VCT[issued.kind], CLOSED_VCT[issued.kind]],
        audience=issued.audience,
        nonce=issued.nonce,
        clock=lambda: NOW,
    )


def _flip(token: str, index: int, replacement: str) -> str:
    return token[:index] + replacement + token[index + 1 :]


@pytest.mark.parametrize("kind", ["checkout", "payment"])
def test_the_unmodified_chain_verifies(kind: str) -> None:
    _verify(CHAINS[kind], CHAINS[kind].token)


@given(
    kind=st.sampled_from(["checkout", "payment"]),
    position=st.floats(min_value=0, max_value=1, exclude_max=True),
    replacement=st.sampled_from(POOL),
    bit=st.integers(min_value=0, max_value=6),
    use_bit=st.booleans(),
)
def test_any_single_character_change_fails(
    kind: str, position: float, replacement: str, bit: int, use_bit: bool
) -> None:
    issued = CHAINS[kind]
    index = int(position * len(issued.token))
    original = issued.token[index]
    new = chr(ord(original) ^ (1 << bit)) if use_bit else replacement
    if new == original:
        return
    with pytest.raises(MandateError):
        _verify(issued, _flip(issued.token, index, new))


@pytest.mark.parametrize("kind", ["checkout", "payment"])
def test_every_position_with_a_substitute_character_fails(kind: str) -> None:
    """Exhaustive: each position, one different base64url character (or '_' for '-')."""
    issued = CHAINS[kind]
    for index, original in enumerate(issued.token):
        new = "A" if original != "A" else "B"
        with pytest.raises(MandateError):
            _verify(issued, _flip(issued.token, index, new))


@pytest.mark.parametrize("kind", ["checkout", "payment"])
def test_deleting_or_duplicating_any_single_character_fails(kind: str) -> None:
    issued = CHAINS[kind]
    for index in range(0, len(issued.token), 7):
        with pytest.raises(MandateError):
            _verify(issued, issued.token[:index] + issued.token[index + 1 :])
        with pytest.raises(MandateError):
            _verify(issued, issued.token[:index] + issued.token[index] + issued.token[index:])


def test_noncanonical_base64_is_the_only_equivalent_class() -> None:
    """Unused trailing bits of a base64url segment decode to the same bytes; we reject them."""
    issued = CHAINS["checkout"]
    first = issued.token.split("~")[0]
    header, payload, signature = first.split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for segment_index, segment in enumerate((header, payload, signature)):
        if len(segment) % 4 == 0:
            continue  # no unused bits in a segment that fills whole quanta
        changed = alphabet[alphabet.index(segment[-1]) ^ 1]
        parts = [header, payload, signature]
        parts[segment_index] = segment[:-1] + changed
        with pytest.raises(MandateError) as caught:
            _verify(issued, issued.token.replace(first, ".".join(parts), 1))
        assert caught.value.code == "structure_base64url"

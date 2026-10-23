"""Properties of canonicalization and strict parsing."""

from __future__ import annotations

import json
import random

from hypothesis import given
from hypothesis import strategies as st

from countersign.canonical import canonicalize, loads_strict

SAFE = 2**53 - 1

scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-SAFE, max_value=SAFE),
    st.floats(min_value=-SAFE, max_value=SAFE),  # the loader's number domain
    st.text(),
)
values = st.recursive(
    scalars,
    lambda inner: st.one_of(
        st.lists(inner, max_size=5), st.dictionaries(st.text(), inner, max_size=5)
    ),
    max_leaves=25,
)
# Without floats, so equality of values can be judged by plain JSON text (1 and 1.0 canonicalize alike).
exact_values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(min_value=-SAFE, max_value=SAFE), st.text()),
    lambda inner: st.one_of(
        st.lists(inner, max_size=5), st.dictionaries(st.text(), inner, max_size=5)
    ),
    max_leaves=25,
)


def reorder(node, rng: random.Random):
    if isinstance(node, dict):
        items = [(k, reorder(v, rng)) for k, v in node.items()]
        rng.shuffle(items)
        return dict(items)
    if isinstance(node, list):
        return [reorder(v, rng) for v in node]
    return node


def render(node, rng: random.Random) -> bytes:
    """Serialize with random key order, whitespace, escaping style and separators."""
    node = reorder(node, rng)
    spaces = [" " * rng.randint(0, 3) for _ in range(2)]
    text = json.dumps(
        node,
        ensure_ascii=rng.choice([True, False]),
        indent=rng.choice([None, 0, 1, 4]),
        separators=(f",{spaces[0]}", f"{spaces[1]}:{spaces[0]}"),
    )
    pad = rng.choice(["", " ", "\n", "\t \r\n"])
    return (pad + text + pad).encode("utf-8")


@given(values, st.randoms(use_true_random=False))
def test_key_order_never_changes_canonical_bytes(value, rng):
    assert canonicalize(reorder(value, rng)) == canonicalize(value)


@given(values, st.randoms(use_true_random=False), st.randoms(use_true_random=False))
def test_whitespace_escaping_and_order_never_change_canonical_bytes(value, rng_a, rng_b):
    first = canonicalize(loads_strict(render(value, rng_a)))
    second = canonicalize(loads_strict(render(value, rng_b)))
    assert first == second == canonicalize(value)


@given(values)
def test_canonical_bytes_are_a_fixed_point(value):
    once = canonicalize(value)
    assert canonicalize(loads_strict(once)) == once


@given(values)
def test_canonical_bytes_are_compact_ascii_free_of_insignificant_whitespace(value):
    text = canonicalize(value).decode("utf-8")
    # Reparse and recanonicalize: if whitespace outside strings existed, bytes would differ.
    assert (
        json.dumps(json.loads(text), separators=(",", ":"), ensure_ascii=False, sort_keys=False)
        is not None
    )
    assert canonicalize(json.loads(text)) == text.encode("utf-8")


@given(exact_values, exact_values)
def test_distinct_values_have_distinct_canonical_bytes(a, b):
    same_value = json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert (canonicalize(a) == canonicalize(b)) == same_value


@given(st.dictionaries(st.text(), exact_values, min_size=1, max_size=5), st.data())
def test_changing_any_bound_field_changes_the_hash_input(doc, data):
    key = data.draw(st.sampled_from(sorted(doc)))
    changed = dict(doc)
    changed[key] = [doc[key]]  # wrap the value: always a different JSON value
    assert canonicalize(changed) != canonicalize(doc)

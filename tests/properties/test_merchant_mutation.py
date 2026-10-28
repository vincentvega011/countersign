"""Single-field mutation of a signed closed Checkout Mandate must fail Merchant verification.

(A) Tamper: any one field of the closed link (a JOSE header member, a payload member, any leaf of
any disclosure) is changed or removed WITHOUT re-signing. Verification must return `Rejected`, and
never `Accepted`, and never fail with `internal_error` (a crash is not a rejection).

(B) Re-signed by the legitimate agent: the agent signs a closed mandate with one field changed.
Bound fields must be rejected. The fields below in FREE are explicit equivalent cases: changing
them yields another valid mandate, which is the intended behaviour, and the test pins that they
are accepted so the equivalence is checked rather than skipped.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from countersign.canonical import checkout_hash
from countersign.merchant.verify import Accepted, Rejected
from tests.mandate_issuer import NOW
from tests.merchant_support import make_setup

S = make_setup()
TOKEN = S.mandate().token
OPEN_PART, CLOSED_PART = TOKEN[:-1].split("~~")
CLOSED = CLOSED_PART.split("~")  # jwt, disclosures...


def _dec(text: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))


def _enc(value: Any) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _leaves(value: Any, path: tuple = ()) -> list[tuple]:
    if isinstance(value, dict):
        out: list[tuple] = []
        for key, item in value.items():
            out += _leaves(item, (*path, key))
        return out or [path]
    if isinstance(value, list):
        out = []
        for index, item in enumerate(value):
            out += _leaves(item, (*path, index))
        return out or [path]
    return [path]


def _get(value: Any, path: tuple) -> Any:
    for step in path:
        value = value[step]
    return value


def _mutate(value: Any, path: tuple, how: int) -> Any:
    value = json.loads(json.dumps(value))
    if not path:
        return None if value is not None else 0
    parent, key = _get(value, path[:-1]), path[-1]
    old = parent[key]
    if how == 0 and isinstance(parent, dict):
        del parent[key]
    elif how == 1:
        parent[key] = None if old is not None else 0
    elif isinstance(old, str):
        parent[key] = old + "x" if how == 2 else old[:-1] + chr(ord(old[-1]) ^ 1) if old else "x"
    elif isinstance(old, bool):
        parent[key] = not old
    elif isinstance(old, int):
        parent[key] = old + 1
    else:
        parent[key] = [old]
    return value


def _targets() -> list[tuple[str, int, tuple]]:
    jwt = CLOSED[0].split(".")
    items: list[tuple[str, int, tuple]] = []
    for part, name in ((0, "header"), (1, "payload")):
        items += [(name, part, p) for p in _leaves(_dec(jwt[part]))]
    for index in range(1, len(CLOSED)):
        items += [("disclosure", index, p) for p in _leaves(_dec(CLOSED[index]))]
    return items


TARGETS = _targets()


def _tampered(target: tuple[str, int, tuple], how: int) -> str:
    kind, index, path = target
    parts = list(CLOSED)
    if kind in ("header", "payload"):
        jwt = parts[0].split(".")
        jwt[index] = _enc(_mutate(_dec(jwt[index]), path, how))
        parts[0] = ".".join(jwt)
    else:
        parts[index] = _enc(_mutate(_dec(parts[index]), path, how))
    return OPEN_PART + "~~" + "~".join(parts)


def test_the_targets_cover_header_payload_and_every_disclosure() -> None:
    kinds = {t[0] for t in TARGETS}
    assert kinds == {"header", "payload", "disclosure"}
    assert len(TARGETS) >= 15


def test_the_unmodified_mandate_is_accepted() -> None:
    fresh = make_setup()
    assert isinstance(fresh.verify(fresh.mandate().token), Accepted)


@given(target=st.sampled_from(TARGETS), how=st.integers(min_value=0, max_value=3))
def test_tampering_with_any_single_field_fails(target: tuple, how: int) -> None:
    result = S.verify(_tampered(target, how))
    assert isinstance(result, Rejected), (target, how)
    assert result.reason != "internal_error", (target, how)


def test_every_target_with_every_mutation_fails() -> None:
    for target in TARGETS:
        for how in range(4):
            result = S.verify(_tampered(target, how))
            assert isinstance(result, Rejected), (target, how)
            assert result.reason != "internal_error", (target, how)


# ----- (B) re-signed by the legitimate agent -----

BOUND = {
    "vct": {"edit_kb_content": lambda c: c.update(vct="mandate.checkout.open.1")},
    "checkout_hash": {"checkout_hash_value": "x" * 43},
    "exp_in_the_past": {"closed_exp": NOW - 61},
    "nbf_in_the_future": {"closed_nbf": NOW + 61},
    "aud": {"kb_aud": "credential-provider"},
    "sd_hash": {"sd_hash_value": "y" * 43},
    "iat_in_the_future": {"kb_iat": NOW + 61},
    "typ": {"kb_typ": "kb+jwt"},
    "checkout_jwt_removed": {"omit_checkout_jwt": True},
    "alg": {"kb_alg_header": "ES384"},
}

# Equivalent cases: the mutated mandate is another legitimate mandate.
FREE = {
    "nonce_changed": {"nonce": "another-nonce"},
    "unrelated_claim_added": {"edit_kb_content": lambda c: c.update(note="ignored")},
    "iat_within_skew": {"kb_iat": NOW + 60},
    "closed_exp_added": {"closed_exp": NOW + 600},
}


@pytest.mark.parametrize("name", sorted(BOUND))
def test_a_resigned_mandate_with_a_bound_field_changed_fails(name: str) -> None:
    s = make_setup()
    assert isinstance(s.verify(s.mandate(**BOUND[name]).token), Rejected), name


@pytest.mark.parametrize("name", sorted(FREE))
def test_documented_equivalent_cases_are_accepted(name: str) -> None:
    s = make_setup()
    assert isinstance(s.verify(s.mandate(**FREE[name]).token), Accepted), name


def test_checkout_hash_stays_the_hash_of_the_session_jwt() -> None:
    assert S.mandate().token and checkout_hash(S.jwt)

"""The customer id is the signed top-level `sub` of the platform's issuer JWT, and it is mandatory.

Decision 47 and its follow-up (Decision 82): a mandate without a usable `sub` is not a mandate this
verifier accepts. The shared vectors (tests/vectors/mandates) cover the chain level for Python and Node;
this file covers the rule itself and what is, and is not, read as the customer id.
"""

from __future__ import annotations

from typing import Any

import pytest

from countersign.mandates import MandateError, customer_id_of, verify_chain
from countersign.mandates.errors import SubjectMissingError
from tests.mandate_issuer import NOW, SUBJECT, Keys, issue

GOOD = "cus_" + "A" * 22


@pytest.mark.parametrize("value", [GOOD, "c", "c" * 128, "customer 1", "a.b-c_d"])
def test_a_printable_string_of_one_to_128_characters_is_a_customer_id(value: str) -> None:
    assert customer_id_of({"sub": value}) == value


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        " ",
        " x",
        "x ",
        "x\n",
        "\tx",
        "c" * 129,
        "a\x07b",
        "a\u200bb",
        5,
        1.5,
        True,
        [],
        {},
    ],
)
def test_anything_else_is_no_customer_id(value: Any) -> None:
    assert customer_id_of({"sub": value}) is None


def test_a_missing_sub_is_no_customer_id() -> None:
    assert customer_id_of({}) is None


def verify(issued: Any, keys: Keys) -> Any:
    return verify_chain(
        issued.token,
        issuer_key=keys.issuer,
        expected_vcts=["mandate.checkout.open.1", "mandate.checkout.1"],
        audience="merchant",
        nonce=issued.nonce,
        clock=lambda: NOW,
    )


def test_a_chain_with_a_sub_verifies_and_exposes_it() -> None:
    keys = Keys()
    chain = verify(issue(keys=keys), keys)
    assert chain.links[0].claims["sub"] == SUBJECT


@pytest.mark.parametrize("bad", [None, "", " x", "c" * 129])
def test_a_chain_without_a_usable_sub_is_refused_with_its_own_code(bad: str | None) -> None:
    keys = Keys()
    with pytest.raises(SubjectMissingError) as error:
        verify(issue(keys=keys, sub=bad), keys)
    assert error.value.code == "subject_missing" and isinstance(error.value, MandateError)


def test_a_vct_problem_is_reported_before_a_missing_sub() -> None:
    keys = Keys()
    with pytest.raises(MandateError) as error:
        verify(issue(keys=keys, sub=None, open_vct="mandate.checkout.open.2"), keys)
    assert error.value.code == "vct_mismatch"


def test_only_the_issuer_link_needs_a_sub() -> None:
    """The key-binding links carry no customer id, and must not be asked for one."""
    keys = Keys()
    chain = verify(issue(keys=keys, hops=2), keys)
    assert "sub" not in chain.links[1].claims

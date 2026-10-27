"""The capture approval can only be minted, never built, altered, copied or pickled."""

from __future__ import annotations

import copy
import pickle
from typing import Any

import pytest

from countersign.canonical.money import Money
from countersign.paypal.approval import CaptureApproval, mint_capture_approval

GOOD: dict[str, Any] = {
    "checkout_id": "chk_abcdefghijklmnopqrstuv",
    "authorization_id": "AUTH1",
    "expected_total": Money("USD", 7400),
    "invoice_id": "chk_abcdefghijklmnopqrstuv",
    "custom_id": "cs1.abc",
}


def test_the_mint_builds_an_approval_with_the_fields_given() -> None:
    approval = mint_capture_approval(**GOOD)
    assert type(approval) is CaptureApproval
    for name, value in GOOD.items():
        assert getattr(approval, name) == value


@pytest.mark.parametrize("seal", [None, object(), 0, "seal", True])
def test_the_constructor_refuses_without_the_seal(seal: object) -> None:
    with pytest.raises(TypeError, match="capture gate"):
        CaptureApproval(seal, **GOOD)


def test_the_constructor_cannot_be_called_with_no_seal_at_all() -> None:
    with pytest.raises(TypeError):
        CaptureApproval(**GOOD)  # type: ignore[call-arg]


def test_it_cannot_be_subclassed() -> None:
    with pytest.raises(TypeError, match="subclassed"):

        class Forged(CaptureApproval):
            pass


def test_it_is_immutable() -> None:
    approval = mint_capture_approval(**GOOD)
    with pytest.raises(AttributeError):
        approval.custom_id = "cs1.other"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        del approval.custom_id
    with pytest.raises(AttributeError):
        approval.extra = 1  # type: ignore[attr-defined]


def test_it_cannot_be_copied_or_pickled() -> None:
    approval = mint_capture_approval(**GOOD)
    with pytest.raises(TypeError):
        copy.copy(approval)
    with pytest.raises(TypeError):
        copy.deepcopy(approval)
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        with pytest.raises(TypeError):
            pickle.dumps(approval, protocol)


@pytest.mark.parametrize(
    "override",
    [
        {"expected_total": Money("USD", 0)},
        {"expected_total": Money("USD", -1)},
        {"expected_total": 7400},
        {"expected_total": "74.00"},
        {"checkout_id": ""},
        {"checkout_id": None},
        {"authorization_id": "AUTH/1"},
        {"authorization_id": ""},
        {"invoice_id": ""},
        {"custom_id": ""},
        {"custom_id": "x" * 256},
        {"invoice_id": "x" * 128},
    ],
)
def test_bad_fields_are_refused(override: dict[str, Any]) -> None:
    with pytest.raises((ValueError, TypeError)):
        mint_capture_approval(**{**GOOD, **override})


def test_the_repr_has_no_amounts_or_ids_beyond_the_two_references() -> None:
    text = repr(mint_capture_approval(**GOOD))
    assert "AUTH1" in text and "cs1.abc" not in text and "7400" not in text

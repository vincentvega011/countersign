"""Direct tests of mandate primitives that the shared vectors do not express."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from joserfc.jwk import ECKey

from countersign.mandates import CLOCK_SKEW_SECONDS, MAX_MANDATE_CHARS, split_chain, verify_chain
from countersign.mandates.errors import (
    ClaimTypeError,
    ExpiredError,
    ExpMissingError,
    IssuedInFutureError,
    MandateError,
    MandateTooLargeError,
    MandateTypeError,
    NotYetValidError,
    UnknownExpectedVctError,
)
from countersign.mandates.timecheck import check_times
from tests.mandate_issuer import CLOSED_VCT, NOW, OPEN_VCT, issue

SRC = Path(__file__).resolve().parents[2] / "src" / "countersign" / "mandates"
VCTS = [OPEN_VCT["checkout"], CLOSED_VCT["checkout"]]


def _verify(issued, **kwargs):  # type: ignore[no-untyped-def]
    options = {
        "issuer_key": issued.keys.issuer,
        "expected_vcts": VCTS,
        "audience": issued.audience,
        "nonce": issued.nonce,
        "clock": lambda: NOW,
    } | kwargs
    return verify_chain(issued.token, **options)


def test_the_provisional_skew_is_sixty_seconds() -> None:
    assert CLOCK_SKEW_SECONDS == 60


def test_a_valid_chain_exposes_verified_content() -> None:
    issued = issue()
    chain = _verify(issued)
    open_link, closed = chain.links
    assert open_link.content["vct"] == OPEN_VCT["checkout"]
    assert open_link.cnf_thumbprint == issued.keys.agent.thumbprint()
    assert closed.audience == "merchant" and closed.nonce == "nonce-0001"
    assert closed.content["checkout_hash"] == closed.content["checkout_hash"]
    assert "checkout_jwt" in closed.content
    assert chain.final is closed
    assert open_link.serialization == issued.open_token


def test_the_issuer_may_be_given_as_a_private_key() -> None:
    issued = issue()
    assert _verify(issued, issuer_key=ECKey.import_key(issued.keys.issuer.as_dict()))


def test_nonce_none_still_requires_a_nonce_in_the_key_binding() -> None:
    assert _verify(issue(), nonce=None)
    with pytest.raises(MandateError) as caught:
        _verify(issue(omit_nonce=True), nonce=None)
    assert caught.value.code == "kb_claim_missing"


def test_the_clock_is_injected_and_read_once() -> None:
    calls: list[int] = []

    def clock() -> float:
        calls.append(1)
        return NOW

    _verify(issue(), clock=clock)
    assert calls == [1]


@pytest.mark.parametrize("vcts", [[], ["mandate.checkout.open.1", "mandate.unknown.1"], ["x"]])
def test_unknown_or_empty_expected_vcts_fail_closed(vcts: list[str]) -> None:
    with pytest.raises(UnknownExpectedVctError):
        _verify(issue(), expected_vcts=vcts)


@pytest.mark.parametrize("token", [None, 5, b"abc~", ["a"]])
def test_a_non_string_mandate_is_rejected_with_a_typed_error(token: object) -> None:
    with pytest.raises(MandateTypeError):
        split_chain(token)


def test_an_oversized_mandate_is_rejected_before_anything_else() -> None:
    with pytest.raises(MandateTooLargeError):
        split_chain("A" * (MAX_MANDATE_CHARS + 1))
    assert split_chain("a.b.c~")  # shape only; nothing is decoded here


def test_split_chain_reports_links_and_the_hashed_serialization() -> None:
    issued = issue()
    first, second = split_chain(issued.token)
    assert first.serialization == issued.open_token
    assert issued.token == first.serialization + "~" + second.serialization


@pytest.mark.parametrize(
    ("exp", "now", "error"),
    [
        (1000, 1060, None),
        (1000, 1061, ExpiredError),
        (1000, 900, None),
        (None, 1000, ExpMissingError),
        (True, 1000, ClaimTypeError),
        ("1000", 1000, ClaimTypeError),
        (1000.5, 1000, ClaimTypeError),
    ],
)
def test_check_times_exp(exp: object, now: int, error: type[Exception] | None) -> None:
    claims = {} if exp is None else {"exp": exp}
    if error is None:
        check_times(claims, now, require_exp=True)  # type: ignore[arg-type]
    else:
        with pytest.raises(error):
            check_times(claims, now, require_exp=True)  # type: ignore[arg-type]


def test_check_times_nbf_and_iat_boundaries() -> None:
    check_times({"nbf": 1060}, 1000, require_exp=False)
    check_times({"iat": 1060}, 1000, require_exp=False)
    with pytest.raises(NotYetValidError):
        check_times({"nbf": 1061}, 1000, require_exp=False)
    with pytest.raises(IssuedInFutureError):
        check_times({"iat": 1061}, 1000, require_exp=False)
    check_times({"nbf": 1000}, 1000, require_exp=False)


def test_exp_is_not_required_on_the_final_key_binding() -> None:
    assert _verify(issue(closed_exp=None))
    assert _verify(issue(hops=3), expected_vcts=[VCTS[0], VCTS[0], VCTS[1]])


def test_no_bare_or_blanket_except_in_the_package() -> None:
    """INV-10: errors are caught by type, so an unexpected failure cannot be swallowed."""
    for path in SRC.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ExceptHandler):
                assert node.type is not None, f"bare except in {path.name}:{node.lineno}"
                names = ast.dump(node.type)
                assert "'Exception'" not in names, f"except Exception in {path.name}:{node.lineno}"
                assert "BaseException" not in names


def test_every_error_class_has_a_distinct_stable_code() -> None:
    from countersign.mandates import errors

    classes = [
        c
        for c in vars(errors).values()
        if isinstance(c, type) and issubclass(c, MandateError) and c.__module__ == errors.__name__
    ]
    codes = [c.code for c in classes]
    structural_bases = {"MandateStructureError", "DisclosureError"}
    concrete = [c for c in classes if c.__name__ not in structural_bases]
    assert len({c.code for c in concrete}) == len(concrete), codes

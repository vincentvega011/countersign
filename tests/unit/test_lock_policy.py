"""The merchant lock policy as pure data: shape, version, hash and the threshold boundary (INV-9)."""

from __future__ import annotations

import pytest

from countersign.canonical.money import Money
from countersign.lock import MerchantPolicy, PolicyError


def test_the_default_policy_requires_nothing() -> None:
    policy = MerchantPolicy(0)
    assert policy.mode == "off" and not policy.requires_ap2(Money("USD", 10**9))


def test_require_all_requires_every_total_even_none() -> None:
    policy = MerchantPolicy(1, "all")
    assert policy.requires_ap2(Money("USD", 0)) and policy.requires_ap2(None)


@pytest.mark.parametrize("minor,expected", [(0, False), (4999, False), (5000, False), (5001, True)])
def test_over_threshold_is_strictly_above_the_limit(minor: int, expected: bool) -> None:
    policy = MerchantPolicy(1, "over_threshold", 5000, "USD")
    assert policy.requires_ap2(Money("USD", minor)) is expected


def test_a_total_in_another_currency_or_none_counts_as_over() -> None:
    policy = MerchantPolicy(1, "over_threshold", 5000, "USD")
    assert policy.requires_ap2(Money("EUR", 1)) and policy.requires_ap2(None)


def test_the_hash_covers_every_field_and_the_version() -> None:
    base = MerchantPolicy(1, "over_threshold", 5000, "USD")
    variants = [
        MerchantPolicy(2, "over_threshold", 5000, "USD"),
        MerchantPolicy(1, "over_threshold", 5001, "USD"),
        MerchantPolicy(1, "over_threshold", 5000, "EUR"),
        MerchantPolicy(1, "all"),
        MerchantPolicy(1, "off"),
    ]
    hashes = {v.hash() for v in variants} | {base.hash()}
    assert len(hashes) == len(variants) + 1
    assert base.hash() == MerchantPolicy(1, "over_threshold", 5000, "USD").hash()


@pytest.mark.parametrize(
    "args",
    [
        (1, "maybe", None, None),
        (1, "over_threshold", None, None),
        (1, "over_threshold", 5000, None),
        (1, "over_threshold", -1, "USD"),
        (1, "over_threshold", 50.5, "USD"),
        (1, "over_threshold", True, "USD"),
        (1, "all", 5000, "USD"),
        (-1, "off", None, None),
        (True, "off", None, None),
    ],
)
def test_a_malformed_policy_is_refused(args: tuple) -> None:  # type: ignore[type-arg]
    with pytest.raises(PolicyError):
        MerchantPolicy(*args)

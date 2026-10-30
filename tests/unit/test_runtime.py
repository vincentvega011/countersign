"""Mode and ablation settings: what starts, what is refused, and that nothing is inferred."""

from __future__ import annotations

import pytest

from countersign.ablations import NAMES
from countersign.main import create
from countersign.runtime import Mode, ModeRefused, RuntimeSettings


def test_the_default_is_full_with_nothing_switched_off() -> None:
    settings = RuntimeSettings.from_env({})
    assert settings.mode is Mode.FULL and not settings.ablations.any
    assert settings.active_ablations == () and settings.app_env == "dev"


@pytest.mark.parametrize("value", ["", "FULL", "Baseline", "naive", "baseline ", "0", "true"])
def test_only_the_two_exact_mode_names_are_accepted(value: str) -> None:
    with pytest.raises(ModeRefused, match="CS_MODE"):
        RuntimeSettings.from_env({"CS_MODE": value})


def test_baseline_must_be_asked_for_by_name() -> None:
    assert RuntimeSettings.from_env({"CS_MODE": "baseline"}).mode is Mode.BASELINE
    assert RuntimeSettings.from_env({"CS_MODE": "full"}).mode is Mode.FULL


def test_baseline_is_allowed_in_demo_because_the_comparison_needs_it() -> None:
    settings = RuntimeSettings.from_env({"CS_MODE": "baseline", "APP_ENV": "demo"})
    assert settings.mode is Mode.BASELINE and settings.app_env == "demo"


@pytest.mark.parametrize("name", NAMES)
def test_every_ablation_is_refused_in_demo_and_accepted_elsewhere(name: str) -> None:
    with pytest.raises(ModeRefused, match="APP_ENV=demo"):
        RuntimeSettings.from_env({"APP_ENV": "demo", name: "1"})
    assert RuntimeSettings.from_env({"APP_ENV": "dev", name: "1"}).active_ablations == (name,)
    assert RuntimeSettings.from_env({"APP_ENV": "demo", name: "0"}).active_ablations == ()


@pytest.mark.parametrize("name", NAMES)
def test_a_demo_process_with_an_ablation_does_not_start(name: str) -> None:
    """The entry point refuses before it reads a key, opens a database or builds PayPal."""
    env = {"APP_ENV": "demo", name: "1"}  # no keys, no database: nothing else may be reached
    with pytest.raises(ModeRefused):
        create(env)


def test_an_ablation_together_with_baseline_is_refused() -> None:
    with pytest.raises(ModeRefused, match="baseline"):
        RuntimeSettings.from_env({"CS_MODE": "baseline", "ABL_NO_GATE": "1"})


def test_a_flag_value_other_than_0_or_1_is_refused() -> None:
    with pytest.raises(ModeRefused):
        RuntimeSettings.from_env({"ABL_NO_GATE": "yes"})

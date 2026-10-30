"""The behavior matrix: every mode and every flag against a fixed set of scenarios.

The expected outcomes are checked in as data (`tests/vectors/behavior_matrix.json`): the `full` row
in whole, and for every other configuration only the cells that differ from `full`. A cell that is
not listed must equal `full`'s, so a flag that leaks into another behavior fails here, and so does
a flag that stops doing what it is for. `TARGETS` names the scenarios each configuration may change;
the data may not list a cell outside them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import Engine

from tests.behavior_scenarios import SCENARIOS, Outcome
from tests.mode_support import CONFIGS, make_world, reset, settings_for

MATRIX = json.loads((Path(__file__).parents[1] / "vectors" / "behavior_matrix.json").read_text())

ACP = "acp_complete_without_mandate_by_a_locked_principal"
TARGETS: dict[str, set[str]] = {
    "full": set(),
    # Baseline changes exactly what its definition omits (docs/PROTOCOL.md Decision 59).
    "baseline": {
        "nonce_replay_in_a_new_session",
        "order_raised_while_approved",
        "order_items_changed_while_approved",
        ACP,
        "budget_split_across_sessions",
        "duplicate_json_keys",
    },
    # Layered defenses: the pre-authorize check stops these first, so the gate alone reopens nothing.
    "ABL_NO_GATE": set(),
    # With the pre-check off the authorization is made and the gate must void it.
    "ABL_NO_PREAUTH_CHECK": {"order_raised_while_approved", "order_items_changed_while_approved"},
    "ABL_NO_PRINCIPAL_LOCK": {ACP},
    # The open-mandate rule is also global, so the budget view alone reopens nothing either.
    "ABL_NO_BUDGET_RECON": set(),
    # The split is still refused, one layer later: by the budget ledger instead of the open-mandate rule.
    "ABL_NO_GLOBAL_NONCE": {"nonce_replay_in_a_new_session", "budget_split_across_sessions"},
    "ABL_NO_STRICT_JSON": {"duplicate_json_keys"},
}


def expected(config: str, scenario: str) -> Outcome:
    out: Outcome = MATRIX["full"][scenario]
    return MATRIX["differences"].get(config, {}).get(scenario, out)  # type: ignore[no-any-return]


def run(admin: Engine, app: Engine, config: str, scenario: str) -> Outcome:
    reset(admin)
    world = make_world(app, settings_for(config))
    with world.client:
        return SCENARIOS[scenario](world)


def test_the_data_covers_every_scenario_and_only_targeted_cells_differ() -> None:
    assert set(MATRIX["full"]) == set(SCENARIOS)
    assert set(MATRIX["differences"]) <= set(CONFIGS) - {"full"}
    for config, cells in MATRIX["differences"].items():
        assert set(cells) <= TARGETS[config], f"{config} lists a cell it may not change"
        for scenario, out in cells.items():
            assert out != MATRIX["full"][scenario], f"{config}/{scenario} equals full: drop it"


@pytest.mark.parametrize("scenario", list(SCENARIOS))
@pytest.mark.parametrize("config", CONFIGS)
def test_the_outcome_matches_the_table(
    admin_engine: Engine, app_engine: Engine, config: str, scenario: str
) -> None:
    assert run(admin_engine, app_engine, config, scenario) == expected(config, scenario)


def test_the_rows_that_matter_differ_between_full_and_baseline() -> None:
    """Guards the table itself: baseline really loses the protections, full really has them."""
    full, base = MATRIX["full"], MATRIX["differences"]["baseline"]
    assert full["nonce_replay_in_a_new_session"]["captured"] == 1
    assert base["nonce_replay_in_a_new_session"]["captured"] == 2
    assert full[ACP]["captured"] == 0 and base[ACP]["captured"] == 1
    # The split is refused in baseline too, by its local budget counter; only the stage differs.
    assert full["budget_split_across_sessions"]["captured"] == 1
    assert base["budget_split_across_sessions"]["captured"] == 1
    assert (
        base["budget_split_across_sessions"]["result"]
        != full["budget_split_across_sessions"]["result"]
    )

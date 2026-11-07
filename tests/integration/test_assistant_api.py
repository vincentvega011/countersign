"""Ask Countersign over the real read models: the endpoint, grounded counts, and the code table's coverage."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text

from countersign.assistant import Assistant
from countersign.assistant.codes import CODES
from countersign.dashboard import read
from countersign.dashboard.assistant_data import DashboardData
from countersign.runtime import Mode, RuntimeSettings
from tests.assistant_support import gateway, plan
from tests.mode_support import World, make_world, reset

API = "/dashboard/api/v1/assistant"
ROOT = Path(__file__).resolve().parents[2]


def _seed_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "dashboard_seed", ROOT / "scripts" / "dashboard_seed.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def world(app_engine: Engine, admin_engine: Engine) -> Iterator[World]:
    reset(admin_engine)
    seed = _seed_module()
    seed.seed_simulated(app_engine, 80, 2)
    seed.seed_mandates(admin_engine)
    w = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    with w.client:
        yield w


def _install(world: World, tmp: Path, script: list[Any]) -> None:
    service = world.client.app.state.dashboard  # type: ignore[attr-defined]
    gw, _ = gateway(script, tmp)
    service.assistant = Assistant(gw, DashboardData(service))


def test_suggestions_are_listed_with_the_mode(world: World) -> None:
    body = world.client.get(f"{API}/suggestions").json()
    assert body["mode"] == "replay" and len(body["suggestions"]) >= 10
    assert all(set(s) == {"label", "question"} for s in body["suggestions"])


def test_the_counts_in_an_answer_equal_independent_sql(
    world: World, admin_engine: Engine, tmp_path: Path
) -> None:
    _install(world, tmp_path, [plan(("query_orders", {})), plan(("open_mandate_state", {}))])
    with admin_engine.connect() as conn:
        orders = conn.execute(text("SELECT count(*) FROM checkout_sessions")).scalar_one()
    body = world.client.get(f"{API}/ask", params={"q": "How many orders are there?"}).json()
    answer = body["answer"]
    assert answer["status"] == "answered" and answer["replaced"] == 0
    assert f"There are {orders} orders in total." == answer["lines"][0]["text"]
    assert {c["kind"] for c in answer["lines"][0]["cites"]} == {"order"}
    mandates = world.client.get(f"{API}/ask", params={"q": "mandates?"}).json()["answer"]
    assert mandates["lines"][0]["text"] == "There are 5 open mandates matching."
    states = {line["text"] for line in mandates["lines"]}
    assert {"used: 1.", "revoked: 1.", "expired: 1.", "unused: 1.", "in flight: 1."} <= states


def test_an_unrecorded_question_in_replay_mode_says_so(world: World) -> None:
    body = world.client.get(f"{API}/ask", params={"q": "something nobody recorded"}).json()
    assert body["mode"] == "replay"
    assert body["answer"]["status"] == "replay_only"
    assert body["answer"]["text"] == "This demo replays recorded questions; pick a suggestion."


def test_every_reason_the_dashboard_can_show_has_a_fixed_explanation(world: World) -> None:
    service = world.client.app.state.dashboard  # type: ignore[attr-defined]
    reasons = {e["reason"] for e in read.protection_events(service.engine)}
    reasons |= {o["reason"] for o in read.orders(service.engine) if o["reason"]}
    assert reasons, "the seed produced no blocked attempts"
    missing = sorted(r for r in reasons if r not in CODES)
    assert missing == [], missing


def test_every_recorded_question_replays_and_is_answered_without_replacement(
    world: World,
) -> None:
    """Uses the real recorded cassettes (red until the owner records them): replay, tools, grounding."""
    import json

    from countersign.api.assistant_routes import RECORDED
    from countersign.assistant.suggestions import SUGGESTIONS
    from countersign.llm import LlmConfig, LlmGateway

    model = json.loads(RECORDED.read_text(encoding="utf-8"))["model"]
    service = world.client.app.state.dashboard  # type: ignore[attr-defined]
    service.assistant = Assistant(
        LlmGateway(LlmConfig(mode="replay", model=model)), DashboardData(service)
    )
    for _, question in SUGGESTIONS:
        body = world.client.get(f"{API}/ask", params={"q": question}).json()["answer"]
        assert body["status"] == "answered", question
        assert body["replaced"] == 0, question
        assert body["lines"], question

"""Browser test of Ask Countersign in Studio's assistant panel, with recorded questions replayed offline.

Planner calls for three suggested questions are recorded here into a temporary cassette directory (a
scripted provider stands in for a model) and replayed through the real gateway in replay mode, so the
test exercises the same path as the demo: replay hit, replay miss, templates, citations, grounding.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from countersign.assistant import Assistant
from countersign.assistant.suggestions import SUGGESTIONS
from countersign.dashboard.assistant_data import DashboardData
from countersign.llm import FakeProvider, LlmConfig, LlmGateway
from countersign.runtime import Mode, RuntimeSettings
from tests.assistant_support import plan
from tests.integration.test_dashboard_detail_browser import _expectations, _run, _start
from tests.mode_support import make_world, reset

ROOT = Path(__file__).resolve().parents[2]
RECORDED = {
    "How many orders are there in total?": plan(("query_orders", {})),
    "How many blocked or voided attempts are there for each reason code?": plan(
        ("blocked_attempts_by_reason", {})
    ),
    "What does the mandate_expired code mean?": plan(
        ("explain_error_code", {"code": "mandate_expired"})
    ),
}


def record_plans(directory: Path, model: str) -> None:
    """Write planner cassettes with the gateway's own record mode and its scrubber."""
    provider = FakeProvider(lambda call: RECORDED[call.messages[-1]["content"]])
    config = LlmConfig(
        mode="record", model=model, base_url="https://example.invalid", api_key="test-key-123456",
        per_minute=1000, cassette_dir=directory,
    )  # fmt: skip
    gateway = LlmGateway(config, provider, sleep=lambda _: None)
    from countersign.assistant.planner import plan_request

    for question in RECORDED:
        gateway.complete(plan_request(question))


def _seed_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "dashboard_seed", ROOT / "scripts" / "dashboard_seed.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def served(
    app_engine: Engine, admin_engine: Engine, tmp_path: Path
) -> Iterator[tuple[str, dict[str, Any]]]:
    reset(admin_engine)
    seed = _seed_module()
    seed.seed_simulated(app_engine, 60, 2)
    seed.seed_mandates(admin_engine)
    record_plans(tmp_path, "test-model")
    world = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    service = world.client.app.state.dashboard  # type: ignore[attr-defined]
    replay = LlmGateway(LlmConfig(mode="replay", model="test-model", cassette_dir=tmp_path))
    service.assistant = Assistant(replay, DashboardData(service))
    expected = _expectations(admin_engine)
    base, server, thread, sock = _start(world.client.app)
    try:
        yield base, expected
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


def test_recorded_questions_replay_offline_in_studios_panel(
    served: tuple[str, dict[str, Any]],
) -> None:
    base, expected = served
    assert {q for _, q in SUGGESTIONS} >= set(RECORDED)
    _run(base, expected, ["test/assistant.test.mjs"])

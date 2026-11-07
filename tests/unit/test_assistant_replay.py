"""The recorded planner calls (Decision 127): present, clean, valid, and replayed with no network.

RED until `scripts/record_assistant_cassettes.py` has been run by the owner: no test here skips.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from countersign.assistant.catalog import catalog_json
from countersign.assistant.planner import make_plan, plan_request
from countersign.assistant.suggestions import SUGGESTIONS
from countersign.llm import LlmConfig, LlmGateway, request_key
from countersign.llm.cassette import DEFAULT_DIR

INDEX = Path(__file__).resolve().parents[2] / "eval" / "cassettes" / "assistant.json"
EXPECTED_FIRST_TOOL = {
    "How many orders are there in total?": "query_orders",
    "How many orders were captured, and for how much in total?": "query_orders",
    "How many blocked or voided attempts are there for each reason code?": "blocked_attempts_by_reason",
    "Which orders were voided by the capture gate?": "query_orders",
    "How many orders were captured with no verified mandate?": "query_orders",
    "How many open mandates are there in each state?": "open_mandate_state",
    "Which open mandates have been used, and how much was spent under them?": "open_mandate_state",
    "Which evidence steps passed for the latest_captured order?": "summarize_evidence",
    "What does the mandate_expired code mean?": "explain_error_code",
    "How does full protection mode compare with baseline mode in the latest evaluation?": "compare_modes",
}
CASSETTE_KEYS = {
    "v",
    "key",
    "task",
    "model",
    "temperature",
    "schema_sha256",
    "messages",
    "reply",
    "usage",
}


def _index() -> dict[str, object]:
    assert INDEX.is_file(), "no eval/cassettes/assistant.json: record the planner calls first"
    return json.loads(INDEX.read_text(encoding="utf-8"))


def _gateway() -> LlmGateway:
    return LlmGateway(LlmConfig(mode="replay", model=str(_index()["model"])))


def test_the_recording_matches_the_current_catalog_and_questions() -> None:
    index = _index()
    assert index["catalog_sha256"] == hashlib.sha256(catalog_json().encode()).hexdigest(), (
        "the tool catalog changed since the recording: record again"
    )
    assert index["questions"] == [q for _, q in SUGGESTIONS]
    assert set(EXPECTED_FIRST_TOOL) == {q for _, q in SUGGESTIONS}


def test_every_suggested_question_has_a_clean_cassette_and_a_valid_plan() -> None:
    gateway = _gateway()
    model = str(_index()["model"])
    for _, question in SUGGESTIONS:
        request = plan_request(question)
        key = request_key(
            request.task, model, request.messages(), request.schema, request.temperature
        )
        path = DEFAULT_DIR / f"{key}.json"
        assert path.is_file(), f"no cassette for {question!r}"
        body = json.loads(path.read_text(encoding="utf-8"))
        assert set(body) == CASSETTE_KEYS, "a cassette carries only the documented members"
        assert [m["role"] for m in body["messages"]] == ["system", "user"]
        assert body["messages"][1]["content"] == question
        reply = json.loads(body["reply"])
        assert set(reply) == {"calls"}, "the reply is the plan and nothing else"
        raw = path.read_text(encoding="utf-8").lower()
        for banned in ("thought_signature", "authorization", "bearer", "api_key", "x-goog", "sk-"):
            assert banned not in raw, banned
        plan = make_plan(gateway, question)
        assert plan is not None and plan.calls[0][0] == EXPECTED_FIRST_TOOL[question], question

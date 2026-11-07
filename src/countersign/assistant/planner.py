"""The planner call: question in, validated plan out. The model never sees data or tool results.

One gateway call (`task` assistant_plan) with the fixed system prompt (instructions and catalog) and the
cleaned question. The gateway validates the structure against the plan schema and retries once; this
module then validates each call against its tool's schema. Any failure maps to a typed outcome, never to a
made-up plan. In replay mode a missing cassette raises `LlmReplayMissingError`, which the caller turns into
the fixed "replays recorded questions" message (docs/PROTOCOL.md Decision 127).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from countersign.assistant.catalog import (
    clean_question,
    plan_schema,
    system_prompt,
    validate_call,
)
from countersign.llm import LlmGateway, LlmRequest

TASK = "assistant_plan"


@dataclass(frozen=True)
class Plan:
    calls: tuple[tuple[str, dict[str, Any]], ...]


def plan_request(question: str) -> LlmRequest:
    return LlmRequest(
        task=TASK, system=system_prompt(), user=clean_question(question), schema=plan_schema(),
        temperature=0.0, max_output_chars=2000, timeout_s=30.0,
    )  # fmt: skip


def make_plan(gateway: LlmGateway, question: str) -> Plan | None:
    """The validated plan, or None if the model proposed nothing usable (unknown tool, bad arguments).

    Raises the gateway's typed errors (`LlmReplayMissingError`, `LlmSchemaError`, ...) unchanged.
    """
    result = gateway.complete(plan_request(question))
    raw = result.data.get("calls") if isinstance(result.data, dict) else None
    if not isinstance(raw, list) or not raw:
        return None
    calls: list[tuple[str, dict[str, Any]]] = []
    for item in raw:
        checked = validate_call(item)
        if checked is None:
            return None
        calls.append(checked)
    return Plan(tuple(calls))

"""Ask Countersign: plan with the model, answer with deterministic code (docs/PROTOCOL.md Decisions 125 to 129).

    question -> planner (model, sees only the question and the catalog) -> validated plan
             -> tools (pure, read only) -> fixed-template lines with citations
             -> grounding check (a line with an unmatched numeral is replaced) -> answer

The model's output is data that selects among read-only lookups; no text it writes reaches an answer. An
unknown tool, bad arguments, an empty plan or a schema failure yields the fixed "I can only answer" message.
A missing cassette in replay mode yields the fixed "replays recorded questions" message; a plan is never
invented. Nothing here writes anything or reaches PayPal, a secret or an authorization code path.
"""

from __future__ import annotations

from countersign.assistant.catalog import clean_question
from countersign.assistant.data import DataSource
from countersign.assistant.grounding import ground_answer
from countersign.assistant.model import (
    REPLAY_ONLY,
    UNAVAILABLE,
    UNSUPPORTED,
    Answer,
    Line,
    ToolResult,
)
from countersign.assistant.planner import make_plan
from countersign.assistant.suggestions import SUGGESTIONS
from countersign.assistant.tools import BY_NAME
from countersign.llm import (
    LlmBudgetExceededError,
    LlmError,
    LlmGateway,
    LlmRateLimitedError,
    LlmReplayMissingError,
    LlmSchemaError,
)


class Assistant:
    def __init__(self, gateway: LlmGateway, source: DataSource) -> None:
        self._gateway = gateway
        self._source = source

    @property
    def mode(self) -> str:
        return self._gateway.config.mode

    @staticmethod
    def suggestions() -> list[dict[str, str]]:
        return [{"label": label, "question": question} for label, question in SUGGESTIONS]

    def ask(self, question: str) -> Answer:
        question = clean_question(question)
        if not question:
            return _message("unsupported", UNSUPPORTED)
        try:
            plan = make_plan(self._gateway, question)
        except LlmReplayMissingError:
            return _message("replay_only", REPLAY_ONLY)
        except LlmSchemaError:
            return _message("unsupported", UNSUPPORTED)
        except (LlmBudgetExceededError, LlmRateLimitedError):
            return _message(
                "unavailable", "The assistant has reached its call limit; try again later."
            )
        except LlmError:
            return _message("unavailable", UNAVAILABLE)
        if plan is None:
            return _message("unsupported", UNSUPPORTED)
        results: list[ToolResult] = []
        for name, args in plan.calls:
            try:
                results.append(BY_NAME[name].run(self._source, args))
            except Exception:  # noqa: BLE001 - a tool failure is a fixed message, never a guess
                return _message("unavailable", UNAVAILABLE)
        lines = tuple(line for result in results for line in result.lines)
        calls = tuple({"tool": n, "args": a} for n, a in plan.calls)
        answer = Answer("answered", lines, calls)
        return ground_answer(answer, results)


def _message(status: str, text: str) -> Answer:
    return Answer(status, (Line(text),))

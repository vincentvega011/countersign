"""The assistant's value types. Everything here is plain data built by deterministic code."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CITE_KINDS = ("order", "evidence_step", "eval_case", "log", "mandate", "code")


@dataclass(frozen=True)
class Cite:
    """Where a number or identifier in an answer came from: a row, a log entry, a bundle step, a case."""

    kind: str
    id: str
    label: str
    step: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in CITE_KINDS:
            raise ValueError("unknown citation kind")

    def to_dict(self) -> dict[str, str | None]:
        return {"kind": self.kind, "id": self.id, "label": self.label, "step": self.step}


@dataclass(frozen=True)
class Line:
    text: str
    cites: tuple[Cite, ...] = ()


@dataclass(frozen=True)
class ToolResult:
    """What a tool read. `data` holds every number the lines may state; the grounding check reads it."""

    tool: str
    args: dict[str, Any]
    data: dict[str, Any]
    lines: tuple[Line, ...] = ()


@dataclass(frozen=True)
class Answer:
    status: str  # answered | unsupported | replay_only | unavailable
    lines: tuple[Line, ...]
    calls: tuple[dict[str, Any], ...] = ()
    replaced: int = 0  # lines swapped for the fixed "cannot verify" sentence
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return "\n".join(line.text for line in self.lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "text": self.text,
            "lines": [
                {"text": line.text, "cites": [c.to_dict() for c in line.cites]}
                for line in self.lines
            ],
            "calls": list(self.calls),
            "replaced": self.replaced,
        }


UNSUPPORTED = "I can only answer questions about orders, protection activity, evidence and evaluation results."
UNVERIFIED = "I cannot verify that figure from the data."
REPLAY_ONLY = "This demo replays recorded questions; pick a suggestion."
UNAVAILABLE = "The assistant is not available right now."

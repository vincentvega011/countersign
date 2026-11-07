"""Ask Countersign: a read-only assistant whose model only plans a lookup (docs/PROTOCOL.md Decisions 125 to 129).

This package imports no authorization module and none imports it (`tests/unit/test_llm_boundary.py`).
"""

from countersign.assistant.data import DataSource
from countersign.assistant.grounding import ground, ground_answer, line_is_grounded
from countersign.assistant.model import Answer, Cite, Line, ToolResult
from countersign.assistant.service import Assistant

__all__ = [
    "Answer", "Assistant", "Cite", "DataSource", "Line", "ToolResult", "ground", "ground_answer",
    "line_is_grounded",
]  # fmt: skip

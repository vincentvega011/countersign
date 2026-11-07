"""The grounding check: a pure function over text and tool results (docs/PROTOCOL.md Decision 128).

Every numeral in a line of the final answer must equal a number present in the tool results that line
cites. A line with a numeral that no cited result holds is replaced, whole, by a fixed sentence. Numerals
inside identifiers (`chk_ab12`, `cus_seed03`, `G-AMOUNT`, `SIMCAPTURE3`) are not claims and are skipped;
formatting does not matter (`1,234` equals `1234`, `$54.00` equals 5400 minor units). Words ("five") are not
numerals and are not checked, so the templates avoid number words for data values. No model, no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from typing import Any

from countersign.assistant.model import UNVERIFIED, Answer, Line, ToolResult

# A numeral not glued to letters, digits, underscores or a dot before it, nor a word and hyphen before it
# ("evt-12"), nor letters after it ("3x"). A leading minus is not part of it, so "-5" is checked as 5.
_NUMERAL = re.compile(r"(?<![\w.])(?<!\w-)\$?\d[\d,]*(?:\.\d+)?(?![\w])")


def numerals(text: str) -> list[Decimal]:
    out: list[Decimal] = []
    for match in _NUMERAL.finditer(text):
        raw = match.group(0).lstrip("$").replace(",", "")
        try:
            out.append(Decimal(raw))
        except InvalidOperation:
            continue
    return out


def _walk(value: Any, key: str, found: set[Decimal]) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        found.add(Decimal(value))
        if key.endswith("_minor"):
            found.add(Decimal(value) / 100)
    elif isinstance(value, float):
        found.add(Decimal(str(value)))
    elif isinstance(value, str):
        found.update(numerals(value))
    elif isinstance(value, dict):
        for k, v in value.items():
            _walk(v, str(k), found)
    elif isinstance(value, list | tuple):
        for v in value:
            _walk(v, key, found)


def allowed_numbers(results: Iterable[ToolResult]) -> set[Decimal]:
    """Every number a set of tool results holds (money fields count in minor units and in major units)."""
    found: set[Decimal] = set()
    for result in results:
        _walk(result.data, "", found)
    return found


def line_is_grounded(text: str, allowed: set[Decimal]) -> bool:
    return all(any(n == a for a in allowed) for n in numerals(text))


def ground(lines: Iterable[Line], results: Iterable[ToolResult]) -> tuple[tuple[Line, ...], int]:
    """The lines with any ungrounded line replaced by the fixed sentence, and how many were replaced."""
    allowed = allowed_numbers(results)
    out: list[Line] = []
    replaced = 0
    for line in lines:
        if line_is_grounded(line.text, allowed):
            out.append(line)
        else:
            out.append(Line(UNVERIFIED))
            replaced += 1
    return tuple(out), replaced


def ground_answer(answer: Answer, results: Iterable[ToolResult]) -> Answer:
    lines, replaced = ground(answer.lines, results)
    return Answer(answer.status, lines, answer.calls, replaced, answer.extra)

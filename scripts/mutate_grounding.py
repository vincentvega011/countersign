"""Mutation sweep of the grounding check (src/countersign/assistant/grounding.py), Decision 128.

Each mutant changes one expression; the assistant's grounding and tool tests must fail on it. The file is
restored afterwards, even on error. Prints a table and exits 1 if any mutant survives.

    uv run python scripts/mutate_grounding.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "src" / "countersign" / "assistant" / "grounding.py"
TESTS = ["tests/unit/test_assistant_grounding.py", "tests/unit/test_assistant_tools.py"]

MUTANTS = [
    ("no leading word/dot guard", r"(?<![\w.])(?<!\w-)", r"(?<!\w-)"),
    ("no word-hyphen guard", r"(?<!\w-)\$?", r"\$?"),
    ("no trailing word guard", r"(?![\w])", r""),
    ("commas kept", '.replace(",", "")', '.replace(",", ",")'),
    ("dollar sign kept", '.lstrip("$")', ""),
    ("no minor-unit conversion", 'key.endswith("_minor")', "False"),
    ("wrong minor divisor", "Decimal(value) / 100", "Decimal(value) / 10"),
    ("floats ignored", "elif isinstance(value, float):", "elif False:"),
    ("strings ignored", "found.update(numerals(value))", "pass"),
    ("bool counted as number", "if isinstance(value, bool) or value is None:", "if value is None:"),
    ("lists ignored", "elif isinstance(value, list | tuple):", "elif False:"),
    ("any instead of all", "return all(any(n == a for a in allowed) for n in numerals(text))",
     "return any(any(n == a for a in allowed) for n in numerals(text))"),
    ("inequality match", "any(n == a for a in allowed)", "any(n <= a for a in allowed)"),
    ("ungrounded line kept", "out.append(Line(UNVERIFIED))", "out.append(line)"),
    ("replacement not counted", "replaced += 1", "replaced += 0"),
    ("empty line passes", "return all(", "return True or all("),
]  # fmt: skip


def run_tests() -> bool:
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *TESTS],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )  # fmt: skip
    return result.returncode == 0


def main() -> int:
    original = TARGET.read_text(encoding="utf-8")
    survivors = 0
    try:
        assert run_tests(), "the unmutated tests must pass first"
        print(f"{'mutant':34} result")
        for name, old, new in MUTANTS:
            if old not in original:
                print(f"{name:34} NOT APPLICABLE (pattern missing)")
                survivors += 1
                continue
            TARGET.write_text(original.replace(old, new, 1), encoding="utf-8")
            killed = not run_tests()
            survivors += 0 if killed else 1
            print(f"{name:34} {'killed' if killed else 'SURVIVED'}")
    finally:
        TARGET.write_text(original, encoding="utf-8")
    print(f"{len(MUTANTS) - survivors} of {len(MUTANTS)} killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())

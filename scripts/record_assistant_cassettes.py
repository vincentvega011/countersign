"""Record the planner calls of Ask Countersign for the suggested questions, with the LIVE model gateway.

Only the planner is recorded: one call per suggested question (src/countersign/assistant/suggestions.py).
The model sees the question, the tool catalog and fixed instructions, never any data, so this needs no
database and no PayPal. Cassettes are written by the gateway's own record mode, through its scrubber, to
eval/cassettes/llm/<key>.json, and the model id used is written to eval/cassettes/assistant.json (the
cassette key includes the model, so replay must use the same id).

The model settings come from YOUR SHELL only, never from a file:

    export LLM_PROVIDER=... LLM_BASE_URL=... LLM_MODEL=... LLM_API_KEY=...
    uv run python scripts/record_assistant_cassettes.py

The script sets LLM_MODE=record for itself. It prints, per question, the plan the model proposed and
whether it is valid; it exits 1 if any plan is unusable (the cassettes already written stay, but the model
index is not written, so nothing replays a broken plan). Re-record after changing the catalog or a question.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from countersign.assistant.catalog import catalog_json
from countersign.assistant.planner import make_plan
from countersign.assistant.suggestions import SUGGESTIONS
from countersign.llm import LlmConfig, LlmError, build_gateway

INDEX = ROOT / "eval" / "cassettes" / "assistant.json"
NEEDED = ("LLM_PROVIDER", "LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")


def main() -> int:
    missing = [name for name in NEEDED if not os.environ.get(name)]
    if missing:
        print("missing in your shell: " + ", ".join(missing))
        return 2
    try:
        config = LlmConfig.from_env({**os.environ, "LLM_MODE": "record"})
        gateway = build_gateway(config)
    except LlmError as error:
        print(f"configuration refused: {error}")
        return 2
    print(f"provider {config.provider}, model {config.model}, {len(SUGGESTIONS)} questions")
    bad = 0
    for label, question in SUGGESTIONS:
        try:
            plan = make_plan(gateway, question)
        except LlmError as error:
            print(f"  FAIL  {label}: {type(error).__name__}")
            bad += 1
            continue
        if plan is None:
            print(f"  FAIL  {label}: no usable plan (unknown tool, bad arguments or empty)")
            bad += 1
            continue
        print(
            f"  ok    {label}: "
            + "; ".join(f"{t} {json.dumps(a, sort_keys=True)}" for t, a in plan.calls)
        )
    print(f"model calls used: {gateway.calls_used}")
    if bad:
        print(f"{bad} question(s) failed; the model index was NOT written")
        return 1
    INDEX.write_text(
        json.dumps(
            {
                "model": config.model,
                "catalog_sha256": hashlib.sha256(catalog_json().encode()).hexdigest(),
                "questions": [q for _, q in SUGGESTIONS],
            },
            indent=2, sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )  # fmt: skip
    print(f"wrote {INDEX.relative_to(ROOT)}; now grep the new cassettes and run the replay tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

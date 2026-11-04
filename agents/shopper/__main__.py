"""`python -m agents.shopper "goal"`: run the shopping agent against a running service.

Environment: `COUNTERSIGN_URL` (default http://localhost:8000) and the model settings of
`countersign.llm` (`LLM_MODE`, `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`; replay by
default). Events go to stdout as JSON lines, then a readable summary. The agent key lives in memory.
"""

from __future__ import annotations

import json
import os
import sys

from agents.shopper.agent import ShopperError, run_shopper, summary
from countersign.llm import LlmError, build_gateway


def _line(event: dict[str, object]) -> None:
    print(json.dumps(event, sort_keys=True), flush=True)


def _approve(url: str) -> None:
    print(f"Open this on the phone to approve: {url}", file=sys.stderr, flush=True)


def _payer(url: str) -> None:
    print(f"Approve the payment as the sandbox buyer: {url}", file=sys.stderr, flush=True)
    input("Press Enter once the payer has approved: ")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print('usage: python -m agents.shopper "goal"', file=sys.stderr)
        return 2
    try:
        result = run_shopper(
            argv[1],
            base_url=os.environ.get("COUNTERSIGN_URL", "http://localhost:8000"),
            gateway=build_gateway(),
            on_approve_url=_approve,
            on_payer_approval=_payer,
            emit=_line,
        )
    except (ShopperError, LlmError) as error:
        _line({"event": "error", "code": getattr(error, "code", type(error).__name__)})
        print(f"Stopped: {error}", file=sys.stderr)
        return 1
    _line({"event": "result", **json.loads(result.to_json())})
    print(summary(result), file=sys.stderr)
    return 0 if result.outcome == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

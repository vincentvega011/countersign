"""`python -m agents.adversary --list`: the scripted attacks this agent can run.

Running one needs a `Counterparties` provider (what the customer signed, the payer's approval), which
only the evaluation harness has: `uv run python -m eval.run --suite adversary --case <id>`.
"""

from __future__ import annotations

import sys

from agents.adversary.scripts import SCRIPTS


def main(argv: list[str]) -> int:
    if argv[1:] != ["--list"]:
        print("usage: python -m agents.adversary --list", file=sys.stderr)
        return 2
    for name in SCRIPTS:
        print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

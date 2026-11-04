"""`python -m countersign_verify bundle.json [--merchant-key K.json --platform-key P.json] [--json]`.

Exit status: 0 every step passed, 1 a step failed, 2 usage or an unreadable file. Without pinned keys the
`trusted_keys` step fails on purpose: a bundle can prove it is self-consistent, not who the merchant is.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from countersign_verify import verify_text
from countersign_verify.crypto import Invalid, loads


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="countersign_verify")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--merchant-key", type=Path, help="the merchant's public JWK, to pin")
    parser.add_argument(
        "--platform-key", type=Path, help="the platform provider's public JWK, to pin"
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    pinned = {}
    try:
        text = args.bundle.read_bytes()
        for name, path in (("merchant", args.merchant_key), ("platform", args.platform_key)):
            if path is not None:
                pinned[name] = loads(path.read_bytes())
    except (OSError, Invalid) as error:
        print(f"cannot read input: {error}", file=sys.stderr)
        return 2
    results = verify_text(text, pinned or None)
    if args.json:
        print(json.dumps([r.__dict__ for r in results], indent=1))
    else:
        for r in results:
            print(f"{'PASS' if r.ok else 'FAIL'}  {r.name}: {r.message}")
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

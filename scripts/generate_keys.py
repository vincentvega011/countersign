"""Create the merchant ES256 signing key if it does not exist. Prints only the public `kid`."""

from __future__ import annotations

import os
import sys

from countersign.merchant.keys import MerchantKeyError, load_merchant_key, write_key_file

DEFAULT_PATH = "secrets/merchant_es256.jwk.json"


def main() -> int:
    path = os.environ.get("MERCHANT_KEY_PATH", DEFAULT_PATH)
    if os.path.exists(path):
        try:
            key = load_merchant_key(path)
        except MerchantKeyError as exc:
            print(f"keys: existing file is invalid: {exc}", file=sys.stderr)
            return 1
        print(f"keys: {path} already exists and is valid (kid {key.kid})")
        return 0
    kid = write_key_file(path)
    print(f"keys: wrote {path} (kid {kid})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

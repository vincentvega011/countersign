"""The single JCS (RFC 8785) function. Everything Countersign signs or hashes as JSON uses it.

Security reasoning. A signature or hash is only meaningful if signer and verifier derive the same
bytes from the same value. Having exactly one canonicalizer, pinned in `pyproject.toml`, removes
the chance of two code paths disagreeing about key order, number spelling or escapes. No other
module may call `rfc8785` or serialize JSON for signing or hashing; they call `canonicalize`.

What the pinned library rejects, and so this function does: NaN and Infinity, integers outside
+/-(2^53 - 1), lone surrogates, non-string keys and values that are not JSON types. A lone
surrogate raises two different exception types in the library (CanonicalizationError as a value,
UnicodeEncodeError as a key), so both are caught here and surfaced as one `JcsError`. Deeply nested
values that exhaust the stack fail closed the same way.

Input should come from `loads_strict`, which also rejects duplicate keys, excess decimal precision
and floats beyond +/-(2^53 - 1); those are properties of parsing text, which JCS cannot see. This
function does not re-check them, so it must not be fed unparsed attacker-shaped Python values.
"""

from __future__ import annotations

from typing import Any

import rfc8785


class JcsError(ValueError):
    """The value has no canonical form. Fail closed: callers must not sign or hash it."""

    code = "jcs_invalid"


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of a parsed JSON value."""
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise JcsError(str(exc)) from exc
    except UnicodeEncodeError as exc:
        raise JcsError("value contains a lone surrogate") from exc
    except RecursionError as exc:
        raise JcsError("value is nested too deeply") from exc

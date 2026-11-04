"""Offline verifier for Countersign evidence bundles. Imports nothing from the service (Decision 105)."""

from __future__ import annotations

from typing import Any

from countersign_verify.crypto import Invalid, loads
from countersign_verify.steps import STEPS, Bundle, Result

__all__ = ["Invalid", "Result", "verify", "verify_text"]


def verify(raw: Any, pinned: dict[str, Any] | None = None) -> list[Result]:
    """Run every step. A bundle that cannot even be read fails `bundle_structure` and nothing else runs."""
    try:
        bundle = Bundle(raw, pinned)
    except Invalid as error:
        return [Result("bundle_structure", False, str(error))]
    results: list[Result] = []
    for name, step in STEPS:
        try:
            results.append(Result(name, True, step(bundle)))
        except (Invalid, KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
            results.append(Result(name, False, str(error) or f"malformed ({type(error).__name__})"))
    return results


def verify_text(text: str | bytes, pinned: dict[str, Any] | None = None) -> list[Result]:
    try:
        return verify(loads(text), pinned)
    except Invalid as error:
        return [Result("bundle_structure", False, str(error))]

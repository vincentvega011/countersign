"""Offline verifier for Countersign evidence bundles. Imports nothing from the service (Decision 105)."""

from __future__ import annotations

from typing import Any

from countersign_verify.crypto import Invalid, loads
from countersign_verify.steps import STEPS, Bundle, Result

__all__ = ["Invalid", "Result", "verify", "verify_text"]


def _failure(name: str, error: Exception) -> Result:
    if isinstance(error, Invalid):
        return Result(name, False, str(error), error.code)
    return Result(name, False, f"malformed ({type(error).__name__})", "malformed")


def verify(raw: Any, pinned: dict[str, Any] | None = None) -> list[Result]:
    """Run every step. A bundle that cannot even be read fails `bundle_structure` and nothing else runs.

    Any error inside a step fails that step (Decision 106): an `Invalid` with its stable code, anything
    else with the code `malformed`. Nothing a bundle holds can stop the other steps from running."""
    try:
        bundle = Bundle(raw, pinned)
    except Exception as error:  # noqa: BLE001
        return [_failure("bundle_structure", error)]
    results: list[Result] = []
    for name, step in STEPS:
        try:
            results.append(Result(name, True, step(bundle)))
        except Exception as error:  # noqa: BLE001
            results.append(_failure(name, error))
    return results


def verify_text(text: str | bytes, pinned: dict[str, Any] | None = None) -> list[Result]:
    try:
        raw = loads(text)
    except Exception as error:  # noqa: BLE001
        return [_failure("bundle_structure", error)]
    return verify(raw, pinned)

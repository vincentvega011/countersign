"""Deliberately weakened implementations, for the evaluation only (docs/PROTOCOL.md Decision 59).

Everything here exists to show what the protections of `full` mode prevent. The package is imported
only by `countersign.composition`, and only when `CS_MODE=baseline` or an ablation asks for a piece of
it (enforced by `tests/unit/test_degraded_import_guard.py`). It is the one place outside `gate/` that
may build a capture approval and capture, and it says so in the capture surface test.
"""

"""The coordinator's customer check fails closed (Decision 111, INV-10)."""

from __future__ import annotations

from typing import Any

from countersign.completion import CompleteCoordinator
from countersign.lock import Principal


class _Raises:
    def admits(self, *_a: Any) -> bool:
        raise RuntimeError("store down")


class _Says:
    def __init__(self, answer: bool) -> None:
        self.answer = answer
        self.seen: list[tuple[Any, ...]] = []

    def admits(self, *args: Any) -> bool:
        self.seen.append(args)
        return self.answer


def _coordinator(binding: Any) -> CompleteCoordinator:
    return CompleteCoordinator(None, None, None, binding=binding)  # type: ignore[arg-type]


def test_an_error_in_the_check_refuses() -> None:
    assert _coordinator(_Raises())._customer_admitted("chk_x", Principal("cus_a", "tp")) is False


def test_the_check_passes_the_chain_customer_and_agent() -> None:
    says = _Says(False)
    assert _coordinator(says)._customer_admitted("chk_x", Principal("cus_a", "tp")) is False
    assert says.seen == [("chk_x", "cus_a", "tp")]
    assert _coordinator(_Says(True))._customer_admitted("chk_x", Principal("cus_a", None)) is True

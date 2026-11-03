"""An in-process provider for tests and the demo's offline paths. No network."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from countersign.llm.provider import ProviderCall, ProviderReply


class FakeProvider:
    """Replies from a script (a list consumed in order) or a function of the call."""

    def __init__(self, script: list[Any] | Callable[[ProviderCall], Any] | None = None) -> None:
        self._script = script if script is not None else []
        self.calls: list[ProviderCall] = []

    def generate(self, call: ProviderCall) -> ProviderReply:
        self.calls.append(call)
        item = self._script(call) if callable(self._script) else self._script.pop(0)
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, ProviderReply):
            return item
        return ProviderReply(item if isinstance(item, str) else _dump(item), 10, 5)


def _dump(value: Any) -> str:
    import json

    return json.dumps(value)

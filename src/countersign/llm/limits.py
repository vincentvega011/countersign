"""Client-side rate limit and per-run call budget, so a free tier is never hammered."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

from countersign.llm.errors import LlmBudgetExceededError, LlmRateLimitedError


class RateLimiter:
    """At most `per_minute` calls in any 60 second window. `acquire` waits, or refuses past a deadline."""

    def __init__(
        self,
        per_minute: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if per_minute < 1:
            raise ValueError("per_minute is at least 1")
        self._per_minute = per_minute
        self._clock = clock
        self._sleep = sleep
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self, deadline: float) -> None:
        while True:
            with self._lock:
                now = self._clock()
                while self._stamps and now - self._stamps[0] >= 60.0:
                    self._stamps.popleft()
                if len(self._stamps) < self._per_minute:
                    self._stamps.append(now)
                    return
                wait = 60.0 - (now - self._stamps[0])
            if now + wait > deadline:
                raise LlmRateLimitedError("the client-side rate limit would exceed the deadline")
            self._sleep(wait)


class CallBudget:
    """A cap on provider calls for one run. Replayed calls are free; every live call and retry counts."""

    def __init__(self, max_calls: int) -> None:
        if max_calls < 1:
            raise ValueError("max_calls is at least 1")
        self._max = max_calls
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        return self._used

    def spend(self) -> None:
        with self._lock:
            if self._used >= self._max:
                raise LlmBudgetExceededError(
                    f"the run's budget of {self._max} model calls is spent"
                )
            self._used += 1

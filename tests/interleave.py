"""Deterministic control of concurrent requests at the points where they touch PayPal.

Two tools, both outside the code under test:

- `PausingTransport` wraps the PayPal simulator's transport and runs a callback before each PayPal
  request, in the calling thread and outside the simulator's lock, so a test can hold one request at an
  exact call (for example "the first `get_order`") while another runs.
- `TokenScheduler` lets exactly one of N request threads run at a time and hands the token on at every
  PayPal call, to the thread a list of picks names. Between PayPal calls a thread runs alone, so a
  schedule is a complete, repeatable interleaving at PayPal-call granularity; Hypothesis draws the
  picks. No transaction is held across a PayPal call (docs/PROTOCOL.md Decision 38), so a thread
  never waits on a database lock held by a thread without the token.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from typing import Any

import httpx

from tests.paypal_sim import PayPalSim


class PausingTransport(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport, before: Callable[[str], None]) -> None:
        self._inner = inner
        self._before = before

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != "/v1/oauth2/token":
            self._before(PayPalSim._op(request.method, request.url.path))
        return self._inner.handle_request(request)


class Rendezvous:
    """Hold the calling thread until the test releases it; the test can wait for the arrival."""

    def __init__(self) -> None:
        self.arrived = threading.Event()
        self.released = threading.Event()

    def hold(self, timeout: float = 20.0) -> None:
        self.arrived.set()
        if not self.released.wait(timeout):
            raise TimeoutError("a held request was never released")


class TokenScheduler:
    def __init__(self, count: int, picks: Sequence[int], timeout: float = 30.0) -> None:
        self._cond = threading.Condition()
        self._alive = list(range(count))
        self._picks = list(picks) or [0]
        self._at = 0
        self._holder = 0
        self._timeout = timeout
        self._local = threading.local()

    def _next(self) -> int:
        choice = self._picks[self._at % len(self._picks)]
        self._at += 1
        return self._alive[choice % len(self._alive)]

    def _wait_for_token(self, me: int) -> None:
        while self._holder != me:
            if not self._cond.wait(self._timeout):
                raise TimeoutError("the schedule deadlocked")

    def before_paypal(self, _op: str) -> None:
        me = getattr(self._local, "me", None)
        if me is None:
            return
        with self._cond:
            self._holder = self._next()
            self._cond.notify_all()
            self._wait_for_token(me)

    def run(self, jobs: Sequence[Callable[[], Any]]) -> list[Any]:
        results: list[Any] = [None] * len(jobs)
        errors: list[BaseException | None] = [None] * len(jobs)

        def body(i: int) -> None:
            self._local.me = i
            with self._cond:
                self._wait_for_token(i)
            try:
                results[i] = jobs[i]()
            except BaseException as exc:  # noqa: BLE001 - reported to the test
                errors[i] = exc
            finally:
                with self._cond:
                    self._alive.remove(i)
                    if self._alive:
                        self._holder = self._next()
                    self._cond.notify_all()

        threads = [threading.Thread(target=body, args=(i,)) for i in range(len(jobs))]
        with self._cond:
            self._holder = 0
        for t in threads:
            t.start()
        for t in threads:
            t.join(self._timeout * 2)
        for error in errors:
            if error is not None:
                raise error
        return results

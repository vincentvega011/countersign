"""A small in-process rate limit on the public mutating routes (P5a, Decision 138).

Security reasoning. A public demo URL gets poked. This limit is not a security boundary for money (the
gate, the lock and the mandate checks decide that, and none of them depends on it); it keeps one client
from filling the decision log, the database or the PayPal sandbox quota, and from running the
assistant in a loop. It has no fail-open path: a bug here answers 500 through the
normal handler, because the rule table is plain data and the counter is a dict of deques under one lock.

- **Per client address, per group.** A sliding window: a request is refused when the group already has
  `limit` requests from that address in the last `window_s` seconds. Refused requests are not counted,
  so a client that stops recovers after one window.
- **429 with `Retry-After`** (whole seconds, at least 1) and the body `{"code": "rate_limited"}`.
- **The address.** The socket peer by default. Behind Render's proxy (`TRUST_PROXY=1`) it is the
  rightmost `X-Forwarded-For` entry, which is the one the platform proxy appended; entries to its left
  are client supplied and never used.
- **One process.** Counters live in memory, so they reset on restart and are per instance. The free
  tier runs one instance (L72).
- **Bounded memory.** Expired entries are dropped on use, and the table is swept when it passes
  `MAX_KEYS`; if it is still over the cap after the sweep, the oldest keys are dropped.
"""

from __future__ import annotations

import math
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

MAX_KEYS = 20_000


@dataclass(frozen=True)
class Rule:
    group: str
    methods: frozenset[str]
    path: re.Pattern[str]
    limit: int
    window_s: float = 60.0


def _rule(group: str, methods: str, pattern: str, limit: int) -> Rule:
    return Rule(group, frozenset(methods.split(",")), re.compile(pattern), limit)


# Per client address, per minute. Chosen to leave a person or the sample agent room (one purchase is a
# handful of calls) and to stop loops.
RULES: tuple[Rule, ...] = (
    _rule("enrolment", "POST", r"/trusted-surface/keys(?:/challenge)?", 10),
    _rule("consent", "POST", r"/trusted-surface/(?:consent|proposals|proposals/[^/]+/mandates|"
          r"purchases/(?:offer|consent)|activity/(?:session|revoke)|keys/revoke)", 20),
    _rule("checkout_create", "POST", r"/ucp/v1/checkout-sessions|/checkout_sessions", 30),
    _rule("checkout_update", "PUT,POST", r"/ucp/v1/checkout-sessions/[^/]+|"
          r"/checkout_sessions/[^/]+|/ucp/v1/checkout-sessions/[^/]+/cancel|"
          r"/checkout_sessions/[^/]+/cancel|/agentic_commerce/delegate_payment", 60),
    _rule("checkout_complete", "POST", r"/ucp/v1/checkout-sessions/[^/]+/complete|"
          r"/checkout_sessions/[^/]+/complete", 20),
    _rule("assistant", "GET", r"/dashboard/api/v1/assistant/ask", 12),
    _rule("evidence", "GET", r"/evidence/[^/]+", 60),
    _rule("webhook", "POST", r"/webhooks/paypal", 120),
    _rule("attack_run", "POST", r"/dashboard/api/v1/attack-runs", 6),
)  # fmt: skip


class RateLimiter:
    def __init__(
        self,
        rules: tuple[Rule, ...] = RULES,
        *,
        trust_proxy: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rules = rules
        self.trust_proxy = trust_proxy
        self._clock = clock
        self._hits: dict[tuple[str, str], deque[float]] = {}
        self._lock = threading.Lock()

    def rule_for(self, method: str, path: str) -> Rule | None:
        for rule in self.rules:
            if method in rule.methods and rule.path.fullmatch(path):
                return rule
        return None

    def client(self, request: Request) -> str:
        if self.trust_proxy:
            forwarded = request.headers.get("x-forwarded-for", "")
            last = forwarded.rsplit(",", 1)[-1].strip()
            if last:
                return last[:64]
        return request.client.host if request.client else "unknown"

    def check(self, rule: Rule, client: str) -> int:
        """0 when the request may proceed (and is counted), else the seconds to wait."""
        now = self._clock()
        key = (rule.group, client)
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= rule.window_s:
                hits.popleft()
            if len(hits) >= rule.limit:
                return max(1, math.ceil(rule.window_s - (now - hits[0])))
            hits.append(now)
            if len(self._hits) > MAX_KEYS:
                self._sweep(now)
            return 0

    def _sweep(self, now: float) -> None:
        window = max(r.window_s for r in self.rules)
        for key in [k for k, h in self._hits.items() if not h or now - h[-1] >= window]:
            del self._hits[key]
        extra = len(self._hits) - MAX_KEYS
        if extra > 0:
            oldest = sorted(self._hits, key=lambda k: self._hits[k][-1])[:extra]
            for key in oldest:
                del self._hits[key]


def install(app: FastAPI, limiter: RateLimiter) -> None:
    app.state.rate_limiter = limiter

    @app.middleware("http")
    async def limit(request: Request, call_next: Callable[[Request], Any]) -> Response:
        rule = limiter.rule_for(request.method, request.url.path)
        if rule is not None:
            wait = limiter.check(rule, limiter.client(request))
            if wait:
                return JSONResponse(
                    {"code": "rate_limited", "group": rule.group},
                    status_code=429,
                    headers={"Retry-After": str(wait), "Cache-Control": "no-store"},
                )
        response: Response = await call_next(request)
        return response

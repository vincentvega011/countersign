"""The attack case format and the context a case runs in.

A case is data plus a small function. The data says what the attack is, who the attacker is, what
counts as success and what each mode is expected to do. The function performs the steps against a
whole app built by the composition root (`tests.mode_support.make_world`) over the PayPal
simulator, and registers what the customer actually signed so the judge (`eval.judge`) can compare
it with what PayPal ended up holding. Nothing in a case decides whether it succeeded: the judge
reads PayPal state and the decision log (never a model, never a response body).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sqlalchemy import Engine

from countersign.canonical import sd_hash
from tests.mode_support import (
    Pair,
    World,
    codes,
    mandate_pair,
    new_checkout,
    purchase,
    total_of,
)

__all__ = ["BLOCKED", "SUCCESS", "Actor", "AttackCase", "Ctx", "Expect", "Pair"]

SUCCESS = "success"
BLOCKED = "blocked"


class Actor(StrEnum):
    MALICIOUS_AGENT = "malicious agent"
    COMPROMISED_MERCHANT_COMPONENT = "compromised merchant-side component"
    NETWORK_ATTACKER = "network attacker"


@dataclass(frozen=True)
class Expect:
    outcome: str  # SUCCESS or BLOCKED
    reason: str | None = None  # the reason code of the decisive response, when it is stable
    note: str = ""  # why, in one sentence (defense in depth when baseline also blocks)


@dataclass
class Ctx:
    world: World
    admin: Engine
    mode: str
    signed: dict[str, int] = field(default_factory=dict)  # checkout id -> signed total, minor units
    signed_items: dict[str, tuple[str, ...]] = field(default_factory=dict)
    keys: dict[str, set[str]] = field(default_factory=dict)  # checkout id -> single-use keys
    budgets: dict[str, int] = field(default_factory=dict)  # single-use key -> budget, minor units
    invalid: dict[str, str] = field(default_factory=dict)  # checkout id -> why its mandate is void
    violations: list[str] = field(default_factory=list)
    side_effects: set[str] = field(default_factory=set)
    reason: str | None = None

    # ------------------------------------------------------------ what the customer signed

    def checkout(self, **headers: str) -> dict[str, Any]:
        return new_checkout(self.world, **headers)

    def mandates(self, body: dict[str, Any], **kw: Any) -> Pair:
        return mandate_pair(self.world, body, **kw)

    def register(self, body: dict[str, Any], pair: Pair, *, budget: int | None = None) -> None:
        """Record that the customer signed `pair` for `body`: the total, the goods and the keys
        that may back one purchase only (the open mandate and the two closed nonces)."""
        cid = body["id"]
        open_key = "open:" + sd_hash(pair.open_checkout)
        self.signed[cid] = total_of(body)
        self.signed_items[cid] = tuple(line["item"]["title"] for line in body["line_items"])
        self.keys[cid] = {
            open_key,
            f"nonce-checkout:{pair.nonce_checkout}",
            f"nonce-payment:{pair.nonce_payment}",
        }
        if budget is not None:
            self.budgets[open_key] = budget

    def buy(self, body: dict[str, Any], pair: Pair, *, budget: int | None = None) -> Any:
        """Register what was signed, then complete (approving at PayPal when asked)."""
        self.register(body, pair, budget=budget)
        return self.note(purchase(self.world, body, pair))

    # ------------------------------------------------------------ observations

    def note(self, response: Any) -> Any:
        """Remember the reason code of a decisive response (reporting only; never the verdict)."""
        try:
            body = response.json()
        except ValueError:
            return response
        listed = codes(response) if isinstance(body, dict) else []
        code = body.get("code") if isinstance(body, dict) and "status" not in body else None
        self.reason = code or (listed[0] if listed else None) or f"http_{response.status_code}"
        return response

    @contextmanager
    def forbid_money_calls(self, label: str) -> Iterator[None]:
        """Any PayPal call that can move money during this block is itself a violation."""
        before = self.world.sim.money_calls()
        yield
        if self.world.sim.money_calls() > before:
            self.violations.append(f"money_call_during:{label}")


@dataclass(frozen=True)
class AttackCase:
    id: str
    category: str
    description: str
    actor: Actor
    steps: tuple[str, ...]
    success_condition: str
    expected: dict[str, Expect]  # keys "full" and "baseline"
    run: Callable[[Ctx], None]
    webhook_id: str | None = None  # set when the case needs the webhook route installed

    def __post_init__(self) -> None:
        if set(self.expected) != {"full", "baseline"}:
            raise ValueError(f"{self.id}: declare an expectation for full and baseline")
        for expect in self.expected.values():
            if expect.outcome not in (SUCCESS, BLOCKED):
                raise ValueError(f"{self.id}: outcome must be success or blocked")

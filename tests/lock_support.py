"""Shared setup for principal lock tests: a real lock on the real Postgres, real signed delegations."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Engine

from countersign.ablations import Ablations
from countersign.canonical.money import Money
from countersign.lock import LockRequest, Principal, PrincipalLock
from tests.mandate_issuer import NOW, Keys, issue, public_jwk

TOTAL = Money("USD", 8500)


def make_lock(
    engine: Engine, keys: Keys, *, ablations: Ablations | None = None, clock: float = float(NOW)
) -> PrincipalLock:
    return PrincipalLock(engine, platform_key=keys.issuer, clock=lambda: clock, ablations=ablations)


def delegation(keys: Keys, *, sub: str | None = "cust-1", agent: int = 0) -> str:
    """An open Checkout Mandate signed by the platform for one customer and one agent key."""

    def payload(p: dict[str, Any]) -> None:
        if sub is not None:
            p["sub"] = sub

    return issue(
        "checkout",
        keys=keys,
        cnf={"jwk": public_jwk(keys.agents[agent])},
        edit_open_payload=payload,
    ).open_token


def principal(keys: Keys, *, sub: str | None = "cust-1", agent: int = 0) -> Principal:
    return Principal(sub, keys.agents[agent].thumbprint())


def request(
    operation: str,
    who: Principal | None,
    *,
    negotiated: bool = False,
    mandate: bool = False,
    amount: Money | None = TOTAL,
    checkout_id: str = "chk_lock_test_000000000",
) -> LockRequest:
    return LockRequest(operation, checkout_id, who, negotiated, mandate, amount)  # type: ignore[arg-type]


def second_protocol_entry(lock: PrincipalLock, who: Principal | None, **kw: Any) -> bool:
    """A test-only entry point that stands for another protocol adapter (the real ACP adapter is exercised in tests/integration/test_acp.py).

    It builds its own `Principal` and calls the SAME shared function the UCP adapter calls. It holds
    no policy of its own, which is the point of the test.
    """
    return lock.decide(request("complete", who, **kw)).allowed

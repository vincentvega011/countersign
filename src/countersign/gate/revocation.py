"""Revoking an open mandate by identity, without a customer proof (an operator or test path).

The customer path (`trusted_surface.activity`) authorizes with a device key signature and then calls the
same `openmandates.revoke_in`, so both take the open mandate's row lock and answer the same codes.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import Engine

from countersign.openmandates import RevokeOutcome, revoke_in


def revoke_mandate(
    engine: Engine,
    payment_identity: str,
    checkout_identity: str,
    clock_us: Callable[[], int],
    currency: str = "USD",
) -> RevokeOutcome:
    with engine.begin() as conn:
        return revoke_in(
            conn, payment_identity=payment_identity, checkout_identity=checkout_identity,
            currency=currency, now_us=clock_us(),
        )  # fmt: skip


__all__ = ["revoke_mandate"]

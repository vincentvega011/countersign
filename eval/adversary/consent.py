"""The customer and the payer for an adversary run in the evaluation harness.

The adversary (`agents/adversary`) cannot sign for a customer or approve at PayPal. Here the customer is
the same issuer the attack cases use (`tests.mode_support.mandate_pair`) and the payer is the PayPal
simulator. `sign(authorized=True)` also records what the customer really signed with the judge's
context, so a capture outside it can be called unauthorized. The adversary never sees that record.
"""

from __future__ import annotations

from typing import Any

from agents.adversary.session import Signed
from eval.core import Ctx
from tests.lock_support import delegation
from tests.mode_support import Pair


def _pair(signed: Signed) -> Pair:
    return Pair(
        signed.cm, signed.pm, signed.open_cm, signed.open_pm, signed.nonce_cm, signed.nonce_pm
    )


class EvalCounterparties:
    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx

    def delegation(self) -> str:
        return delegation(self.ctx.world.keys)

    def sign(
        self,
        checkout: dict[str, Any],
        *,
        authorized: bool = True,
        budget: int | None = None,
        reuse: Signed | None = None,
        nonces: tuple[str, str] | None = None,
    ) -> Signed:
        options: dict[str, Any] = {}
        if budget is not None:
            options["budget"] = budget
        if reuse is not None:
            options["reuse"] = _pair(reuse)
        if nonces is not None:
            options["nonce_checkout"], options["nonce_payment"] = nonces
        pair = self.ctx.mandates(checkout, **options)
        if authorized:
            self.ctx.register(checkout, pair, budget=budget)
        return Signed(pair.cm, pair.pm, pair.open_checkout, pair.open_payment,
                      pair.nonce_checkout, pair.nonce_payment)  # fmt: skip

    def payer_approves(self) -> None:
        sim = self.ctx.world.sim
        for order_id, order in list(sim.orders.items()):
            waiting = order["status"] != "APPROVED" and not any(
                a["order"] == order_id for a in sim.authorizations.values()
            )
            if waiting:
                sim.approve(order_id)

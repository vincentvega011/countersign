"""Baseline capture: capture right after authorization, with no gate (docs/PROTOCOL.md Decision 59).

A conventional integration authorizes the order and captures it. This stage does exactly that:
claim the attempt, capture the authorization for whatever amount PayPal says it holds (the one read
of the authorization that the client's capture interface needs, never compared with the signed
total), and book the result from the capture response. It does not fetch the order or the capture,
does not re-derive terms, and does not re-check the mandates, the budget or the lock. A raised order
is therefore captured at the raised amount. It is a `CaptureGate`
subclass only to reuse the claim (so two completes capture once), the deterministic Request-Id, the
ledger entries and the signed Payment Receipt; its `_execute` replaces every check.

Failure behaviour is the gate's: a capture PayPal refuses takes the fail path, which reads PayPal and
voids what it can. Only the checks are missing, never the bookkeeping. It can only be built by the
composition root when `CS_MODE=baseline`.
"""

from __future__ import annotations

from countersign.canonical.money import Money
from countersign.gate.gate import CaptureGate, _Run
from countersign.gate.outcomes import G_CAPTURE, GateFailure, GateOutcome, GatePending
from countersign.paypal.approval import mint_capture_approval
from countersign.paypal.errors import PayPalError


class ImmediateCapture(CaptureGate):
    def _execute(self, run: _Run) -> GateOutcome:
        row = run.row
        run.step = G_CAPTURE
        self._log("degraded.immediate_capture", run.checkout_id)
        try:
            held = self._call(
                run, "get_authorization",
                lambda: self._paypal.get_authorization(row.authorization_id),
            )  # fmt: skip
        except PayPalError as error:
            raise GateFailure(G_CAPTURE, f"capture_failed:{type(error).__name__}") from None
        total: Money = held.amount
        if not self._store.set_state(run.checkout_id, "capturing", expect=("gating",)):
            return GatePending(run.checkout_id, "capturing")
        approval = mint_capture_approval(
            checkout_id=run.checkout_id,
            authorization_id=row.authorization_id,
            expected_total=total,
            invoice_id=held.invoice_id or run.checkout_id,
            custom_id=held.custom_id or row.custom_id,
        )
        try:
            made = self._call(run, "capture", lambda: self._paypal.capture_authorization(approval))
        except PayPalError as error:
            raise GateFailure(G_CAPTURE, f"capture_failed:{type(error).__name__}") from None
        return self._finalize(run, made.resource_id, total)

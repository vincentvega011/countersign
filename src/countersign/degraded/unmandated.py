"""Baseline ACP complete: no mandate, no lock, authorize and capture at once (Decision 59).

This is the permissive implementation of the ACP adapter's `UnmandatedCompletion` seam. A
conventional integration that adds a second checkout protocol maps ACP complete to "charge the
buyer", so that is what this does, with the same two payer approval modes the Credential Provider
has and no more:

- the principal has a vault entry: PayPal creates and authorizes the order in one call (the sandbox
  vaulted wallet), and the stage captures;
- otherwise: the order is created and the answer carries the PayPal approval link; a later complete,
  after the payer approved on PayPal, authorizes and captures.

Nothing here invents a way to charge without the payer. It does not verify a mandate (there is none),
does not re-derive terms before authorizing, and keeps its pending orders in process memory
(`# SHORTCUT:` a naive integration would; docs/LIMITATIONS.md). It is built only by the composition
root when `CS_MODE=baseline`.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import replace

from sqlalchemy import Engine, select

from countersign.canonical.models import Checkout
from countersign.canonical.money import Money
from countersign.cp.config import CpConfig
from countersign.ledger import store as ledger_store
from countersign.lock import Principal
from countersign.merchant.policy import policy_hash
from countersign.paypal.approval import mint_capture_approval
from countersign.paypal.client import PayPalClient
from countersign.paypal.errors import PayPalError
from countersign.paypal.models import ExperienceContext, VaultCharge
from countersign.paypal.translate import order_request_from_checkout
from countersign.protocols.acp.service import (
    UnmandatedApproval,
    UnmandatedDenied,
    UnmandatedOutcome,
    UnmandatedPaid,
)
from countersign.tables import payer_vault

_DECLINED = "payment_declined"


def now_us() -> int:
    return time.time_ns() // 1000


class NaiveUnmandatedCompletion:
    resumable = True

    def __init__(
        self,
        config: CpConfig,
        engine: Engine,
        paypal: PayPalClient,
        *,
        clock_us: Callable[[], int] = now_us,
        vault_lookup: Callable[[str], str | None] | None = None,
    ) -> None:
        self._config = config
        self._engine = engine
        self._paypal = paypal
        self._clock_us = clock_us
        self._vault_lookup = vault_lookup or self._vault_from_table
        self._policy_hash = policy_hash()
        self._orders: dict[
            str, tuple[str, str | None]
        ] = {}  # checkout id -> (order id, approval url)
        self._mutex = threading.Lock()

    def _vault_from_table(self, principal: str) -> str | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(payer_vault.c.vault_id).where(payer_vault.c.principal == principal)
            ).first()
        return None if row is None else str(row.vault_id)

    def _log(self, kind: str, checkout_id: str, **payload: object) -> None:
        with self._engine.begin() as conn:
            ledger_store.append(
                conn, kind=kind, payload=payload, policy_hash=self._policy_hash,
                checkout_id=checkout_id, ts_us=self._clock_us(),
            )  # fmt: skip

    def complete(self, checkout: Checkout, principal: Principal | None) -> UnmandatedOutcome:
        with self._mutex:  # one naive complete at a time per process; PayPal ids make retries safe
            try:
                return self._complete(checkout, principal)
            except PayPalError as error:
                self._log("degraded.unmandated.failed", checkout.id, error=type(error).__name__)
                return UnmandatedDenied(_DECLINED, "The payment could not be completed.")

    def _complete(self, checkout: Checkout, principal: Principal | None) -> UnmandatedOutcome:
        cid = checkout.id
        total: Money = next(t.amount for t in checkout.totals if t.type == "total")
        custom_id = "bl0." + cid
        self._log("degraded.unmandated.started", cid, amount=f"{total.currency}:{total.minor}")
        known = self._orders.get(cid)
        if known is None:
            request = order_request_from_checkout(
                checkout, custom_id=custom_id,
                experience_context=ExperienceContext(
                    self._config.return_url, self._config.cancel_url
                ),
            )  # fmt: skip
            vault_id = None
            if principal is not None and principal.agent_thumbprint:
                vault_id = self._vault_lookup(principal.agent_thumbprint)
            if vault_id:
                request = replace(request, vault=VaultCharge(vault_id))
            created = self._paypal.create_order(cid, request)
            self._orders[cid] = (created.resource_id, created.approval_url)
            order = self._paypal.get_order(created.resource_id)
            if not vault_id or not order.authorizations:
                if created.approval_url is None:
                    return UnmandatedDenied(_DECLINED, "No payer approval link.")
                self._log(
                    "degraded.unmandated.approval_required", cid, order_id=created.resource_id
                )
                return UnmandatedApproval(created.approval_url)
        else:
            order_id, link = known
            order = self._paypal.get_order(order_id)
            if order.status in ("CREATED", "PAYER_ACTION_REQUIRED"):
                if link is None:
                    return UnmandatedDenied(_DECLINED, "The payer has not approved.")
                return UnmandatedApproval(link)
            if not order.authorizations:
                self._paypal.authorize_order(cid, order.id)
                order = self._paypal.get_order(order.id)
        (authorization,) = order.authorizations
        approval = mint_capture_approval(
            checkout_id=cid, authorization_id=authorization.id, expected_total=total,
            invoice_id=cid, custom_id=custom_id,
        )  # fmt: skip
        made = self._paypal.capture_authorization(approval)
        self._log(
            "degraded.unmandated.captured", cid, order_id=order.id, capture_id=made.resource_id
        )
        return UnmandatedPaid(order.id, made.resource_id)

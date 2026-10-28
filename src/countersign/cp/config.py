"""Credential Provider configuration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from joserfc.jwk import ECKey

from countersign.ablations import Ablations
from countersign.merchant.keys import MerchantKey


@dataclass(frozen=True)
class CpConfig:
    issuer: str  # `iss` of the Payment Receipts
    signing_key: MerchantKey
    platform_key: ECKey | None  # the one trusted platform provider key (Decision 5)
    payee: Mapping[str, str]  # {"id": ..., "name": ...}: the merchant a payment must name
    paypal_payee_merchant_id: str  # the PayPal merchant id the live order must carry
    return_url: str
    cancel_url: str
    audience: str = "credential-provider"
    checkout_audience: str = "merchant"
    enroll_vault: bool = False  # ask PayPal to vault the wallet on redirect approval (sandbox)
    ablations: Ablations = field(default_factory=Ablations)

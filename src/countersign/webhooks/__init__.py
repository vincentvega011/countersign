"""Verified PayPal webhook reconciliation. See docs/PROTOCOL.md Decisions 55 to 58.

A verified notification is only a hint to look at PayPal again. Nothing here moves money.
"""

from countersign.webhooks.service import Settler, WebhookResult, WebhookService

__all__ = ["Settler", "WebhookResult", "WebhookService"]

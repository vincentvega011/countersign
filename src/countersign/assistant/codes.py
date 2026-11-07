"""Fixed explanations of Countersign's codes and fixed text for evidence steps and gate steps.

Plain text, no digits (the grounding check treats a numeral in an answer as a claim about the data), and no
text that comes from the data. An unknown code is answered with a fixed sentence, never guessed.
"""

from __future__ import annotations

CODES: dict[str, str] = {
    # UCP and AP2 mandate extension error codes
    "mandate_required": "A mandate is required for this principal or this checkout, and none was presented.",
    "agent_missing_key": "The agent did not present a key to bind the mandate to.",
    "mandate_invalid_signature": "A signature in the mandate chain did not verify.",
    "mandate_expired": "The mandate was past its expiry time when it was used.",
    "mandate_scope_mismatch": "The mandate does not cover this checkout, customer, amount or items.",
    "merchant_authorization_invalid": "The merchant authorization on the checkout did not verify.",
    "merchant_authorization_missing": "The checkout carried no merchant authorization.",
    # Countersign codes
    "checkout_customer_mismatch": "The checkout belongs to a different customer than the one who approved or paid.",
    "checkout_canceled_after_rejection": "The checkout was canceled after a refused attempt, so it cannot be reused.",
    "checkout_not_ready": "The checkout was not ready to complete.",
    "complete_in_progress": "Another completion of this checkout was already running.",
    "mandate_revoked": "The customer revoked the open mandate.",
    "nonce_replayed": "A single-use value in the mandate had already been used.",
    "no_mandate": "The baseline mode captured this order with no mandate behind it.",
    "invalid_field": "A field in the request was missing, malformed or not allowed.",
    "json_duplicate_key": "The request repeated a key, which Countersign refuses before anything else runs.",
    "json_excess_precision": "A number in the request had more precision than allowed for money.",
    "unmandated_checkout_not_allowed": "The merchant requires a mandate for this checkout.",
    "locked_or_required": "The principal is locked or the merchant requires AP2, and no valid mandate was presented.",
    "unsupported": "The request used an operation this protocol path does not support.",
    "denied:ap2_negotiation_required": "The principal is locked and the agent did not negotiate AP2 protection.",
    "denied:mandate_required": "The principal is locked and no mandate was presented.",
    "denied:customer_unknown": "The lock could not tell which customer this was, so it refused.",
    "denied:lock_store_unreadable": "The lock state could not be read, so it refused.",
    "denied:lock_log_failed": "The decision could not be logged, so it was refused.",
    "payment_failed": "The payment attempt failed before any capture.",
    # Capture gate steps
    "G-FETCH": "The gate could not read the live PayPal order and authorization.",
    "G-STATUS": "The authorization was not capturable, was expired, shared its order, or was already captured.",
    "G-REVERSE": "The gate could not re-derive the checkout terms from the live order.",
    "G-TERMS": "The live PayPal order differs from the signed checkout, or its invoice id or custom id changed.",
    "G-AMOUNT": "The authorized amount differs from the checkout total.",
    "G-MANDATE": "A mandate no longer verified, was revoked, or was no longer reserved by this checkout.",
    "G-BUDGET": "The budget no longer held under the reconciled ledger view.",
    "G-LOCK": "The principal lock policy no longer allowed the payment.",
    "G-CHECKOUT": "The checkout was no longer in progress when the capture started.",
    "G-CAPTURE": "The capture itself or its confirmation failed.",
}

GATE_ORDER = (
    "G-FETCH", "G-STATUS", "G-REVERSE", "G-TERMS", "G-AMOUNT", "G-MANDATE", "G-BUDGET", "G-LOCK",
    "G-CHECKOUT",
)  # fmt: skip

STEP_TITLES: dict[str, str] = {
    "bundle_structure": "Bundle structure",
    "checkout_mandate": "Checkout Mandate (first AP2 dispute step)",
    "checkout_jwt_hash": "Checkout hash (second AP2 dispute step)",
    "checkout_receipt": "Checkout Receipt (third AP2 dispute step)",
    "payment_mandate": "Payment Mandate (fourth AP2 dispute step)",
    "payment_receipt": "Payment Receipt (fifth AP2 dispute step)",
    "consent_signature": "Customer device consent",
    "paypal_objects": "PayPal order, authorization and capture",
    "paypal_custom_id": "Evidence reference at PayPal",
    "gate_result": "Capture gate as logged",
    "decision_log": "Decision log consistency",
    "trusted_keys": "Trusted keys",
}

NO_EVIDENCE = {
    "simulated": "There is no evidence bundle for this order: it is simulated.",
    "unmandated": "There is no evidence bundle for this order: the baseline captured it with no mandate.",
    "missing": "The evidence bundle for this order is missing.",
    "not_captured": "There is no evidence bundle for this order: nothing was captured.",
}

STATE_TEXT = {
    "unused": "unused",
    "in_flight": "in flight",
    "used": "used",
    "revoked": "revoked",
    "expired": "expired",
}

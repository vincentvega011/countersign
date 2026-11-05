// Every string the Trusted Surface shows is in this file, as a fixed template. Nothing is built
// from a model, and the only value that comes from the service is a stable error code, which is
// shown only if it matches CODE_PATTERN. Text is plain and has no dashes used as punctuation.

export const CODE_PATTERN = /^[a-z][a-z0-9_]{0,47}$/;

export const MESSAGES = Object.freeze({
  checking: {
    title: "Checking this browser",
    body: "Making sure this browser can create and keep a device key.",
  },
  ready: {
    title: "Create this device's key",
    body: "The key is created here and stays here. The private part cannot be read out, not even by this page. Only a signature ever leaves the device.",
  },
  creating: {
    title: "Creating your key",
    body: "Making the key, saving it on this device and registering it. This takes a moment.",
  },
  registered: {
    title: "This device is registered",
    body: "Your device key is registered. When you approve something later, check that this fingerprint matches.",
  },
  unregistered: {
    title: "Registration is not finished",
    body: "A key is saved on this device, but it is not registered yet. Finish the registration to use it.",
  },
  insecure_context: {
    title: "This page is not secure",
    body: "Device keys need a secure connection. Open this page over HTTPS and try again.",
  },
  no_subtle: {
    title: "This browser cannot create device keys",
    body: "The browser's cryptography tools are not available here. Try a current version of Safari, Chrome, Firefox or Edge.",
  },
  no_indexeddb: {
    title: "This browser cannot store a device key",
    body: "Browser storage is switched off or not supported. Private browsing often does this. Open the page in a normal window and try again.",
  },
  idb_unavailable: {
    title: "Browser storage is not available",
    body: "The browser would not open its storage. Private browsing often does this. Open the page in a normal window and try again.",
  },
  storage_quota: {
    title: "Not enough storage",
    body: "The browser refused to save the key because storage is full. Free some space and try again. Nothing was registered.",
  },
  storage_write_failed: {
    title: "The key could not be saved",
    body: "The browser refused to save the key. Nothing was registered. Try again, or use a normal window.",
  },
  key_lost: {
    title: "The key on this device is gone",
    body: "This device was registered before, but its key can no longer be found. The old key cannot be recovered and can no longer be used. You can create a new key and register it as a new device.",
  },
  key_unreadable: {
    title: "The saved key cannot be read",
    body: "A key is saved on this device but it is damaged or not usable. The old key can no longer be used. You can create a new key and register it as a new device.",
  },
  register_rejected: {
    title: "Registration was not accepted",
    body: "The service refused this registration and nothing was changed. Your key is saved on this device. The error code is below.",
  },
  network: {
    title: "Could not reach the service",
    body: "Check your connection and try again. Your key is saved on this device.",
  },
  intent: {
    title: "Approve what your agent may buy",
    body: "Your agent asks to shop for you on these terms. Check each line. Nothing is approved until you tap Approve.",
  },
  intent_loading: {
    title: "Getting your request ready",
    body: "Asking the store for a fresh, single use code to sign. This takes a moment.",
  },
  intent_signing: {
    title: "Signing your approval",
    body: "Signing with your device key and asking the store to issue the mandates.",
  },
  intent_approved: {
    title: "Approved",
    body: "Your agent can now shop within these limits. You can leave this page.",
  },
  intent_declined: {
    title: "Declined",
    body: "Nothing was approved and nothing was sent.",
  },
  intent_invalid: {
    title: "This request cannot be shown",
    body: "The request is damaged or incomplete, so nothing can be approved. Ask your agent to send it again.",
  },
  intent_expired: {
    title: "This request has expired",
    body: "The single use code ran out before you approved. Nothing was issued. Get a fresh request and check it again.",
  },
  intent_mismatch: {
    title: "The approval did not match what was shown",
    body: "The store could not match your signature to the terms, so nothing was issued. Nothing you approved was changed. Try again.",
  },
  intent_terms: {
    title: "The store cannot accept these terms",
    body: "The store refused something in the request, such as the store, an item, the limit or the expiry. Nothing was issued. Ask your agent for a new request.",
  },
  intent_key: {
    title: "This device key cannot approve",
    body: "The store does not accept this device key for this customer, or it was revoked. Nothing was issued. Register the device again.",
  },
  intent_refused: {
    title: "The approval was not accepted",
    body: "Nothing was issued. The error code is below.",
  },
  proposal_unknown: {
    title: "This request was not found",
    body: "The store has no request with this code. Nothing was approved. Ask your agent to send it again.",
  },
  proposal_expired: {
    title: "This request has expired",
    body: "The request ran out of time before it was approved. Nothing was issued. Ask your agent to send it again.",
  },
  proposal_used: {
    title: "This request was already approved",
    body: "This request has been approved once and cannot be used again. Nothing new was issued.",
  },
  purchase: {
    title: "Approve this purchase",
    body: "This is exactly what the store signed. Check each line. Nothing is bought until you tap Approve.",
  },
  purchase_loading: {
    title: "Getting the store's checkout",
    body: "Asking the store for the signed checkout and checking its signature. This takes a moment.",
  },
  purchase_signing: {
    title: "Signing your approval",
    body: "Signing with your device key and asking the store to issue the purchase mandates.",
  },
  purchase_approved: {
    title: "Approved",
    body: "Your approval was recorded and the signed purchase mandates were issued for this checkout.",
  },
  purchase_declined: {
    title: "Declined",
    body: "Nothing was approved and nothing was sent.",
  },
  purchase_missing: {
    title: "No checkout to approve",
    body: "This link does not name a checkout. Open the link the store gave you.",
  },
  purchase_unavailable: {
    title: "This checkout cannot be approved",
    body: "The checkout is not there or is not ready to pay. Nothing was issued. Go back to the store.",
  },
  purchase_expired: {
    title: "This checkout has expired",
    body: "The checkout or your approval code ran out of time. Nothing was issued. Go back to the store for a new one.",
  },
  purchase_changed: {
    title: "The checkout changed",
    body: "The checkout is no longer the one you were shown, so nothing was issued. Open it again to see the new terms.",
  },
  purchase_unsigned: {
    title: "The store's signature did not check out",
    body: "The checkout could not be verified as signed by the store, so it is not shown and nothing was issued.",
  },
  purchase_mismatch: {
    title: "The approval did not match what was shown",
    body: "The store could not match your signature to the checkout, so nothing was issued. Open the checkout again.",
  },
  purchase_key: {
    title: "This device key cannot approve",
    body: "The store does not accept this device key for this customer, or it was revoked. Nothing was issued.",
  },
  purchase_not_yours: {
    title: "This checkout belongs to another customer",
    body: "Only the customer this checkout was made for can approve it. Nothing was issued.",
  },
  purchase_used: {
    title: "This checkout was already approved",
    body: "An approval for this checkout already exists. Nothing new was issued.",
  },
  purchase_refused: {
    title: "The approval was not accepted",
    body: "Nothing was issued. The error code is below.",
  },
  needs_key: {
    title: "This device is not registered",
    body: "Register this device first, then open this link again.",
  },
  activity: {
    title: "My agent activity",
    body: "Each approval you gave an agent, what became of it, and a way to take it back.",
  },
  activity_loading: {
    title: "Opening your activity",
    body: "Signing in with your device key and loading your approvals.",
  },
  activity_empty: {
    title: "No approvals yet",
    body: "When you approve an agent to shop for you, it will be listed here.",
  },
  activity_denied: {
    title: "Your activity could not be opened",
    body: "The store did not accept this device key for this customer. Nothing is shown. The error code is below.",
  },
  revoke_confirm: {
    title: "Take this approval back?",
    body: "Your agent will no longer be able to buy with it. This cannot be undone.",
  },
  revoke_done: {
    title: "Approval taken back",
    body: "Your agent can no longer buy with this approval.",
  },
  revoke_in_flight: {
    title: "A payment is being taken right now",
    body: "The purchase under this approval has already started, so it cannot be taken back. Refresh to see how it ended.",
  },
  revoke_already_used: {
    title: "This approval was already used",
    body: "A purchase was completed under this approval, so there is nothing left to take back.",
  },
  revoke_refused: {
    title: "The approval was not taken back",
    body: "Nothing was changed. The error code is below.",
  },
  unexpected: {
    title: "Something went wrong",
    body: "The key could not be created. Nothing was registered. Try again.",
  },
});

export const NOTES = Object.freeze({
  persist_denied:
    "Your browser did not agree to keep this key permanently. It may be removed if the device runs low on space, and you would then need to register again.",
});

// Which fixed message each refusal code of the consent endpoint gets. Anything else gets
// `intent_refused` with the code shown, if it is a plain code.
export const CONSENT_REFUSALS = Object.freeze({
  consent_signature_invalid: "intent_mismatch",
  consent_claims_mismatch: "intent_mismatch",
  consent_malformed: "intent_mismatch",
  consent_purpose_mismatch: "intent_mismatch",
  agent_key_mismatch: "intent_mismatch",
  consent_proposal_mismatch: "intent_mismatch",
  proposal_unknown: "proposal_unknown",
  proposal_expired: "proposal_expired",
  proposal_used: "proposal_used",
  consent_terms_invalid: "intent_terms",
  consent_time_invalid: "intent_expired",
  consent_expired: "intent_expired",
  challenge_expired: "intent_expired",
  challenge_used: "intent_expired",
  challenge_unknown: "intent_expired",
  challenge_nonce_mismatch: "intent_expired",
  device_key_unknown: "intent_key",
  device_key_revoked: "intent_key",
  device_key_customer_mismatch: "intent_key",
});

export const LABELS = Object.freeze({
  merchant: "Store",
  items: "Items",
  ceiling: "Spend up to",
  expires: "Valid until",
  agent: "Agent key fingerprint",
  yourKey: "Your device key fingerprint",
  approve: "Approve",
  decline: "Decline",
  refresh: "Get a fresh request",
  mandates: "Show the signed mandates",
  checkoutMandate: "Open Checkout Mandate",
  paymentMandate: "Open Payment Mandate",
  fingerprint: "Key fingerprint",
  previous: "Previous key fingerprint",
  customer: "Customer ID",
  code: "Error code",
  create: "Create key",
  retry: "Try again",
  working: "Working",
  finish: "Finish registration",
  recreate: "Create a new key",
  total: "Total",
  checkoutValid: "Checkout valid until",
  refreshActivity: "Refresh",
  revoke: "Take back",
  revokeYes: "Yes, take it back",
  revokeKeep: "Keep it",
  state: "State",
  spendLimit: "Spend limit",
  purchase: "Purchase",
  checkoutId: "Checkout",
  captureId: "Capture ID",
  paid: "Paid",
  when: "When",
  register: "Go to device setup",
});

// Which fixed message each refusal code of the purchase endpoints gets.
export const PURCHASE_REFUSALS = Object.freeze({
  checkout_unknown: "purchase_unavailable",
  checkout_not_ready: "purchase_unavailable",
  checkout_expired: "purchase_expired",
  checkout_changed: "purchase_changed",
  offer_expired: "purchase_expired",
  offer_unknown: "purchase_unavailable",
  offer_used: "purchase_used",
  checkout_customer_mismatch: "purchase_not_yours",
  proof_invalid: "purchase_key",
  merchant_authorization_invalid: "purchase_unsigned",
  consent_signature_invalid: "purchase_mismatch",
  consent_claims_mismatch: "purchase_mismatch",
  consent_malformed: "purchase_mismatch",
  consent_purpose_mismatch: "purchase_mismatch",
  consent_time_invalid: "purchase_expired",
  consent_expired: "purchase_expired",
  challenge_expired: "purchase_expired",
  challenge_used: "purchase_expired",
  challenge_unknown: "purchase_expired",
  challenge_nonce_mismatch: "purchase_expired",
  device_key_unknown: "purchase_key",
  device_key_revoked: "purchase_key",
  device_key_customer_mismatch: "purchase_key",
});

// The states of an open mandate on the activity screen: a fixed label, tone and glyph each.
export const MANDATE_STATES = Object.freeze({
  unused: { label: "Not used yet", tone: "accent", glyph: "○" },
  in_flight: { label: "Purchase in progress", tone: "warning", glyph: "◐" },
  used: { label: "Used", tone: "success", glyph: "✓" },
  revoked: { label: "Taken back", tone: "neutral", glyph: "⊘" },
  expired: { label: "Expired", tone: "neutral", glyph: "✕" },
});

export const REVOKE_REFUSALS = Object.freeze({
  in_flight: "revoke_in_flight",
  already_used: "revoke_already_used",
});

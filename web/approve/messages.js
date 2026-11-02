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
});

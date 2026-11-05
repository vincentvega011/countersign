// Every sentence the verifier page can show. Fixed templates only: nothing here or on the page comes
// from a model, and nothing from a bundle is ever shown as markup.

export const STEP_TEXT = {
  bundle_structure: {
    title: "Bundle structure",
    explains:
      "The file is strict JSON, has exactly the members of a version 1 evidence bundle, and says the payment was captured.",
  },
  checkout_mandate: {
    title: "Checkout Mandate (AP2 dispute step 1)",
    explains:
      "The platform signed the customer's open Checkout Mandate, the agent key it names signed the closed one, the closed mandate discloses the signed checkout, and its items and quantities are what the customer allowed.",
  },
  checkout_jwt_hash: {
    title: "Checkout hash (AP2 dispute step 2)",
    explains:
      "The hash of the merchant-signed checkout equals the checkout_hash in the mandate, and it is the checkout this bundle is about.",
  },
  checkout_receipt: {
    title: "Checkout Receipt (AP2 dispute step 3)",
    explains:
      "The merchant signed a Success receipt whose reference is the hash of the closed Checkout Mandate.",
  },
  payment_mandate: {
    title: "Payment Mandate (AP2 dispute step 4)",
    explains:
      "The Payment Mandate is scoped to the same checkout, names the same customer and agent, and its amount, payee, merchant, range and budget are within what was approved.",
  },
  payment_receipt: {
    title: "Payment Receipt (AP2 dispute step 5)",
    explains:
      "The merchant signed a Success receipt for this PayPal capture whose reference is the hash of the closed Payment Mandate.",
  },
  consent_signature: {
    title: "Customer device consent",
    explains:
      "The customer's device key signed the exact terms both open mandates were issued from, and those terms rebuild into exactly these mandates.",
  },
  paypal_objects: {
    title: "PayPal order, authorization and capture",
    explains:
      "Every PayPal object as it was read has the signed total, invoice id, items and ids, and the capture is a completed final capture.",
  },
  paypal_custom_id: {
    title: "Evidence reference at PayPal",
    explains:
      "Every custom_id PayPal holds equals the evidence reference recomputed from the signed mandates.",
  },
  gate_result: {
    title: "Capture gate (as logged)",
    explains:
      "The decision log in the bundle shows each of the nine gate checks passing once, and the capture it records is the one the receipt names. The log is not signed or anchored, so this shows the log is consistent, not that nothing was left out.",
  },
  decision_log: {
    title: "Decision log consistency",
    explains:
      "Each log entry recomputes to its hash, entries follow each other, and every one is included in the stated Merkle root. The root is not anchored anywhere yet.",
  },
  trusted_keys: {
    title: "Trusted keys",
    explains:
      "The merchant and platform keys used for every check are the ones you pinned.",
  },
};

export const TEXT = {
  passed: "Passed",
  failed: "Failed",
  firstFailure: "First failure",
  notPinned: "Keys not pinned",
  code: "Failure code",
  why: "What the check found",
  allPassed: "Every step passed",
  allPassedBody:
    "The bundle is consistent and its keys are the ones you pinned.",
  failedAt: "Verification failed",
  failedAtBody: (title) => `The first step that failed is: ${title}.`,
  onlyKeysBody:
    "Every check of the bundle passed, but its keys were not pinned, so this shows the bundle is consistent, not who signed it.",
  unpinned:
    "No keys are pinned. The merchant and platform keys were taken from the bundle itself and are not pinned: the result shows the bundle is self-consistent, not that the real merchant and platform signed it.",
  pinned:
    "Both keys are pinned. The merchant's and the platform's signatures are checked with the keys you pasted. The customer's device key and the agent's key are not pinned: they come from the bundle, vouched for by the platform's signature, so the customer's approval is only as trustworthy as the platform key. Compare the device key fingerprint below with the one the customer's phone showed when the key was made.",
  partlyPinned:
    "Only one key is pinned. Pin both keys, or the check of trusted keys fails.",
  keyFingerprint: (who) => `${who} key fingerprint`,
  merchant: "Merchant",
  device: "Customer device",
  platform: "Platform",
  working: "Checking",
  emptyBundle: "Paste a bundle, drop a file or load one by capture id first.",
  badKey: (who) =>
    `The ${who} key is not a valid JSON public key, so nothing was checked.`,
  badId: "A capture id is 1 to 64 letters, digits, '-' or '_'.",
  loading: "Loading the stored bundle.",
  loaded: "Loaded the stored bundle. Press Verify to check it.",
  notFound: "No stored bundle has that capture id.",
  loadFailed: "The stored bundle could not be loaded. Try again.",
  fileRead: "Read the file. Press Verify to check it.",
  fileFailed: "The file could not be read.",
};

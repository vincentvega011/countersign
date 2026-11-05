// What the Approve purchase screen is built from: the terms of a merchant-signed checkout, the consent
// record the device key signs, and the fixed templates the page renders. Pure functions, no DOM and no
// network, so the record that is shown, the record that is signed and the record that is sent are one
// and the same object. The Python twin that rebuilds and compares is
// countersign.trusted_surface.purchase (build_closed); the backend also rebuilds the terms from the
// checkout it holds and refuses any difference (docs/PROTOCOL.md Decision 90).

import { jcs } from "./device-key.js";
import { expiryText } from "./consent.js";

export const PURPOSE_CHECKOUT = "countersign.consent.checkout.v1";
export const CHALLENGE_PURPOSE_CHECKOUT = "consent_checkout";
export const PURPOSE_OFFER = "countersign.purchase.offer.v1";
export const CHALLENGE_PURPOSE_OFFER = "purchase_offer";
export const RECORD_VERSION = 1;
export const RECORD_SECONDS = 300;
export const MANDATE_SECONDS = 900;
export const CHECKOUT_ID = /^chk_[A-Za-z0-9_-]{22}$/;

const TEXT = /^[\x20-\x7e]{1,200}$/;
const isInt = (v) => typeof v === "number" && Number.isSafeInteger(v);
const isText = (v) => typeof v === "string" && TEXT.test(v);
const exactly = (value, members) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === members.length &&
  members.every((m) => Object.hasOwn(value, m));

export class OfferError extends Error {}

export function checkoutIdFromHash(hash) {
  const match = /^#checkout=([^&]*)$/.exec(hash);
  if (match === null) return null;
  if (!CHECKOUT_ID.test(match[1])) throw new OfferError("checkout id");
  return match[1];
}

// The offer the backend returns after it verified the merchant's signature. Strict shape.
export function checkOffer(value) {
  if (!exactly(value, ["offer_id", "terms", "checkout_hash", "expires_us"]))
    throw new OfferError("offer");
  const t = value.terms;
  if (
    !exactly(t, [
      "merchant",
      "checkout_id",
      "currency",
      "items",
      "totals",
      "total_minor",
      "checkout_expires_at",
    ]) ||
    !exactly(t.merchant, ["id", "name", "website"]) ||
    !Object.values(t.merchant).every(isText) ||
    !CHECKOUT_ID.test(t.checkout_id) ||
    t.currency !== "USD" ||
    !isInt(t.total_minor) ||
    !isInt(t.checkout_expires_at) ||
    !Array.isArray(t.items) ||
    t.items.length < 1 ||
    t.items.length > 20 ||
    !Array.isArray(t.totals)
  )
    throw new OfferError("terms");
  for (const item of t.items)
    if (
      !exactly(item, ["id", "title", "quantity", "unit_minor", "line_minor"]) ||
      !isText(item.id) ||
      !isText(item.title) ||
      !isInt(item.quantity) ||
      !isInt(item.unit_minor) ||
      !isInt(item.line_minor)
    )
      throw new OfferError("item");
  for (const row of t.totals)
    if (
      !exactly(row, ["type", "amount_minor"]) ||
      !isText(row.type) ||
      !isInt(row.amount_minor)
    )
      throw new OfferError("total");
  if (
    !/^off_[A-Za-z0-9_-]{22}$/.test(value.offer_id) ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.checkout_hash) ||
    !isInt(value.expires_us)
  )
    throw new OfferError("ids");
  return value;
}

export function mandateExpiry(checkoutExpiresAt, issuedAt) {
  return Math.min(checkoutExpiresAt, issuedAt + MANDATE_SECONDS);
}

// The contents of the two closed mandates for these terms (Decision 29). The backend rebuilds exactly
// this and compares the JCS bytes before the platform key signs anything.
export function closedFor(terms, checkoutHash, issuedAt) {
  const exp = mandateExpiry(terms.checkout_expires_at, issuedAt);
  const merchant = () => ({
    id: terms.merchant.id,
    name: terms.merchant.name,
    website: terms.merchant.website,
  });
  return {
    checkout: {
      vct: "mandate.checkout.1",
      checkout_hash: checkoutHash,
      exp,
    },
    payment: {
      vct: "mandate.payment.1",
      transaction_id: checkoutHash,
      payee: merchant(),
      payment_amount: { amount: terms.total_minor, currency: terms.currency },
      payment_instrument: {
        id: "wallet",
        type: "wallet",
        description: "Payment wallet",
      },
      exp,
    },
  };
}

export function buildPurchaseRecord({
  offer,
  challenge,
  customerId,
  deviceThumbprint,
  origin,
}) {
  return {
    v: RECORD_VERSION,
    purpose: PURPOSE_CHECKOUT,
    customer_id: customerId,
    device_thumbprint: deviceThumbprint,
    challenge_id: challenge.challenge_id,
    challenge: challenge.nonce,
    issued_at: challenge.issued_at,
    expires_at: challenge.issued_at + RECORD_SECONDS,
    origin,
    offer_id: offer.offer_id,
    terms: offer.terms,
    mandate: closedFor(offer.terms, offer.checkout_hash, challenge.issued_at),
  };
}

// The request that opens an offer: proof that this device's customer is the one asking (Decision 111).
export function buildOfferProof({
  challenge,
  customerId,
  deviceThumbprint,
  checkoutId,
  origin,
}) {
  return {
    v: RECORD_VERSION,
    purpose: PURPOSE_OFFER,
    challenge_id: challenge.challenge_id,
    challenge: challenge.nonce,
    customer_id: customerId,
    device_thumbprint: deviceThumbprint,
    checkout_id: checkoutId,
    origin,
  };
}

export const purchaseBytes = (record) => new TextEncoder().encode(jcs(record));

// ------------------------------------------------------------------------------------ templates

export const lineText = (item) => `${item.quantity} × ${item.title}`;

const TOTAL_LABELS = Object.freeze({
  subtotal: "Subtotal",
  discount: "Discount",
  items_discount: "Item discounts",
  fulfillment: "Delivery",
  tax: "Tax",
  fee: "Fees",
});

// The lines of the Approve purchase screen, from the terms and nothing else.
export function purchaseView(terms, zone) {
  return {
    merchant: terms.merchant.name,
    items: terms.items.map((item) => ({
      text: lineText(item),
      lineMinor: item.line_minor,
    })),
    adjustments: terms.totals
      .filter((row) => row.type !== "total" && row.type !== "subtotal")
      .map((row) => ({
        label: TOTAL_LABELS[row.type] ?? "Other charges",
        minor: row.amount_minor,
      })),
    subtotalMinor: terms.totals.find((r) => r.type === "subtotal")
      ?.amount_minor,
    totalMinor: terms.total_minor,
    currency: terms.currency,
    expires: expiryText(terms.checkout_expires_at, zone),
  };
}

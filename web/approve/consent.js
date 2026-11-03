// What the Approve intent screen is built from. The proposal an agent sends, the consent record the device key
// signs, and the fixed templates the page renders. Pure functions, no DOM, no network, so the record
// that is shown, the record that is signed and the record that is sent are one and the same object.
//
// The proposal is untrusted input. It is validated strictly, rendered with textContent only through
// the templates below, and signed as part of the record; the backend then refuses any record whose
// merchant, items, ceiling, expiry or agent key do not check out, and rebuilds the mandate contents
// itself and compares them byte for byte (docs/PROTOCOL.md Decision 81).

import { jcs, thumbprintOf } from "./device-key.js";

export const PURPOSE_CONSENT = "countersign.consent.open-mandates.v1";
export const CHALLENGE_PURPOSE_CONSENT = "consent_open_mandates";
export const RECORD_VERSION = 1;
export const RECORD_SECONDS = 300;

const TEXT = /^[\x20-\x7e]{1,200}$/;
const THUMBPRINT = /^[A-Za-z0-9_-]{43}$/;
const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

const isInt = (v) => typeof v === "number" && Number.isSafeInteger(v);
const isText = (v) => typeof v === "string" && TEXT.test(v);
const exactly = (value, members) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === members.length &&
  members.every((m) => Object.hasOwn(value, m));

export class ProposalError extends Error {}

export const PROPOSAL_ID = /^prp_[A-Za-z0-9_-]{16}$/;

// `#proposal=<id>`: the short opaque id of a proposal the agent filed with the backend. Returns the id
// or null when there is none; throws ProposalError for an id that is there but not an id.
export function proposalIdFromHash(hash) {
  const match = /^#proposal=([^&]*)$/.exec(hash);
  if (match === null) return null;
  if (!PROPOSAL_ID.test(match[1])) throw new ProposalError("proposal id");
  return match[1];
}

// What the backend returns for a proposal id: the proposal plus its id and its own expiry. Returns the
// proposal members only.
export function proposalFromView(view) {
  if (
    !exactly(view, [
      "proposal_id",
      "items",
      "ceiling_minor",
      "currency",
      "mandate_expires_at",
      "agent_jwk",
      "expires_us",
    ])
  )
    throw new ProposalError("members");
  // eslint-disable-next-line no-unused-vars
  const { proposal_id, expires_us, ...proposal } = view;
  return checkProposal(proposal);
}

// What an agent proposes: structured values only. Item ids and quantities, a ceiling, an expiry and
// the agent's public key. It carries no store name and no item title: those come from the store
// (`/trusted-surface/store`), so no text an agent wrote can reach this page.
export function checkProposal(value) {
  if (
    !exactly(value, [
      "items",
      "ceiling_minor",
      "currency",
      "mandate_expires_at",
      "agent_jwk",
    ])
  )
    throw new ProposalError("members");
  const { items, agent_jwk: jwk } = value;
  if (!Array.isArray(items) || items.length < 1 || items.length > 10)
    throw new ProposalError("items");
  for (const item of items)
    if (
      !exactly(item, ["id", "quantity"]) ||
      !isText(item.id) ||
      !isInt(item.quantity) ||
      item.quantity < 1 ||
      item.quantity > 99
    )
      throw new ProposalError("item");
  if (
    !isInt(value.ceiling_minor) ||
    value.ceiling_minor < 1 ||
    value.ceiling_minor > 1_000_000
  )
    throw new ProposalError("ceiling");
  if (value.currency !== "USD") throw new ProposalError("currency");
  if (!isInt(value.mandate_expires_at) || value.mandate_expires_at < 1)
    throw new ProposalError("expiry");
  if (
    !exactly(jwk, ["kty", "crv", "x", "y"]) ||
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    !THUMBPRINT.test(jwk.x) ||
    !THUMBPRINT.test(jwk.y)
  )
    throw new ProposalError("agent key");
  return value;
}

// The store's own description, from `/trusted-surface/store`: its merchant record and item titles.
export function checkStore(value) {
  if (!exactly(value, ["merchant", "currency", "items"]))
    throw new ProposalError("store");
  if (
    !exactly(value.merchant, ["id", "name", "website"]) ||
    !Object.values(value.merchant).every(isText)
  )
    throw new ProposalError("store merchant");
  if (
    !Array.isArray(value.items) ||
    !value.items.every(
      (i) => exactly(i, ["id", "title"]) && isText(i.id) && isText(i.title),
    )
  )
    throw new ProposalError("store items");
  return value;
}

// The contents of the two open mandates for these terms. The backend rebuilds exactly this (the
// Python twin is countersign.trusted_surface.consent.build_mandate) and compares the JCS bytes.
export function mandateFor(terms) {
  const lines = terms.items.map((item, index) => ({
    id: `line_${index + 1}`,
    acceptable_items: [{ id: item.id, title: item.title }],
    quantity: item.quantity,
  }));
  const merchant = () => ({
    id: terms.merchant.id,
    name: terms.merchant.name,
    website: terms.merchant.website,
  });
  const cap = terms.ceiling_minor;
  return {
    checkout: {
      vct: "mandate.checkout.open.1",
      exp: terms.mandate_expires_at,
      constraints: [
        { type: "checkout.line_items", items: lines },
        { type: "checkout.allowed_merchants", allowed: [merchant()] },
      ],
    },
    payment: {
      vct: "mandate.payment.open.1",
      exp: terms.mandate_expires_at,
      constraints: [
        {
          type: "payment.amount_range",
          currency: terms.currency,
          min: 1,
          max: cap,
        },
        { type: "payment.allowed_payees", allowed: [merchant()] },
        { type: "payment.budget", max: cap, currency: terms.currency },
        {
          type: "payment.agent_recurrence",
          frequency: "ON_DEMAND",
          max_occurrences: 1,
        },
      ],
    },
  };
}

// The one structured record: what the page shows, what the device key signs, what is sent.
export async function buildRecord({
  proposal,
  store,
  challenge,
  customerId,
  deviceThumbprint,
  origin,
}) {
  const titles = new Map(store.items.map((i) => [i.id, i.title]));
  const terms = {
    merchant: {
      id: store.merchant.id,
      name: store.merchant.name,
      website: store.merchant.website,
    },
    items: proposal.items.map((i) => {
      if (!titles.has(i.id))
        throw new ProposalError("item is not in this store");
      return { id: i.id, title: titles.get(i.id), quantity: i.quantity };
    }),
    ceiling_minor: proposal.ceiling_minor,
    currency: proposal.currency,
    mandate_expires_at: proposal.mandate_expires_at,
    agent_thumbprint: await thumbprintOf(proposal.agent_jwk),
  };
  return {
    v: RECORD_VERSION,
    purpose: PURPOSE_CONSENT,
    customer_id: customerId,
    device_thumbprint: deviceThumbprint,
    challenge_id: challenge.challenge_id,
    challenge: challenge.nonce,
    issued_at: challenge.issued_at,
    expires_at: challenge.issued_at + RECORD_SECONDS,
    origin,
    terms,
    mandate: mandateFor(terms),
  };
}

export const recordBytes = (record) => new TextEncoder().encode(jcs(record));

// ------------------------------------------------------------------------------------ templates

// "Mon 9 Nov, 12:00 (UTC)". Built by hand, not by Intl, so the words are the same in every browser.
export function expiryText(seconds, zone) {
  const d = new Date(seconds * 1000);
  const two = (n) => String(n).padStart(2, "0");
  return `${WEEKDAYS[d.getDay()]} ${d.getDate()} ${MONTHS[d.getMonth()]}, ${two(d.getHours())}:${two(d.getMinutes())} (${zone})`;
}

export const itemText = (item) => `${item.quantity} × ${item.title}`;

// The lines of the Approve intent screen, from the record and nothing else. `amount` is rendered by
// the shared amount component; every other value is the text below.
export function termsView(record, zone) {
  const { terms } = record;
  return {
    merchant: terms.merchant.name,
    items: terms.items.map(itemText),
    ceilingMinor: terms.ceiling_minor,
    currency: terms.currency,
    expires: expiryText(terms.mandate_expires_at, zone),
    agentThumbprint: terms.agent_thumbprint,
  };
}

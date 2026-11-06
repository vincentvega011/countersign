// The twelve verification steps, port of countersign_verify/steps.py: same names, same order, the same
// checks raising the same codes. Each step runs on its own and never trusts another step's result.
import * as cons from "./constraints.js";
import {
  b64url,
  digest,
  domainHash,
  thumbprint,
  utf8,
  verifyEs256,
  verifyJws,
} from "./crypto.js";
import {
  Invalid,
  MAX_SAFE_INTEGER,
  dict,
  get,
  hashable,
  isDict,
  isInt,
  isList,
  isStr,
  item,
  iter,
  jcs,
  len,
  loads,
  or,
  same,
  sameKeys,
} from "./json.js";
import { checkFields, checkInclusion, entryHash, rootOf } from "./log.js";
import { readClosed, readOpen, split } from "./sdjwt.js";

export const VCT = {
  checkout_open: "mandate.checkout.open.1",
  checkout: "mandate.checkout.1",
  payment_open: "mandate.payment.open.1",
  payment: "mandate.payment.1",
};
export const GATE_CODES = [
  "G-FETCH",
  "G-STATUS",
  "G-REVERSE",
  "G-TERMS",
  "G-AMOUNT",
  "G-MANDATE",
  "G-BUDGET",
  "G-LOCK",
  "G-CHECKOUT",
];
const TOP = [
  "v",
  "kind",
  "capture_id",
  "checkout_id",
  "order_id",
  "authorization_id",
  "checkout_jwt",
  "mandates",
  "receipts",
  "consent",
  "paypal",
  "gate",
  "log",
  "keys",
];
const PURPOSE_CONSENT = "countersign.consent.open-mandates.v1";

// An exact integer minor-unit amount from a PayPal `{currency_code, value}` (USD, two places).
export function minor(money) {
  if (!isDict(money))
    throw new Invalid(
      "paypal_amount_malformed",
      "a PayPal amount is malformed",
    );
  const value = get(money, "value");
  const code = get(money, "currency_code");
  if (!isStr(value) || !/^[0-9]+(?:\.[0-9]+)?$/.test(value) || !isStr(code))
    throw new Invalid(
      "paypal_amount_malformed",
      "a PayPal amount is malformed",
    );
  const dot = value.indexOf(".");
  let whole = dot < 0 ? value : value.slice(0, dot);
  const fraction = (dot < 0 ? "" : value.slice(dot + 1)).padEnd(2, "0");
  if (/[^0]/.test(fraction.slice(2)) || code !== "USD")
    throw new Invalid(
      "paypal_amount_not_cents",
      "a PayPal amount is not whole US cents",
    );
  whole = whole.replace(/^0+/, "") || "0";
  const cents = Number(whole) * 100 + Number(fraction.slice(0, 2));
  if (whole.length > 14 || cents > MAX_SAFE_INTEGER)
    throw new Invalid("paypal_amount_range", "a PayPal amount is out of range");
  return [cents, code];
}

const samePair = (a, b) => a[0] === b[0] && a[1] === b[1];

export class Bundle {
  constructor(raw, pinned = null) {
    if (!isDict(raw) || !sameKeys(raw, TOP))
      throw new Invalid(
        "bundle_members",
        "the bundle does not have exactly the expected members",
      );
    if (!same(raw.v, 1) || raw.kind !== "countersign.evidence")
      throw new Invalid(
        "bundle_version",
        "the bundle is not a version 1 Countersign evidence bundle",
      );
    this.raw = raw;
    this.pinned = pinned ?? dict();
    for (const name of [
      "capture_id",
      "checkout_id",
      "order_id",
      "authorization_id",
      "checkout_jwt",
    ])
      if (!isStr(raw[name]) || !raw[name])
        throw new Invalid("bundle_member_type", `${name} is not a text`);
    for (const name of [
      "mandates",
      "receipts",
      "consent",
      "paypal",
      "gate",
      "log",
      "keys",
    ])
      if (!isDict(raw[name]))
        throw new Invalid("bundle_member_type", `${name} is not an object`);
  }

  merchantKey() {
    const key = or(
      get(this.pinned, "merchant"),
      get(this.raw.keys, "merchant"),
    );
    if (!isDict(key)) throw new Invalid("no_merchant_key", "no merchant key");
    return key;
  }

  platformKey() {
    const key = or(
      get(this.pinned, "platform"),
      get(this.raw.keys, "platform"),
    );
    if (!isDict(key)) throw new Invalid("no_platform_key", "no platform key");
    return key;
  }

  mandate(name) {
    const value = get(this.raw.mandates, name);
    if (!isStr(value))
      throw new Invalid("mandate_missing", `mandates.${name} is missing`);
    return value;
  }

  async checkoutChain() {
    const chain = this.mandate("checkout_closed");
    const [opened, link] = split(chain);
    if (opened !== this.mandate("checkout_open"))
      throw new Invalid(
        "checkout_chain_not_extending",
        "the closed Checkout Mandate does not extend the open one in the bundle",
      );
    const om = await readOpen(opened, this.platformKey(), VCT.checkout_open);
    return [
      om,
      await readClosed(
        link,
        opened,
        om,
        VCT.checkout,
        "merchant",
        "checkout_hash",
      ),
    ];
  }

  async paymentChain() {
    const chain = this.mandate("payment_closed");
    const [opened, link] = split(chain);
    if (opened !== this.mandate("payment_open"))
      throw new Invalid(
        "payment_chain_not_extending",
        "the closed Payment Mandate does not extend the open one in the bundle",
      );
    const om = await readOpen(opened, this.platformKey(), VCT.payment_open);
    return [
      om,
      await readClosed(
        link,
        opened,
        om,
        VCT.payment,
        "credential-provider",
        "transaction_id",
      ),
    ];
  }

  async checkout() {
    const [, payload] = await verifyJws(
      this.raw.checkout_jwt,
      this.merchantKey(),
    );
    if (!isDict(payload))
      throw new Invalid("checkout_not_object", "the checkout is not an object");
    return payload;
  }

  async total() {
    const checkout = await this.checkout();
    const totals = [...iter(get(checkout, "totals", []))].filter(
      (t) => get(t, "type") === "total",
    );
    if (totals.length !== 1 || !isInt(get(totals[0], "amount")))
      throw new Invalid(
        "checkout_total",
        "the checkout has no single integer total",
      );
    const currency = get(checkout, "currency");
    if (!isStr(currency))
      throw new Invalid("checkout_currency", "the checkout names no currency");
    return [totals[0].amount, currency];
  }
}

// ------------------------------------------------------------------------------------ the steps

async function bundleStructure(b) {
  if (get(b.raw.gate, "state") !== "captured")
    throw new Invalid(
      "not_captured",
      "the bundle does not say the payment was captured",
    );
  return "the bundle has the expected members and says the payment was captured";
}

async function checkoutMandate(b) {
  const [opened, closed] = await b.checkoutChain();
  if (closed.checkoutJwt !== b.raw.checkout_jwt)
    throw new Invalid(
      "checkout_jwt_not_disclosed",
      "the checkout_jwt in the bundle is not the one the mandate discloses",
    );
  // AP2: with open mandates, the closed checkout must conform to every constraint (Decision 110).
  const found = cons.byType(
    get(opened.content, "constraints"),
    cons.CHECKOUT_TYPES,
    "checkout.line_items",
  );
  cons.lineItems(
    found.get("checkout.line_items"),
    cons.committedCheckout(closed.checkoutJwt),
  );
  return "signatures, key binding and hashes verify; the items are what the customer allowed";
}

async function checkoutJwtHash(b) {
  const [, closed] = await b.checkoutChain();
  if (
    (await digest(b.raw.checkout_jwt)) !== item(closed.content, "checkout_hash")
  )
    throw new Invalid(
      "checkout_hash_mismatch",
      "the hash of the checkout_jwt is not the mandate's checkout_hash",
    );
  const checkout = await b.checkout();
  if (get(checkout, "id") !== b.raw.checkout_id)
    throw new Invalid(
      "checkout_id_mismatch",
      "the signed checkout is for another checkout id",
    );
  return "checkout_hash is the hash of the checkout_jwt, which the merchant signed";
}

async function receipt(b, which, typ, mandateLink) {
  const [, claims] = await verifyJws(
    get(b.raw.receipts, which),
    b.merchantKey(),
    typ,
  );
  if (!isDict(claims) || get(claims, "status") !== "Success")
    throw new Invalid(
      "receipt_not_success",
      `the ${which} receipt is not a Success receipt`,
    );
  if (get(claims, "reference") !== (await digest(mandateLink)))
    throw new Invalid(
      "receipt_reference",
      `the ${which} receipt reference is not the hash of the closed mandate`,
    );
  return claims;
}

async function checkoutReceipt(b) {
  const [, link] = split(b.mandate("checkout_closed"));
  const claims = await receipt(b, "checkout", "checkout-receipt+jwt", link);
  if (get(claims, "order_id") !== b.raw.checkout_id)
    throw new Invalid(
      "receipt_other_checkout",
      "the Checkout Receipt is for another checkout",
    );
  return "the receipt is merchant signed and its reference is the closed mandate's hash";
}

const constraints = (content, kind) =>
  [...iter(get(content, "constraints", []))].filter(
    (c) => get(c, "type") === kind,
  );

async function paymentMandate(b) {
  const [com, ccl] = await b.checkoutChain();
  const [pom, pcl] = await b.paymentChain();
  if (
    item(pcl.content, "transaction_id") !== item(ccl.content, "checkout_hash")
  )
    throw new Invalid(
      "payment_other_checkout",
      "the Payment Mandate is scoped to another checkout (transaction_id)",
    );
  if (
    item(pom.payload, "sub") !== item(com.payload, "sub") ||
    (await thumbprint(pom.content.cnf.jwk)) !==
      (await thumbprint(com.content.cnf.jwk))
  )
    throw new Invalid(
      "payment_other_principal",
      "the two open mandates name a different customer or agent key",
    );
  const reference = constraints(pom.content, "payment.reference");
  if (
    reference.length !== 1 ||
    get(reference[0], "conditional_transaction_id") !==
      (await digest(b.mandate("checkout_open")))
  )
    throw new Invalid(
      "payment_not_bound",
      "the open Payment Mandate is not bound to the open Checkout Mandate",
    );
  const [total, currency] = await b.total();
  if (
    !same(
      get(pcl.content, "payment_amount"),
      dict([
        ["amount", total],
        ["currency", currency],
      ]),
    )
  )
    throw new Invalid(
      "payment_amount",
      "the Payment Mandate amount is not the checkout total",
    );
  const allowed = constraints(pom.content, "payment.allowed_payees");
  const payee = get(pcl.content, "payee");
  if (
    allowed.length !== 1 ||
    ![...iter(get(allowed[0], "allowed", []))].some((p) => same(payee, p))
  )
    throw new Invalid(
      "payment_payee",
      "the payee is not one the customer allowed",
    );
  const budget = constraints(pom.content, "payment.budget");
  if (
    budget.length !== 1 ||
    !isInt(get(budget[0], "max")) ||
    total > budget[0].max
  )
    throw new Invalid(
      "payment_budget",
      "the total is over the budget the customer approved",
    );
  const found = cons.byType(
    get(pom.content, "constraints"),
    cons.PAYMENT_TYPES,
    "payment.reference",
  );
  if (found.has("payment.amount_range"))
    cons.amountRange(found.get("payment.amount_range"), total, currency);
  if (found.has("payment.agent_recurrence"))
    cons.recurrence(found.get("payment.agent_recurrence"));
  const merchants = cons
    .byType(
      get(com.content, "constraints"),
      cons.CHECKOUT_TYPES,
      "checkout.line_items",
    )
    .get("checkout.allowed_merchants");
  if (merchants !== undefined) cons.allowedMerchants(merchants, payee);
  return "chain verifies, scoped to the checkout; amount, payee, merchant and budget are allowed";
}

async function paymentReceipt(b) {
  const [, link] = split(b.mandate("payment_closed"));
  const claims = await receipt(b, "payment", "payment-receipt+jwt", link);
  if (
    get(claims, "psp_confirmation_id") !== b.raw.capture_id ||
    get(claims, "payment_id") !== b.raw.checkout_id
  )
    throw new Invalid(
      "receipt_other_capture",
      "the Payment Receipt is for another capture or checkout",
    );
  return "the receipt is merchant signed, names this capture, and references the closed mandate";
}

const without = (content, names) =>
  dict(Object.entries(content).filter(([k]) => !names.includes(k)));

async function consentSignature(b) {
  const consent = b.raw.consent;
  if (!sameKeys(consent, ["record", "signature", "device_jwk", "customer_id"]))
    throw new Invalid(
      "consent_members",
      "the consent record is missing or has the wrong members",
    );
  const { record: text, signature, device_jwk: device } = consent;
  if (!isStr(text))
    throw new Invalid("consent_not_text", "the consent record is not text");
  const record = loads(text);
  if (jcs(record) !== text)
    throw new Invalid(
      "consent_not_canonical",
      "the consent record is not in canonical form",
    );
  if (!(await verifyEs256(device, utf8(text), signature)))
    throw new Invalid(
      "consent_signature",
      "the device signature does not verify over the consent record",
    );
  if (get(record, "purpose") !== PURPOSE_CONSENT)
    throw new Invalid(
      "consent_purpose",
      "the signed record is not a consent to open mandates",
    );
  if (get(record, "device_thumbprint") !== (await thumbprint(device)))
    throw new Invalid(
      "consent_device",
      "the record names another device key than the one in the bundle",
    );
  const [com] = await b.checkoutChain();
  const [pom] = await b.paymentChain();
  if (
    !same(get(record, "customer_id"), consent.customer_id) ||
    item(com.payload, "sub") !== consent.customer_id
  )
    throw new Invalid(
      "consent_customer",
      "the mandates name another customer than the device consented as",
    );
  if (
    get(item(record, "terms"), "agent_thumbprint") !==
    (await thumbprint(com.content.cnf.jwk))
  )
    throw new Invalid(
      "consent_agent",
      "the consent names another agent key than the mandates bind",
    );
  const signed = get(record, "mandate", dict());
  if (!same(get(signed, "checkout"), without(com.content, ["cnf", "iat"])))
    throw new Invalid(
      "consent_checkout",
      "the open Checkout Mandate is not what the device signed",
    );
  const payment = without(pom.content, ["cnf", "iat"]);
  payment.constraints = [...iter(item(payment, "constraints"))].filter(
    (c) => get(c, "type") !== "payment.reference",
  );
  if (!same(get(signed, "payment"), payment))
    throw new Invalid(
      "consent_payment",
      "the open Payment Mandate is not what the device signed",
    );
  const terms = item(record, "terms");
  const budgets = payment.constraints.filter(
    (c) => get(c, "type") === "payment.budget",
  );
  if (
    !budgets.length ||
    !same(get(terms, "ceiling_minor"), item(budgets[0], "max"))
  )
    throw new Invalid(
      "consent_ceiling",
      "the signed ceiling is not the mandate budget",
    );
  if (!same(get(record, "mandate"), cons.rebuildMandate(terms)))
    throw new Invalid(
      "consent_terms_mismatch",
      "the terms the device was shown do not make these mandates",
    );
  return "the device signature verifies and the signed terms equal both open mandates";
}

function last(bodies, what) {
  if (!isList(bodies) || !bodies.length || !isDict(bodies[bodies.length - 1]))
    throw new Invalid(
      "paypal_missing",
      `the bundle holds no ${what} as fetched`,
    );
  return bodies[bodies.length - 1];
}

function immutable(obj, what, cid, total, currency) {
  if (!samePair(minor(get(obj, "amount")), [total, currency]))
    throw new Invalid(
      "paypal_amount",
      `a PayPal ${what} amount is not the signed checkout total`,
    );
  if (get(obj, "invoice_id") !== cid)
    throw new Invalid(
      "paypal_invoice",
      `a PayPal ${what} is for another checkout (invoice_id)`,
    );
}

function orderUnit(order, cid, total, currency, checkout, ids) {
  const units = get(order, "purchase_units");
  if (!isList(units) || units.length !== 1)
    throw new Invalid(
      "paypal_units",
      "the order does not have exactly one purchase unit",
    );
  const unit = units[0];
  immutable(unit, "order", cid, total, currency);
  const payee = get(or(get(unit, "payee"), dict()), "merchant_id");
  if (!isStr(payee) || !payee)
    throw new Invalid("paypal_no_payee", "the order names no payee");
  const nested = or(get(unit, "payments"), dict());
  for (const [kind, key] of [
    ["authorization", "authorizations"],
    ["capture", "captures"],
  ])
    for (const inner of iter(get(nested, key, []))) {
      if (get(inner, "id") !== ids[kind])
        throw new Invalid(
          "paypal_nested_id",
          `the order holds a ${kind} the bundle does not name`,
        );
      immutable(inner, `nested ${kind}`, cid, total, currency);
    }
  const items = get(unit, "items", []);
  const lines = get(checkout, "line_items", []);
  if (len(items) !== len(lines))
    throw new Invalid(
      "paypal_item_count",
      "the order has a different number of items than the checkout",
    );
  const itemList = [...iter(items)];
  const lineList = [...iter(lines)];
  for (let i = 0; i < itemList.length; i++) {
    const it = itemList[i];
    const line = lineList[i];
    const want = item(line, "item");
    if (!isInt(item(want, "price")) || !isInt(item(line, "quantity")))
      throw new Invalid(
        "checkout_line",
        "a checkout line has no integer price and quantity",
      );
    if (
      !same(
        [get(it, "name"), get(it, "sku"), get(it, "quantity")],
        [item(want, "title"), item(want, "id"), String(line.quantity)],
      )
    )
      throw new Invalid(
        "paypal_item",
        "an order item is not the checkout line item",
      );
    if (!samePair(minor(get(it, "unit_amount")), [want.price, currency]))
      throw new Invalid(
        "paypal_item_price",
        "an order item price is not the checkout price",
      );
  }
  let subtotal = 0;
  for (const line of lineList)
    subtotal += item(item(line, "item"), "price") * item(line, "quantity");
  const itemTotal = get(
    get(get(unit, "amount", dict()), "breakdown", dict()),
    "item_total",
  );
  if (!samePair(minor(itemTotal), [subtotal, currency]))
    throw new Invalid(
      "paypal_item_total",
      "the order item_total is not the sum of the checkout lines",
    );
}

async function paypalObjects(b) {
  const [total, currency] = await b.total();
  const checkout = await b.checkout();
  const paypal = b.raw.paypal;
  const cid = b.raw.checkout_id;
  const kinds = ["order", "authorization", "capture"];
  const lastOf = {};
  for (const kind of kinds) lastOf[kind] = last(get(paypal, kind), kind);
  const ids = {
    order: b.raw.order_id,
    authorization: b.raw.authorization_id,
    capture: b.raw.capture_id,
  };
  for (const kind of kinds)
    for (const body of paypal[kind]) {
      if (!isDict(body) || get(body, "id") !== ids[kind])
        throw new Invalid(
          "paypal_id",
          `a PayPal ${kind} has an id the bundle does not name`,
        );
      if (kind === "order") {
        if (get(body, "intent") !== "AUTHORIZE")
          throw new Invalid(
            "paypal_intent",
            "a PayPal order is not an authorization order",
          );
        orderUnit(body, cid, total, currency, checkout, ids);
      } else immutable(body, kind, cid, total, currency);
    }
  const payees = new Set(
    paypal.order.map((o) =>
      item(item(item(item(o, "purchase_units"), 0), "payee"), "merchant_id"),
    ),
  );
  if (payees.size !== 1)
    throw new Invalid(
      "paypal_payee_changed",
      "the payee changed between two reads of the order",
    );
  const auth = lastOf.authorization;
  const capture = lastOf.capture;
  if (
    get(capture, "status") !== "COMPLETED" ||
    get(capture, "final_capture") !== true
  )
    throw new Invalid(
      "paypal_capture_status",
      "the capture is not a completed final capture",
    );
  if (get(auth, "status") !== "CAPTURED")
    throw new Invalid(
      "paypal_authorization_status",
      "the authorization is not captured",
    );
  return "ids, statuses, amounts, invoice id and items agree with the signed checkout";
}

// The custom_id every PayPal object must carry, recomputed from the signed mandates.
export async function expectedCustomId(b) {
  const [, ccl] = await b.checkoutChain();
  const reference = jcs(
    dict([
      ["v", 1],
      ["checkout_hash", item(ccl.content, "checkout_hash")],
      [
        "checkout_mandate",
        await digest(split(b.mandate("checkout_closed"))[1]),
      ],
      ["payment_mandate", await digest(split(b.mandate("payment_closed"))[1])],
    ]),
  );
  return `cs1.${b64url(await domainHash("cs.evidence.ref.v1", utf8(reference)))}`;
}

async function customId(b) {
  const want = await expectedCustomId(b);
  const found = [hashable(get(b.raw.gate, "custom_id"))];
  for (const kind of ["order", "authorization", "capture"])
    for (const body of iter(get(b.raw.paypal, kind, [])))
      if (kind === "order") {
        for (const unit of iter(get(body, "purchase_units", []))) {
          found.push(hashable(get(unit, "custom_id")));
          for (const key of ["authorizations", "captures"])
            for (const inner of iter(
              get(or(get(unit, "payments"), dict()), key, []),
            ))
              found.push(hashable(get(inner, "custom_id")));
        }
      } else found.push(hashable(get(body, "custom_id")));
  if (!found.every((f) => isStr(f) && f === want))
    throw new Invalid(
      "custom_id_mismatch",
      "a custom_id at PayPal is not the evidence reference of these mandates",
    );
  return "every custom_id equals the reference recomputed from the signed mandates";
}

function entriesOf(b) {
  const entries = get(b.raw.log, "entries");
  if (!isList(entries) || !entries.length)
    throw new Invalid("log_empty", "the bundle holds no log entries");
  return entries;
}

async function gateResult(b) {
  const entries = entriesOf(b);
  const steps = new Map();
  let captured = null;
  for (const e of entries) {
    const payload = loads(item(e, "payload"));
    if (item(e, "kind") === "gate.step") {
      const code = hashable(item(payload, "code"));
      const outcome = item(payload, "outcome");
      if (isStr(code)) {
        if (!steps.has(code)) steps.set(code, []);
        steps.get(code).push(outcome);
      }
    }
    if (e.kind === "gate.captured") captured = payload;
  }
  for (const code of GATE_CODES)
    if (!same(steps.get(code) ?? null, ["pass"]))
      throw new Invalid(
        "gate_step",
        `gate step ${code} did not pass exactly once in the log`,
      );
  if (captured === null)
    throw new Invalid(
      "gate_not_captured",
      "the log has no gate.captured entry",
    );
  const [total, currency] = await b.total();
  if (
    !same(
      [
        get(captured, "capture_id"),
        get(captured, "order_id"),
        get(captured, "authorization_id"),
        get(captured, "amount"),
      ],
      [
        b.raw.capture_id,
        b.raw.order_id,
        b.raw.authorization_id,
        `${currency}:${total}`,
      ],
    )
  )
    throw new Invalid(
      "gate_captured_mismatch",
      "gate.captured names another capture, order or amount",
    );
  const [, claims] = await verifyJws(
    get(b.raw.receipts, "payment"),
    b.merchantKey(),
  );
  if (!same(get(captured, "reference"), get(claims, "reference")))
    throw new Invalid(
      "gate_receipt_mismatch",
      "gate.captured and the Payment Receipt disagree on the reference",
    );
  return "all nine gate steps passed and gate.captured matches the receipt and the capture";
}

async function decisionLog(b) {
  const log = b.raw.log;
  const entries = entriesOf(b);
  const proofs = get(log, "proofs");
  if (!sameKeys(log, ["entries", "size", "root", "proofs"]) || !isList(proofs))
    throw new Invalid("log_members", "the log section has the wrong members");
  if (!same(log.size, entries.length) || proofs.length !== entries.length)
    throw new Invalid(
      "log_truncated",
      "the log size, entries and proofs disagree (truncated?)",
    );
  const hashes = [];
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    checkFields(e);
    if (get(e, "checkout_id") !== b.raw.checkout_id)
      throw new Invalid(
        "log_other_checkout",
        "a log entry belongs to another checkout",
      );
    if (i && !(e.seq > entries[i - 1].seq))
      throw new Invalid("log_order", "log entries are not in increasing order");
    const computed = await entryHash(e);
    if (b64url(computed) !== e.entry_hash)
      throw new Invalid(
        "log_entry_hash",
        `log entry ${e.seq} does not hash to its entry_hash`,
      );
    if (
      i &&
      e.seq === entries[i - 1].seq + 1 &&
      e.prev_hash !== entries[i - 1].entry_hash
    )
      throw new Invalid(
        "log_chain",
        `log entry ${e.seq} does not follow the previous entry`,
      );
    hashes.push(computed);
  }
  const root = await rootOf(hashes);
  if (b64url(root) !== log.root)
    throw new Invalid(
      "log_root",
      "the log entries do not hash to the stated root",
    );
  for (let i = 0; i < proofs.length; i++) {
    const proof = proofs[i];
    if (
      !isDict(proof) ||
      !same(get(proof, "index"), i) ||
      !same(get(proof, "size"), hashes.length)
    )
      throw new Invalid(
        "proof_position",
        `the proof for entry ${i} is for another position or size`,
      );
    await checkInclusion(hashes[i], proof, root);
  }
  return `${hashes.length} entries recompute, chain where adjacent, and are all included in the root`;
}

async function trustedKeys(b) {
  if (!Object.keys(b.pinned).length)
    throw new Invalid(
      "keys_not_pinned",
      "the keys were taken from the bundle itself; pin them with --merchant-key and --platform-key",
    );
  for (const name of ["merchant", "platform"]) {
    if (!Object.prototype.hasOwnProperty.call(b.pinned, name))
      throw new Invalid("keys_partly_pinned", `the ${name} key was not pinned`);
    if (
      (await thumbprint(b.pinned[name])) !==
      (await thumbprint(get(b.raw.keys, name)))
    )
      throw new Invalid(
        "keys_differ",
        `the bundle's ${name} key is not the pinned one`,
      );
  }
  return "the merchant and platform keys are the ones you pinned";
}

export const STEPS = [
  ["bundle_structure", bundleStructure],
  ["checkout_mandate", checkoutMandate],
  ["checkout_jwt_hash", checkoutJwtHash],
  ["checkout_receipt", checkoutReceipt],
  ["payment_mandate", paymentMandate],
  ["payment_receipt", paymentReceipt],
  ["consent_signature", consentSignature],
  ["paypal_objects", paypalObjects],
  ["paypal_custom_id", customId],
  ["gate_result", gateResult],
  ["decision_log", decisionLog],
  ["trusted_keys", trustedKeys],
];
export const STEP_NAMES = STEPS.map(([name]) => name);

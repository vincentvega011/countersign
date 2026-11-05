// The open mandates' constraints, evaluated against what was bought. Port of
// countersign_verify/constraints.py (Decision 110): same checks, same order, same codes.
import { unb64 } from "./crypto.js";
import {
  Invalid,
  dict,
  get,
  isDict,
  isInt,
  isList,
  isStr,
  item,
  loads,
  sameKeys,
} from "./json.js";

export const CHECKOUT_TYPES = [
  "checkout.line_items",
  "checkout.allowed_merchants",
];
export const PAYMENT_TYPES = [
  "payment.reference",
  "payment.amount_range",
  "payment.allowed_payees",
  "payment.budget",
  "payment.agent_recurrence",
];
const MAX_QUANTITY = 1_000_000;
const MAX_LINES = 100;

const within = (o, names) => Object.keys(o).every((k) => names.includes(k));

export function byType(constraints, allowed, required) {
  if (!isList(constraints))
    throw new Invalid(
      "constraint_unresolved",
      "the constraints are not a list",
    );
  const found = new Map();
  for (const c of constraints) {
    const kind = isDict(c) ? get(c, "type") : null;
    if (!isStr(kind) || !allowed.includes(kind))
      throw new Invalid(
        "constraint_unresolved",
        "a constraint of a type the verifier does not know",
      );
    if (found.has(kind))
      throw new Invalid("constraint_duplicate", "two constraints of one type");
    found.set(kind, c);
  }
  if (!found.has(required))
    throw new Invalid(
      "constraint_unresolved",
      `the required ${required} constraint is missing`,
    );
  return found;
}

// The checkout a closed mandate commits to (bound by checkout_hash); step 2 checks its signature.
export function committedCheckout(checkoutJwt) {
  const parts = checkoutJwt.split(".");
  if (parts.length !== 3)
    throw new Invalid("jws_shape", "a JWS is not three segments");
  const checkout = loads(unb64(parts[1]));
  if (!isDict(checkout))
    throw new Invalid("checkout_not_object", "the checkout is not an object");
  return checkout;
}

const quantity = (v) => isInt(v) && v > 0 && v <= MAX_QUANTITY;

// Edmonds-Karp, nodes: 0 source, 1..n requirements, n+1..n+m items, n+m+1 sink.
function maxFlow(demands, supplies, edges) {
  const n = demands.length;
  const m = supplies.length;
  const sink = n + m + 1;
  const cap = Array.from({ length: sink + 1 }, () =>
    new Array(sink + 1).fill(0),
  );
  demands.forEach((d, i) => {
    cap[0][1 + i] = d;
  });
  supplies.forEach((s, j) => {
    cap[1 + n + j][sink] = s;
  });
  const unlimited = demands.reduce((a, b) => a + b, 0) + 1;
  for (const [i, j] of edges) cap[1 + i][1 + n + j] = unlimited;
  let total = 0;
  for (;;) {
    const parent = new Array(sink + 1).fill(-1);
    parent[0] = 0;
    const queue = [0];
    while (queue.length && parent[sink] < 0) {
      const u = queue.shift();
      for (let v = 0; v <= sink; v++)
        if (cap[u][v] > 0 && parent[v] < 0) {
          parent[v] = u;
          queue.push(v);
        }
    }
    if (parent[sink] < 0) return total;
    let amount = cap[parent[sink]][sink];
    for (let v = sink; v !== 0; v = parent[v])
      amount = Math.min(amount, cap[parent[v]][v]);
    for (let v = sink; v !== 0; v = parent[v]) {
      cap[parent[v]][v] -= amount;
      cap[v][parent[v]] += amount;
    }
    total += amount;
  }
}

export function lineItems(constraint, checkout) {
  const code = "constraint_line_items";
  if (!within(constraint, ["type", "items"]))
    throw new Invalid(
      "constraint_unresolved",
      "checkout.line_items has a member not understood",
    );
  const items = get(constraint, "items");
  if (!isList(items) || !(items.length > 0 && items.length <= MAX_LINES))
    throw new Invalid(
      code,
      "checkout.line_items names no requirement, or too many",
    );
  const demands = [];
  const acceptable = [];
  const ids = new Set();
  for (const requirement of items) {
    if (!isDict(requirement))
      throw new Invalid(code, "a line item requirement is not an object");
    if (!within(requirement, ["id", "acceptable_items", "quantity"]))
      throw new Invalid(
        "constraint_unresolved",
        "a line item requirement has a member not understood",
      );
    const rid = get(requirement, "id");
    const q = get(requirement, "quantity");
    const options = get(requirement, "acceptable_items");
    if (!isStr(rid) || ids.has(rid))
      throw new Invalid(code, "a line item requirement has no unique id");
    ids.add(rid);
    if (!quantity(q) || !isList(options))
      throw new Invalid(
        code,
        "a line item requirement has no valid quantity or items",
      );
    const allowed = new Set();
    for (const option of options) {
      if (!isDict(option) || !isStr(get(option, "id")))
        throw new Invalid(code, "an acceptable item has no id");
      if (!within(option, ["id", "title"]))
        throw new Invalid(
          "constraint_unresolved",
          "an acceptable item has a member not understood",
        );
      allowed.add(option.id);
    }
    demands.push(q);
    acceptable.push(allowed);
  }
  const lines = get(checkout, "line_items");
  if (!isList(lines) || lines.length > MAX_LINES)
    throw new Invalid(
      "checkout_line",
      "the checkout has no line items, or too many",
    );
  const wanted = new Map();
  for (const line of lines) {
    const it = isDict(line) ? get(line, "item") : null;
    const q = isDict(line) ? get(line, "quantity") : null;
    if (!isDict(it) || !isStr(get(it, "id")) || !quantity(q))
      throw new Invalid(
        "checkout_line",
        "a checkout line has no item id and quantity",
      );
    wanted.set(it.id, (wanted.get(it.id) ?? 0) + q);
  }
  const names = [...wanted.keys()].sort();
  const supplies = names.map((name) => wanted.get(name));
  const edges = [];
  acceptable.forEach((opts, r) =>
    names.forEach((name, c) => {
      if (opts.has(name)) edges.push([r, c]);
    }),
  );
  const flow = maxFlow(demands, supplies, edges);
  const sum = (xs) => xs.reduce((a, b) => a + b, 0);
  if (flow !== sum(demands) || flow !== sum(supplies))
    throw new Invalid(
      code,
      "the checkout lines are not the items and quantities the customer allowed",
    );
}

export function allowedMerchants(constraint, payee) {
  if (!within(constraint, ["type", "allowed"]))
    throw new Invalid(
      "constraint_unresolved",
      "checkout.allowed_merchants has a member not understood",
    );
  const allowed = get(constraint, "allowed");
  if (!isList(allowed) || !allowed.length)
    throw new Invalid(
      "constraint_merchant",
      "checkout.allowed_merchants names no merchant",
    );
  const ids = [];
  for (const entry of allowed) {
    if (!isDict(entry) || !isStr(get(entry, "id")))
      throw new Invalid("constraint_merchant", "an allowed merchant has no id");
    ids.push(entry.id);
  }
  const id = isDict(payee) ? get(payee, "id") : null;
  if (!isStr(id) || !ids.includes(id))
    throw new Invalid(
      "constraint_merchant",
      "the merchant paid is not one the customer allowed",
    );
}

export function amountRange(constraint, amount, currency) {
  if (!within(constraint, ["type", "currency", "min", "max"]))
    throw new Invalid(
      "constraint_unresolved",
      "payment.amount_range has a member not understood",
    );
  const low = get(constraint, "min", 0);
  const high = get(constraint, "max");
  if (!isInt(low) || !isInt(high) || !(low >= 0 && low <= high))
    throw new Invalid(
      "constraint_amount_range",
      "payment.amount_range has no valid bounds",
    );
  if (
    get(constraint, "currency") !== currency ||
    !(amount > 0) ||
    !(low <= amount && amount <= high)
  )
    throw new Invalid(
      "constraint_amount_range",
      "the amount is outside the range the customer allowed",
    );
}

export function recurrence(constraint) {
  if (!within(constraint, ["type", "frequency", "max_occurrences"]))
    throw new Invalid(
      "constraint_unresolved",
      "payment.agent_recurrence has a member not understood",
    );
  if (
    !isInt(get(constraint, "max_occurrences")) ||
    constraint.max_occurrences !== 1
  )
    throw new Invalid(
      "constraint_unresolved",
      "payment.agent_recurrence allows more than one payment",
    );
}

// The open mandate contents the platform must issue for `terms`.
export function rebuildMandate(terms) {
  const merchant = item(terms, "merchant");
  const lines = [...item(terms, "items")].map((entry, n) =>
    dict([
      ["id", `line_${n + 1}`],
      [
        "acceptable_items",
        [
          dict([
            ["id", item(entry, "id")],
            ["title", item(entry, "title")],
          ]),
        ],
      ],
      ["quantity", item(entry, "quantity")],
    ]),
  );
  const exp = item(terms, "mandate_expires_at");
  const currency = item(terms, "currency");
  const ceiling = item(terms, "ceiling_minor");
  return dict([
    [
      "checkout",
      dict([
        ["vct", "mandate.checkout.open.1"],
        ["exp", exp],
        [
          "constraints",
          [
            dict([
              ["type", "checkout.line_items"],
              ["items", lines],
            ]),
            dict([
              ["type", "checkout.allowed_merchants"],
              ["allowed", [merchant]],
            ]),
          ],
        ],
      ]),
    ],
    [
      "payment",
      dict([
        ["vct", "mandate.payment.open.1"],
        ["exp", exp],
        [
          "constraints",
          [
            dict([
              ["type", "payment.amount_range"],
              ["currency", currency],
              ["min", 1],
              ["max", ceiling],
            ]),
            dict([
              ["type", "payment.allowed_payees"],
              ["allowed", [merchant]],
            ]),
            dict([
              ["type", "payment.budget"],
              ["max", ceiling],
              ["currency", currency],
            ]),
            dict([
              ["type", "payment.agent_recurrence"],
              ["frequency", "ON_DEMAND"],
              ["max_occurrences", 1],
            ]),
          ],
        ],
      ]),
    ],
  ]);
}

export { sameKeys };

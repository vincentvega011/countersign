// What the dashboard shows about one bundle, computed in the browser by the same verifier modules as
// the /verify/ page and the offline CLI (web/ui/evidence). Nothing here re-implements a check: each
// result is a call into those modules, or a plain read of members the verifier already validated.
// Every value that comes from a bundle is returned as data and rendered as text by the components.
import {
  Bundle,
  GATE_CODES,
  VCT,
  expectedCustomId,
  minor,
} from "../../ui/evidence/steps.js";
import { verify } from "../../ui/evidence/verify.js";
import { readClosed, readOpen, split } from "../../ui/evidence/sdjwt.js";
import { checkInclusion, entryHash, rootOf } from "../../ui/evidence/log.js";
import { thumbprint, b64url } from "../../ui/evidence/crypto.js";
import { Invalid, loads } from "../../ui/evidence/json.js";

export type StepResult = {
  name: string;
  ok: boolean;
  message: string;
  code: string | null;
};
type Json = Record<string, unknown>;
export type Check<T = unknown> =
  { ok: true; value: T } | { ok: false; code: string; message: string };

async function attempt<T>(run: () => Promise<T>): Promise<Check<T>> {
  try {
    return { ok: true, value: await run() };
  } catch (error) {
    if (error instanceof Invalid)
      return { ok: false, code: error.code, message: error.message };
    return {
      ok: false,
      code: "malformed",
      message: "a value had the wrong shape",
    };
  }
}

export interface MandateView {
  title: string;
  open: Check<{ claims: Json; constraints: unknown[] }>;
  closed: Check<{ claims: Json }>;
}
export interface PaypalRow {
  label: string;
  field: string;
  found: string;
  expected: string;
  differs: boolean;
}
export interface GateRow {
  code: string;
  outcomes: string[];
}
export interface LogRow {
  seq: number;
  kind: string;
  proof: Check<true>;
}
export interface DetailModel {
  steps: StepResult[];
  checkout: Check<Json>;
  merchantAuthorization: StepResult | undefined;
  total: Check<[number, string]>;
  mandates: MandateView[];
  consent: {
    step: StepResult | undefined;
    record: Json | null;
    device: string | null;
    customer: string | null;
  };
  paypal: { rows: PaypalRow[]; payeeChanged: boolean; capturedAt: string };
  gate: GateRow[];
  log: { rows: LogRow[]; step: StepResult | undefined; root: string };
}

const text = (value: unknown): string =>
  typeof value === "string"
    ? value
    : value === undefined || value === null
      ? ""
      : JSON.stringify(value);
const asJson = (value: unknown): Json =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Json)
    : {};
const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

function money(value: unknown): string {
  try {
    const [cents, code] = minor(value) as [number, string];
    return `${code}:${cents}`;
  } catch {
    return "unreadable";
  }
}

export async function describe(bundleText: string): Promise<DetailModel> {
  const raw = asJson(loads(bundleText));
  const steps = (await verify(raw, null)) as StepResult[];
  const step = (name: string) => steps.find((s) => s.name === name);
  const b = new Bundle(raw, null);
  const platform = asJson(asJson(raw.keys).platform);
  const mandates = asJson(raw.mandates);

  const chain = async (
    title: string,
    openName: string,
    closedName: string,
    open: string,
    closed: string,
    audience: string,
    hash: string,
  ): Promise<MandateView> => {
    const opened = await attempt(async () => {
      const m = (await readOpen(text(mandates[openName]), platform, open)) as {
        payload: Json;
        content: Json;
      };
      return { m, claims: m.content, constraints: list(m.content.constraints) };
    });
    const closedView = await attempt(async () => {
      if (!opened.ok)
        throw new Invalid(
          "open_not_verified",
          "the open mandate did not verify",
        );
      const [head, link] = split(text(mandates[closedName])) as [
        string,
        string,
      ];
      const c = (await readClosed(
        link,
        head,
        opened.value.m,
        closed,
        audience,
        hash,
      )) as {
        content: Json;
      };
      return { claims: c.content };
    });
    return {
      title,
      open: opened.ok
        ? {
            ok: true,
            value: {
              claims: opened.value.claims,
              constraints: opened.value.constraints,
            },
          }
        : opened,
      closed: closedView,
    };
  };

  const checkout = await attempt(async () => asJson(await b.checkout()));
  const total = await attempt(
    async () => (await b.total()) as [number, string],
  );
  const expected = await attempt(
    async () => (await expectedCustomId(b)) as string,
  );
  const consent = asJson(raw.consent);
  let record: Json | null = null;
  try {
    record = asJson(loads(text(consent.record)));
  } catch {
    record = null;
  }
  const device = await attempt(
    async () => (await thumbprint(consent.device_jwk)) as string,
  );

  // PayPal objects as stored: the last read of each kind, next to what the signed checkout implies.
  const paypal = asJson(raw.paypal);
  const last = (kind: string) => asJson(list(paypal[kind]).at(-1));
  const wantAmount = total.ok
    ? `${total.value[1]}:${total.value[0]}`
    : "unreadable";
  const wantCustom = expected.ok ? expected.value : "unreadable";
  const order = last("order");
  const unit = asJson(list(order.purchase_units)[0]);
  const rows: PaypalRow[] = [];
  const add = (label: string, field: string, found: string, want: string) =>
    rows.push({ label, field, found, expected: want, differs: found !== want });
  add("Order", "amount", money(unit.amount), wantAmount);
  add("Order", "invoice_id", text(unit.invoice_id), text(raw.checkout_id));
  add("Order", "custom_id", text(unit.custom_id), wantCustom);
  const auth = last("authorization");
  add("Authorization", "amount", money(auth.amount), wantAmount);
  add(
    "Authorization",
    "invoice_id",
    text(auth.invoice_id),
    text(raw.checkout_id),
  );
  add("Authorization", "custom_id", text(auth.custom_id), wantCustom);
  const capture = last("capture");
  add("Capture", "amount", money(capture.amount), wantAmount);
  add("Capture", "invoice_id", text(capture.invoice_id), text(raw.checkout_id));
  add("Capture", "custom_id", text(capture.custom_id), wantCustom);
  // The order's items next to the checkout's lines, in order.
  const lines =
    checkout.ok && Array.isArray(checkout.value.line_items)
      ? (checkout.value.line_items as unknown[])
      : [];
  const currency = total.ok ? total.value[1] : "";
  list(unit.items).forEach((it, i) => {
    const stored = asJson(it);
    const line = asJson(lines[i]);
    const want = asJson(line.item);
    add("Order", `item ${i + 1} name`, text(stored.name), text(want.title));
    add(
      "Order",
      `item ${i + 1} unit price`,
      money(stored.unit_amount),
      `${currency}:${text(want.price)}`,
    );
  });
  const payees = new Set(
    list(paypal.order).map((o) =>
      text(asJson(asJson(list(asJson(o).purchase_units)[0]).payee).merchant_id),
    ),
  );
  const payee = [...payees][0] ?? "";
  const payeeChanged = payees.size !== 1;
  rows.push({
    label: "Order",
    field: "payee (merchant id)",
    found: payeeChanged ? [...payees].join(" / ") : payee,
    expected: "the same on every read",
    differs: payeeChanged,
  });

  const log = asJson(raw.log);
  const entries = list(log.entries).map(asJson);
  const gateSteps = new Map<string, string[]>(
    GATE_CODES.map((c: string) => [c, []]),
  );
  for (const e of entries) {
    if (e.kind !== "gate.step") continue;
    try {
      const payload = asJson(loads(text(e.payload)));
      const code = text(payload.code);
      if (gateSteps.has(code)) gateSteps.get(code)!.push(text(payload.outcome));
    } catch {
      // an unreadable payload contributes nothing; the decision_log step reports it
    }
  }

  // Inclusion proofs, one per entry, with the verifier's own functions.
  const hashes: Uint8Array[] = [];
  let hashed = true;
  for (const e of entries) {
    try {
      hashes.push((await entryHash(e)) as Uint8Array);
    } catch {
      hashed = false;
    }
  }
  const root =
    hashed && hashes.length ? ((await rootOf(hashes)) as Uint8Array) : null;
  const proofs = list(log.proofs);
  const logRows: LogRow[] = [];
  for (let i = 0; i < entries.length; i++)
    logRows.push({
      seq: Number(entries[i].seq),
      kind: text(entries[i].kind),
      proof:
        root && hashes[i]
          ? await attempt(async () => {
              await checkInclusion(hashes[i], proofs[i], root);
              return true as const;
            })
          : {
              ok: false,
              code: "log_unreadable",
              message: "the log entries do not hash",
            },
    });

  return {
    steps,
    checkout,
    merchantAuthorization: step("checkout_jwt_hash"),
    total,
    mandates: [
      await chain(
        "Checkout Mandate",
        "checkout_open",
        "checkout_closed",
        VCT.checkout_open,
        VCT.checkout,
        "merchant",
        "checkout_hash",
      ),
      await chain(
        "Payment Mandate",
        "payment_open",
        "payment_closed",
        VCT.payment_open,
        VCT.payment,
        "credential-provider",
        "transaction_id",
      ),
    ],
    consent: {
      step: step("consent_signature"),
      record,
      device: device.ok ? device.value : null,
      customer:
        typeof consent.customer_id === "string" ? consent.customer_id : null,
    },
    paypal: { rows, payeeChanged, capturedAt: "as fetched at capture time" },
    gate: GATE_CODES.map((code: string) => ({
      code,
      outcomes: gateSteps.get(code) ?? [],
    })),
    log: {
      rows: logRows,
      step: step("decision_log"),
      root: root ? (b64url(root) as string) : "",
    },
  };
}

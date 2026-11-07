// The Protection dashboard's data: three more tables beside `orders` (blocked or voided attempts,
// open mandates, and the latest eval's attack cases joined into one row per case), the relation that
// lets the funnel narrow the attempts, and the pre-composed Studio state. All values come from the
// read API; nothing is typed in here.
import type { EvalCase, EventRow, MandateRow } from "./api";
import {
  dataSources as orderSources,
  FIELDS as ORDER_FIELDS,
  type Row,
} from "./fields";
import { FUNNEL_ID } from "./funnel";
import { ATTACK_MATRIX_ID } from "./AttackMatrix";
import { TOTAL_ID, TOTAL_MONEY_ID } from "./kpi";
import { SOURCE_LABEL, money, shortFingerprint } from "./format";

const t = (table: string, id: string, aggregation?: string) =>
  aggregation
    ? { id: `${table}.${id}`, aggregation }
    : { id: `${table}.${id}` };
const title = (text: string, subtitle?: string) => ({
  title: { text, enabled: true },
  ...(subtitle ? { subtitle: { text: subtitle, enabled: true } } : {}),
});
const moneyFormatter = () => (value: unknown) => money(value);

export const OUTCOME_LABEL: Record<string, string> = {
  blocked: "Blocked",
  voided: "Voided",
  captured_unmandated: "Captured, no mandate",
};
const MANDATE_STATE: Record<string, string> = {
  unused: "Unused",
  in_flight: "In flight",
  used: "Used",
  revoked: "Revoked",
  expired: "Expired",
};
export const mandateStateLabel = (s: string) => MANDATE_STATE[s] ?? s;

export function eventRow(e: EventRow): Row {
  return {
    id: String(e.seq),
    at: new Date(e.at),
    day: e.at.slice(0, 10),
    checkout_id: e.checkout_id,
    stage: e.stage,
    outcome: OUTCOME_LABEL[e.outcome] ?? e.outcome,
    voided: e.outcome === "voided" ? 1 : 0,
    reason: e.reason,
    source: e.source,
  };
}
export const EVENT_FIELDS = [
  { id: "id", name: "Event", format: "textFormat", cardinality: "high" },
  { id: "at", name: "Time", format: "dateTimeFormat" },
  { id: "day", name: "Day", format: "textFormat", cardinality: "low" },
  { id: "checkout_id", name: "Checkout", format: "textFormat", cardinality: "high", blankValue: "None" },
  { id: "stage", name: "Where it was stopped", format: "textFormat", cardinality: "low" },
  { id: "outcome", name: "Outcome", format: "textFormat", cardinality: "low" },
  { id: "voided", name: "Voided authorization", format: "integerFormat" },
  { id: "reason", name: "Reason code", format: "textFormat", cardinality: "low" },
  { id: "source", name: "Source", format: "textFormat", cardinality: "low" },
] as const; // prettier-ignore

export function mandateRow(m: MandateRow): Row {
  return {
    id: m.id,
    customer: m.customer_id,
    agent: shortFingerprint(m.agent),
    state: mandateStateLabel(m.state),
    ceiling_minor: m.ceiling_minor,
    spent_minor: m.spent_minor,
    currency: m.currency,
    expires: new Date(m.expires_at),
    created: new Date(m.created_at),
    source: SOURCE_LABEL[m.source] ?? "Unlabelled",
  };
}
export const MANDATE_FIELDS = [
  { id: "id", name: "Open mandate", format: "textFormat", cardinality: "high" },
  { id: "customer", name: "Customer", format: "textFormat" },
  { id: "agent", name: "Agent key", format: "textFormat" },
  { id: "state", name: "State", format: "textFormat", cardinality: "low" },
  { id: "ceiling_minor", name: "Ceiling", format: "integerFormat", createValueFormatter: moneyFormatter },
  { id: "spent_minor", name: "Spent", format: "integerFormat", createValueFormatter: moneyFormatter },
  { id: "currency", name: "Currency", format: "textFormat", cardinality: "low" },
  { id: "expires", name: "Expires", format: "dateTimeFormat" },
  { id: "created", name: "Created", format: "dateTimeFormat" },
  { id: "source", name: "Source", format: "textFormat", cardinality: "low" },
] as const; // prettier-ignore

// One row per attack case: its outcome under each mode, side by side.
export function attackRows(cases: EvalCase[]): Row[] {
  const by = new Map<string, { full?: EvalCase; baseline?: EvalCase }>();
  for (const c of cases) {
    const entry = by.get(c.case) ?? {};
    entry[c.mode] = c;
    by.set(c.case, entry);
  }
  const rows: Row[] = [];
  for (const [name, { full, baseline }] of by) {
    const f = full?.outcome ?? "missing";
    const b = baseline?.outcome ?? "missing";
    rows.push({
      id: name,
      category: (full ?? baseline)!.category,
      full_outcome: f,
      baseline_outcome: b,
      full_reason: full?.reason_code ?? null,
      baseline_reason: baseline?.reason_code ?? null,
      full_unauthorized: full?.unauthorized_captures ?? 0,
      baseline_unauthorized: baseline?.unauthorized_captures ?? 0,
      full_succeeded: f === "success" ? 1 : 0,
      baseline_succeeded: b === "success" ? 1 : 0,
      separates: f !== b ? "Separates the modes" : "Blocked in both modes",
    });
  }
  return rows;
}
export const ATTACK_FIELDS = [
  { id: "id", name: "Attack case", format: "textFormat", cardinality: "high" },
  { id: "category", name: "Category", format: "textFormat", cardinality: "low" },
  { id: "full_outcome", name: "Full mode", format: "textFormat", cardinality: "low" },
  { id: "baseline_outcome", name: "Baseline mode", format: "textFormat", cardinality: "low" },
  { id: "full_reason", name: "Full reason code", format: "textFormat", blankValue: "None" },
  { id: "baseline_reason", name: "Baseline reason code", format: "textFormat", blankValue: "None" },
  { id: "full_unauthorized", name: "Full unauthorized captures", format: "integerFormat" },
  { id: "baseline_unauthorized", name: "Baseline unauthorized captures", format: "integerFormat" },
  { id: "full_succeeded", name: "Full attack succeeded", format: "integerFormat" },
  { id: "baseline_succeeded", name: "Baseline attack succeeded", format: "integerFormat" },
  { id: "separates", name: "Separates the modes", format: "textFormat", cardinality: "low" },
] as const; // prettier-ignore

export function protectionData(
  orders: Row[],
  events: Row[],
  mandates: Row[],
  attacks: Row[],
) {
  const table = (
    id: string,
    name: string,
    data: Row[],
    fields: readonly unknown[],
  ) => ({
    id,
    name,
    primaryKeyField: "id",
    data,
    fields: fields as never[],
  });
  return {
    sources: [
      ...orderSources(orders).sources,
      table("events", "Blocked and voided attempts", events, EVENT_FIELDS),
      table("mandates", "Open mandates", mandates, MANDATE_FIELDS),
      table("attacks", "Attack cases", attacks, ATTACK_FIELDS),
    ],
    // An attempt belongs to a checkout: narrowing the funnel narrows the attempts too.
    relationships: [
      {
        id: "event_checkout",
        type: "many-to-one",
        source: "events.checkout_id",
        target: "orders.id",
      },
    ],
  };
}
export { ORDER_FIELDS };

export function protectionState() {
  return {
    pages: [
      {
        id: "protection",
        widgets: {
          blocked: {
            type: TOTAL_ID,
            format: title(
              "Blocked or voided attempts",
              "Every refusal and void in the decision log",
            ),
            dataMapping: { value: [t("events", "id", "count")] },
          },
          voids: {
            type: TOTAL_ID,
            format: title(
              "Voided authorizations",
              "The gate found a difference and voided",
            ),
            dataMapping: { value: [t("events", "voided", "sum")] },
          },
          mandates: {
            type: TOTAL_ID,
            format: title("Open mandates", "Signed by a customer's device"),
            dataMapping: { value: [t("mandates", "id", "count")] },
          },
          spent: {
            type: TOTAL_MONEY_ID,
            format: title(
              "Spent under open mandates",
              "Captured against their ceilings",
            ),
            dataMapping: { value: [t("mandates", "spent_minor", "sum")] },
          },
          byReason: {
            type: "bar-chart-grouped",
            format: title("Blocked or voided by reason code"),
            dataMapping: {
              categoryKey: [t("events", "reason")],
              valueKey: [t("events", "id", "count")],
            },
          },
          overTime: {
            type: "column-chart-grouped",
            format: title("Blocked or voided over time", "Per day"),
            dataMapping: {
              categoryKey: [t("events", "day")],
              valueKey: [t("events", "id", "count")],
            },
            sort: [{ field: t("events", "day"), direction: "asc" }],
          },
          byState: {
            type: "donut-chart",
            format: title("Open mandates by state"),
            dataMapping: {
              categoryKey: [t("mandates", "state")],
              valueKey: [t("mandates", "id", "count")],
            },
          },
          funnel: {
            type: FUNNEL_ID,
            format: title("Authorization funnel", "How far each checkout got"),
            dataMapping: {
              stage: [t("orders", "funnel_stage")],
              checkouts: [t("orders", "id", "count")],
            },
          },
          mandateGrid: {
            type: "grid",
            format: title(
              "Open mandates: ceiling and spend",
              "One row per open mandate",
            ),
            dataMapping: {
              cols: [
                "id",
                "state",
                "customer",
                "agent",
                "ceiling_minor",
                "spent_minor",
                "expires",
                "source",
              ].map((c) => t("mandates", c)),
            },
          },
          categories: {
            type: "column-chart-grouped",
            format: title(
              "Attack cases by category",
              "Click a bar to filter the matrix",
            ),
            dataMapping: {
              categoryKey: [t("attacks", "category")],
              valueKey: [t("attacks", "id", "count")],
            },
          },
          matrix: {
            type: ATTACK_MATRIX_ID,
            format: title(
              "Attack matrix",
              "Each case under full and baseline mode (latest eval)",
            ),
            dataMapping: {
              attack: [t("attacks", "id")],
              category: [t("attacks", "category")],
              full: [t("attacks", "full_outcome")],
              baseline: [t("attacks", "baseline_outcome")],
              fullReason: [t("attacks", "full_reason")],
              baselineReason: [t("attacks", "baseline_reason")],
              fullUnauthorized: [t("attacks", "full_unauthorized")],
              baselineUnauthorized: [t("attacks", "baseline_unauthorized")],
              separates: [t("attacks", "separates")],
            },
          },
        },
        widgetLayout: {
          blocked: { xTrack: 0, yTrack: 0, xSpan: 6, ySpan: 3 },
          voids: { xTrack: 6, yTrack: 0, xSpan: 6, ySpan: 3 },
          mandates: { xTrack: 12, yTrack: 0, xSpan: 6, ySpan: 3 },
          spent: { xTrack: 18, yTrack: 0, xSpan: 6, ySpan: 3 },
          byReason: { xTrack: 0, yTrack: 3, xSpan: 8, ySpan: 10 },
          overTime: { xTrack: 8, yTrack: 3, xSpan: 8, ySpan: 10 },
          byState: { xTrack: 16, yTrack: 3, xSpan: 8, ySpan: 10 },
          funnel: { xTrack: 0, yTrack: 13, xSpan: 10, ySpan: 10 },
          mandateGrid: { xTrack: 10, yTrack: 13, xSpan: 14, ySpan: 10 },
          categories: { xTrack: 0, yTrack: 23, xSpan: 24, ySpan: 10 },
          matrix: { xTrack: 0, yTrack: 33, xSpan: 24, ySpan: 18 },
        },
      },
    ],
    selectedPageId: "protection",
  };
}

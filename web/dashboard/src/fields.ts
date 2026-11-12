// The `orders` table as Studio sees it: one row per checkout from the read API, with field
// definitions, formats and money formatters. Amounts stay integer minor units; only the formatter turns
// them into text, through the shared UI's formatter (never a float).
import type { Order } from "./api";
import {
  SOURCE_LABEL,
  dateTimeFormatter,
  money,
  shortFingerprint,
} from "./format";

export const TABLE = "orders";

const STATUS_LABEL: Record<string, string> = {
  ready_for_complete: "Ready",
  incomplete: "Incomplete",
  complete_in_progress: "In progress",
  completed: "Completed",
  canceled: "Canceled",
  rejected: "Rejected",
  voided: "Voided",
};
const MANDATE_LABEL: Record<string, string> = {
  verified: "Verified",
  refused: "Refused",
  not_presented: "Not presented",
};

export type Row = Record<string, string | number | Date | null>;

export function toRow(order: Order): Row {
  const label = (map: Record<string, string>, v: string) => map[v] ?? v;
  return {
    id: order.id,
    created: new Date(order.created_us / 1000),
    agent: shortFingerprint(order.agent),
    customer: order.customer_id,
    items: order.items,
    amount_minor: order.amount_minor,
    currency: order.currency,
    status: label(STATUS_LABEL, order.status),
    mandate: label(MANDATE_LABEL, order.mandate),
    protocol: order.protocol.toUpperCase(),
    gate: order.gate,
    capture_id: order.capture_id,
    source: SOURCE_LABEL[order.source] ?? "Unlabelled",
    funnel_stage: String(order.funnel_stage),
    captured_minor: order.captured_minor,
    blocked: order.blocked,
    reason: order.reason,
    unauthorized: order.unauthorized,
    search: [
      order.id, order.customer_id, order.agent, order.items, order.capture_id, order.reason,
      order.status, order.source,
    ].filter(Boolean).join(" ").toLowerCase(), // prettier-ignore
  };
}

const moneyFormatter = () => (value: unknown) => money(value);

export const FIELDS = [
  { id: "id", name: "Checkout", format: "textFormat", cardinality: "high" },
  { id: "created", name: "Time (UTC)", format: "dateTimeFormat", createValueFormatter: dateTimeFormatter },
  { id: "agent", name: "Agent key", format: "textFormat", blankValue: "None" },
  { id: "customer", name: "Customer", format: "textFormat", blankValue: "Unbound" },
  { id: "items", name: "Items", format: "textFormat", cardinality: "high" },
  { id: "amount_minor", name: "Amount", format: "integerFormat", createValueFormatter: moneyFormatter },
  { id: "currency", name: "Currency", format: "textFormat", cardinality: "low" },
  { id: "status", name: "Status", format: "textFormat", cardinality: "low" },
  { id: "mandate", name: "Mandate", format: "textFormat", cardinality: "low" },
  { id: "protocol", name: "Protocol", format: "textFormat", cardinality: "low" },
  { id: "gate", name: "Gate", format: "textFormat", blankValue: "Not run" },
  { id: "capture_id", name: "PayPal capture", format: "textFormat", blankValue: "None" },
  { id: "source", name: "Source", format: "textFormat", cardinality: "low" },
  { id: "funnel_stage", name: "Furthest step", format: "textFormat", cardinality: "low" },
  { id: "captured_minor", name: "Captured", format: "integerFormat", createValueFormatter: moneyFormatter },
  { id: "blocked", name: "Blocked", format: "integerFormat" },
  { id: "reason", name: "Reason code", format: "textFormat", blankValue: "None" },
  { id: "unauthorized", name: "Unauthorized capture", format: "integerFormat" },
  { id: "search", name: "Search text", format: "textFormat", hide: true },
] as const; // prettier-ignore

export function dataSources(rows: Row[]) {
  return {
    sources: [
      {
        id: TABLE,
        name: "Agent orders",
        primaryKeyField: "id",
        transactions: "all" as const,
        data: rows,
        fields: FIELDS as unknown as never[],
      },
    ],
  };
}

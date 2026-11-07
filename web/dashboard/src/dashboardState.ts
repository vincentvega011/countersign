// The pre-composed Orders dashboard: KPI tiles, two charts, the authorization funnel and the orders
// grid, all over the `orders` table so cross filters connect them. Visitors get it in view mode;
// edit mode (dev only) starts from the same state.
import { FUNNEL_ID } from "./funnel";
import { DETAIL_ID } from "./OrderDetail";
import { TOTAL_ID, TOTAL_MONEY_ID } from "./kpi";

const t = (id: string, aggregation?: string) =>
  aggregation ? { id: `orders.${id}`, aggregation } : { id: `orders.${id}` };
const title = (text: string, subtitle?: string) => ({
  title: { text, enabled: true },
  ...(subtitle ? { subtitle: { text: subtitle, enabled: true } } : {}),
});

export const GRID_COLUMNS = [
  "created", "source", "id", "status", "mandate", "amount_minor", "items", "agent", "customer",
  "protocol", "gate", "reason", "capture_id",
]; // prettier-ignore

export function ordersState(grouped: boolean) {
  const grid = grouped
    ? {
        type: "pivot-grid",
        format: title("Agent orders by agent and customer"),
        dataMapping: {
          rows: [t("agent"), t("customer")],
          columns: [],
          values: [
            t("id", "count"),
            t("amount_minor", "sum"),
            t("captured_minor", "sum"),
          ],
        },
      }
    : {
        type: "grid",
        format: {
          ...title("Agent orders", "One row per checkout, across protocols"),
          style: { columnAutoSize: true, grandTotalRow: { enabled: true } },
        },
        dataMapping: {
          cols: GRID_COLUMNS.map((c) =>
            c === "amount_minor" ? t(c, "sum") : t(c),
          ),
        },
        sort: [{ field: t("created"), direction: "desc" }],
      };
  return {
    pages: [
      {
        id: "orders",
        widgets: {
          captured: {
            type: TOTAL_MONEY_ID,
            format: title("Captured", "PayPal captures after the gate"),
            dataMapping: { value: [t("captured_minor", "sum")] },
          },
          orders: {
            type: TOTAL_ID,
            format: title("Orders", "Agent checkouts"),
            dataMapping: { value: [t("id", "count")] },
          },
          blocked: {
            type: TOTAL_ID,
            format: title("Blocked attempts", "Refused or voided"),
            dataMapping: { value: [t("blocked", "sum")] },
          },
          unauthorized: {
            type: TOTAL_ID,
            format: title(
              "Unauthorized captures",
              "Captured with no verified mandate",
            ),
            dataMapping: { value: [t("unauthorized", "sum")] },
          },
          byStatus: {
            type: "donut-chart",
            format: title("Orders by status"),
            dataMapping: {
              categoryKey: [t("status")],
              valueKey: [t("id", "count")],
            },
          },
          byReason: {
            type: "bar-chart-grouped",
            format: title("Blocked attempts by reason code"),
            dataMapping: {
              categoryKey: [t("reason")],
              valueKey: [t("id", "count")],
            },
          },
          funnel: {
            type: FUNNEL_ID,
            format: title("Authorization funnel", "How far each checkout got"),
            dataMapping: {
              stage: [t("funnel_stage")],
              checkouts: [t("id", "count")],
            },
          },
          grid,
          detail: {
            type: DETAIL_ID,
            format: title("Order detail", "Select a row in the grid above"),
            dataMapping: { checkout: [t("id")] },
          },
        },
        widgetLayout: {
          captured: { xTrack: 0, yTrack: 0, xSpan: 6, ySpan: 3 },
          orders: { xTrack: 6, yTrack: 0, xSpan: 6, ySpan: 3 },
          blocked: { xTrack: 12, yTrack: 0, xSpan: 6, ySpan: 3 },
          unauthorized: { xTrack: 18, yTrack: 0, xSpan: 6, ySpan: 3 },
          byStatus: { xTrack: 0, yTrack: 3, xSpan: 6, ySpan: 10 },
          byReason: { xTrack: 6, yTrack: 3, xSpan: 8, ySpan: 10 },
          funnel: { xTrack: 14, yTrack: 3, xSpan: 10, ySpan: 10 },
          grid: { xTrack: 0, yTrack: 13, xSpan: 24, ySpan: 15 },
          detail: { xTrack: 0, yTrack: 28, xSpan: 24, ySpan: 26 },
        },
        filter: {
          widget: {
            byReason: [
              { field: t("blocked"), model: { operator: "equals", value: 1 } },
            ],
          },
        },
      },
    ],
    selectedPageId: "orders",
  };
}

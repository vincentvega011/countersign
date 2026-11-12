// Which order the detail panel shows before anyone clicks a row. The recorded real sandbox capture is
// the best story when it is present; otherwise the newest completed order. A truly empty grid has none,
// and the panel keeps its empty state. The widget cannot take props (Studio builds it), so the choice
// lives here as module state set by the Orders view.
import type { Order } from "./api";

export const RECORDED_CAPTURE = "49029167TJ689282S";

export function pickDefaultOrder(orders: Order[]): string | null {
  const recorded = orders.find(
    (o) => o.capture_id === RECORDED_CAPTURE && o.source === "recorded",
  );
  if (recorded) return recorded.id;
  let newest: Order | null = null;
  for (const o of orders) {
    if (o.status !== "completed") continue;
    if (!newest || o.created_us > newest.created_us) newest = o;
  }
  return newest?.id ?? null;
}

let current: string | null = null;
export const setDefaultOrder = (id: string | null) => {
  current = id;
};
export const getDefaultOrder = () => current;

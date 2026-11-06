// The Protection dashboard on AG Studio: blocked and voided attempts by reason and over time, open
// mandates by state with their ceilings and spend, the authorization funnel, and the attack matrix, all
// over tables loaded from the read API so the cross filters connect them.
import { useCallback, useMemo } from "react";
import { AgStudio, createWidgets } from "ag-studio-react";
import type { EvalCase, EventRow, MandateRow, Order } from "./api";
import { toRow } from "./fields";
import { FUNNEL_ID, funnelDefinition } from "./funnel";
import { ATTACK_MATRIX_ID, attackMatrixDefinition } from "./AttackMatrix";
import { cellRendererFor } from "./renderers";
import {
  attackRows,
  eventRow,
  mandateRow,
  protectionData,
  protectionState,
} from "./protection";
import { buildTheme } from "./theme";

type Props = {
  orders: Order[];
  events: EventRow[];
  mandates: MandateRow[];
  cases: EvalCase[];
};

export function ProtectionStudio({ orders, events, mandates, cases }: Props) {
  const data = useMemo(
    () =>
      protectionData(
        orders.map(toRow),
        events.map(eventRow),
        mandates.map(mandateRow),
        attackRows(cases),
      ),
    [orders, events, mandates, cases],
  );
  const theme = useMemo(() => buildTheme(), []);
  const state = useMemo(() => protectionState(), []);
  const widgets = useCallback(
    (config: { menu: { label: string; widgetIds: readonly string[] }[] }) =>
      createWidgets({
        additionalTypes: [
          funnelDefinition as never,
          attackMatrixDefinition as never,
        ],
        overrides: [
          {
            id: "grid",
            options: { createCellRenderer: cellRendererFor },
          } as never,
        ],
        menu: [
          ...config.menu,
          { label: "Countersign", widgetIds: [FUNNEL_ID, ATTACK_MATRIX_ID] },
        ] as never,
      } as never),
    [],
  );
  return (
    <AgStudio
      data={data as never}
      initialState={state as never}
      mode="view"
      theme={theme as never}
      widgets={widgets as never}
      loadThemeGoogleFonts={false}
      layout={{ columns: 24, rowHeight: 34, minWidth: 720 }}
      panels={{ left: [], right: [] } as never}
      onErrorRaised={(event: unknown) => console.warn("[studio]", event)}
      style={{ height: "100%", width: "100%" }}
    />
  );
}

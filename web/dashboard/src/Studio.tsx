// The Orders dashboard on AG Studio: data through Studio's data source API, the project theme, the
// custom funnel widget, status pill renderers in the grid, and live updates applied as Studio
// transactions when the event stream announces a changed checkout.
import { useCallback, useEffect, useMemo, useRef } from "react";
import { AgStudio, createWidgets } from "ag-studio-react";
import type { AgStudioApi } from "ag-studio";
import { fetchOrders, watchOrders, type Order } from "./api";
import { dataSources, TABLE, toRow } from "./fields";
import { FUNNEL_ID, funnelDefinition } from "./funnel";
import { cellRendererFor } from "./renderers";
import { ordersState } from "./dashboardState";
import { buildTheme } from "./theme";

const PANELS = {
  edit: { left: ["filters"], right: ["edit", "data"] },
  view: { left: [], right: [] },
};

type Props = {
  orders: Order[];
  mode: "view" | "edit";
  grouped: boolean;
  query: string;
  onLive: (count: number) => void;
};

export function OrdersStudio({ orders, mode, grouped, query, onLive }: Props) {
  const api = useRef<AgStudioApi | null>(null);
  const known = useRef(new Set(orders.map((o) => o.id)));
  const data = useMemo(() => dataSources(orders.map(toRow)), [orders]);
  const initialState = useMemo(() => ordersState(grouped), [grouped]);
  const theme = useMemo(() => buildTheme(), []);
  const widgets = useCallback(
    (config: { menu: { label: string; widgetIds: readonly string[] }[] }) =>
      createWidgets({
        additionalTypes: [funnelDefinition as never],
        overrides: [
          {
            id: "grid",
            options: { createCellRenderer: cellRendererFor },
          } as never,
        ],
        menu: [
          ...config.menu,
          { label: "Countersign", widgetIds: [FUNNEL_ID] },
        ] as never,
      } as never),
    [],
  );

  // Live updates: changed rows are fetched by id and applied as one Studio transaction.
  useEffect(() => {
    return watchOrders(async (ids) => {
      const rows = await fetchOrders(ids).catch(() => [] as Order[]);
      const engine = api.current?.getDataEngine();
      if (!rows.length || !engine?.applyTransaction) return;
      const update = rows.filter((r) => known.current.has(r.id)).map(toRow);
      const add = rows.filter((r) => !known.current.has(r.id)).map(toRow);
      for (const r of rows) known.current.add(r.id);
      await engine.applyTransaction({ tableId: TABLE, add, update } as never);
      onLive(rows.length);
    });
  }, [onLive]);

  // The quick filter is a page filter on a hidden text field that joins the searchable columns.
  useEffect(() => {
    const studio = api.current;
    if (!studio) return;
    const state = studio.getState() as unknown as {
      pages: { id: string; filter?: { page?: unknown[]; widget?: unknown } }[];
    };
    const text = query.trim().toLowerCase();
    const pages = state.pages.map((page) => ({
      ...page,
      filter: {
        ...page.filter,
        page: text
          ? [
              {
                field: { id: `${TABLE}.search` },
                model: { operator: "contains", value: text },
              },
            ]
          : [],
      },
    }));
    studio.setState({ ...state, pages } as never);
  }, [query]);

  return (
    <AgStudio
      key={grouped ? "grouped" : "flat"}
      data={data as never}
      initialState={initialState as never}
      mode={mode}
      theme={theme as never}
      widgets={widgets as never}
      loadThemeGoogleFonts={false}
      layout={{ columns: 24, rowHeight: 34, minWidth: 720 }}
      panels={PANELS as never}
      onApiReady={(event: { api: AgStudioApi }) => {
        api.current = event.api;
      }}
      onErrorRaised={(event: unknown) => console.warn("[studio]", event)}
      style={{ height: "100%", width: "100%" }}
    />
  );
}

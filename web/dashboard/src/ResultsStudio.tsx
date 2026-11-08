// The Results view on AG Studio: the frozen full evaluation (eval/reports/latest.json) as totals, charts,
// an ablation table grouped by result, and the targets met or missed. Read only; it reads `latest` and nothing else.
import { useCallback, useMemo } from "react";
import { AgStudio, createWidgets } from "ag-studio-react";
import type { Results } from "./api";
import { totalDefinition } from "./kpi";
import { cellRendererFor } from "./renderers";
import { resultsData, resultsState } from "./results";
import { buildTheme } from "./theme";

export function ResultsStudio({ results }: { results: Results }) {
  const data = useMemo(() => resultsData(results), [results]);
  const theme = useMemo(() => buildTheme(), []);
  const state = useMemo(() => resultsState(results), [results]);
  const widgets = useCallback(
    (config: { menu: { label: string; widgetIds: readonly string[] }[] }) =>
      createWidgets({
        additionalTypes: [totalDefinition as never],
        overrides: [
          {
            id: "grid",
            options: { createCellRenderer: cellRendererFor },
          } as never,
        ],
        menu: config.menu as never,
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

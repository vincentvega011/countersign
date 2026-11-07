// "Total": Countersign's own KPI tile. Studio's value widget shows nothing when its query matches no
// rows, so a tile such as "Unauthorized captures" went blank exactly when the headline claim is 0
// (L61). This widget reads the same aggregated field through Studio's data API, so page filters and
// cross filters still apply, and sums what it gets: no rows is a real 0, computed from the data, never
// a constant. A money variant formats integer minor units with the shared formatter.
import { useEffect, useState } from "react";
import type { AgWidgetParams } from "ag-studio";
import {
  AgIncompleteDataMappingOverlay,
  AgLoadingOverlay,
} from "ag-studio-react";
import { money } from "./format";

export const TOTAL_ID = "countersign-total";
export const TOTAL_MONEY_ID = "countersign-total-money";
const ICON =
  '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" ' +
  'd="M2 3h12v2H2zm0 4h12v2H2zm0 4h8v2H2z"/></svg>';

type Slot = { key: string };

// The sum of one numeric column over the rows Studio returns; no rows and blanks count as 0.
export function totalOf(rows: Record<string, unknown>[], key: string): number {
  let sum = 0;
  for (const row of rows) {
    const n = Number(row[key]);
    if (Number.isFinite(n)) sum += n;
  }
  return sum;
}

function makeWidget(asMoney: boolean) {
  return function TotalWidget(params: AgWidgetParams) {
    const { widgetApi, dataMapping } = params;
    const slot = (dataMapping as Record<string, Slot[] | undefined>).value?.[0];
    const [total, setTotal] = useState<number | null>(null);
    useEffect(() => {
      if (!slot) return;
      let live = true;
      const apply = (response: {
        results: { rows: Record<string, unknown>[] };
      }) => {
        if (live) setTotal(totalOf(response.results.rows, slot.key));
      };
      widgetApi
        .getData(
          { kind: "flat", fields: [slot as never] },
          { queryId: "total", onDataUpdated: apply },
        )
        .then(apply)
        .catch(() => live && setTotal(0));
      return () => {
        live = false;
      };
    }, [widgetApi, slot]);
    if (!slot) return <AgIncompleteDataMappingOverlay />;
    if (total === null) return <AgLoadingOverlay />;
    return (
      <div className="cs-kpi" data-testid="kpi">
        <span className="cs-kpi__value" data-testid="kpi-value">
          {asMoney ? money(total) : total.toLocaleString("en-US")}
        </span>
      </div>
    );
  };
}

const definition = (id: string, label: string, asMoney: boolean) => ({
  id,
  label,
  icon: ICON,
  dataMapping: {
    value: {
      type: "field",
      supportedRoles: ["numeric"],
      required: true,
      aiDescription:
        "The number to total, for example a count of ids or a sum of a 0 or 1 flag. " +
        "Shows 0 when no rows match.",
    },
  },
  form: (p: { createDefaults: (o: unknown) => unknown }) =>
    p.createDefaults({
      supportsCrossHighlight: false,
      dataMappingItems: [{ key: "value", label: "Value" }],
    }),
  comp: makeWidget(asMoney),
  defaultSize: { width: 240, height: 120 },
  minSize: { width: 160, height: 90 },
  featureConfig: { crossFilter: { supportsHighlight: false } },
  ai: {
    description: asMoney
      ? "A money total in integer minor units shown as an amount. Shows 0.00 when no rows match."
      : "A count or total shown as a number. Shows 0 when no rows match.",
  },
});

export const totalDefinition = definition(TOTAL_ID, "Total", false);
export const totalMoneyDefinition = definition(
  TOTAL_MONEY_ID,
  "Money total",
  true,
);

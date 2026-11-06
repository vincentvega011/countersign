// "Attack matrix": a custom AG Studio widget that is Countersign's own. Each attack case from the
// latest evaluation run, side by side under full and baseline mode: whether the attack succeeded, the
// reason code when it was blocked, and the unauthorized captures. Totals sit above the table, and the
// cases that do not separate the two modes are labelled as such. It reads its rows through Studio's
// data API, so a click on a category bar narrows it like any other widget.
import { useEffect, useMemo, useState } from "react";
import type { AgWidgetParams } from "ag-studio";
import {
  AgIncompleteDataMappingOverlay,
  AgLoadingOverlay,
} from "ag-studio-react";
import { Pill } from "./OrderDetail";

export const ATTACK_MATRIX_ID = "attack-matrix";
const ICON =
  '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" ' +
  'd="M1 1h14v14H1zm2 2v4h4V3zm6 0v4h4V3zM3 9v4h4V9zm6 0v4h4V9z"/></svg>';

const SLOTS = {
  attack: "Attack case",
  category: "Category",
  full: "Full mode outcome",
  baseline: "Baseline mode outcome",
  fullReason: "Full reason code",
  baselineReason: "Baseline reason code",
  fullUnauthorized: "Full unauthorized captures",
  baselineUnauthorized: "Baseline unauthorized captures",
  separates: "Separates the modes",
} as const;
type SlotName = keyof typeof SLOTS;
type Slot = { key: string };
type Case = Record<SlotName, string | number | null>;

const outcome = (value: unknown) =>
  value === "success" ? (
    <Pill tone="danger" glyph="!">
      Attack succeeded
    </Pill>
  ) : value === "blocked" ? (
    <Pill tone="success" glyph="✓">
      Blocked
    </Pill>
  ) : (
    <Pill tone="neutral" glyph="?">
      {String(value ?? "no result")}
    </Pill>
  );

export function MatrixView({ cases }: { cases: Case[] }) {
  const count = (mode: "full" | "baseline") =>
    cases.filter((c) => c[mode] === "success").length;
  const unauth = (key: "fullUnauthorized" | "baselineUnauthorized") =>
    cases.reduce((sum, c) => sum + Number(c[key] ?? 0), 0);
  const same = cases.filter((c) => c.full === c.baseline);
  const ordered = [...cases].sort(
    (a, b) =>
      Number(a.full === a.baseline) - Number(b.full === b.baseline) ||
      String(a.attack).localeCompare(String(b.attack)),
  );
  return (
    <div className="cs-detail" data-testid="attack-matrix">
      <p data-testid="matrix-totals">
        <strong>Full mode:</strong>{" "}
        <span data-testid="full-succeeded">{count("full")}</span> of{" "}
        {cases.length} attacks succeeded,{" "}
        <span data-testid="full-unauthorized">
          {unauth("fullUnauthorized")}
        </span>{" "}
        unauthorized captures. <strong>Baseline mode:</strong>{" "}
        <span data-testid="baseline-succeeded">{count("baseline")}</span> of{" "}
        {cases.length} succeeded,{" "}
        <span data-testid="baseline-unauthorized">
          {unauth("baselineUnauthorized")}
        </span>{" "}
        unauthorized captures.
      </p>
      <p className="cs-note" data-testid="matrix-honest">
        {same.length} of {cases.length} cases do not separate the modes: the
        baseline also blocks them, so they show a check that both modes share,
        not an advantage of full mode.
      </p>
      <table className="cs-table" data-testid="matrix-table">
        <thead>
          <tr>
            <th>Attack case</th>
            <th>Category</th>
            <th>Full mode</th>
            <th>Baseline mode</th>
            <th>Reading</th>
          </tr>
        </thead>
        <tbody>
          {ordered.map((c) => (
            <tr
              key={String(c.attack)}
              data-case={String(c.attack)}
              data-separates={String(c.full !== c.baseline)}
            >
              <td className="cs-mono">{String(c.attack)}</td>
              <td className="cs-mono">{String(c.category)}</td>
              <td>
                {outcome(c.full)}{" "}
                <span className="cs-mono">
                  {c.fullReason ? String(c.fullReason) : ""}
                </span>
                {Number(c.fullUnauthorized) > 0
                  ? ` · ${c.fullUnauthorized} unauthorized`
                  : ""}
              </td>
              <td>
                {outcome(c.baseline)}{" "}
                <span className="cs-mono">
                  {c.baselineReason ? String(c.baselineReason) : ""}
                </span>
                {Number(c.baselineUnauthorized) > 0
                  ? ` · ${c.baselineUnauthorized} unauthorized`
                  : ""}
              </td>
              <td>
                {c.full !== c.baseline
                  ? "Separates the modes"
                  : "Does not separate the modes"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AttackMatrixWidget(params: AgWidgetParams) {
  const { widgetApi, dataMapping } = params;
  const slots = dataMapping as Record<string, Slot[] | undefined>;
  const chosen = useMemo(
    () =>
      (Object.keys(SLOTS) as SlotName[]).map(
        (name) => [name, slots[name]?.[0]] as const,
      ),
    [slots],
  );
  const complete = chosen.every(([, slot]) => slot);
  const [cases, setCases] = useState<Case[] | null>(null);

  useEffect(() => {
    if (!complete) return;
    let live = true;
    const fields = chosen.map(([, s]) => s as never);
    const apply = (response: {
      results: { rows: Record<string, unknown>[] };
    }) => {
      if (!live) return;
      setCases(
        response.results.rows.map((row) => {
          const out = {} as Case;
          for (const [name, slot] of chosen)
            out[name] = row[slot!.key] as string | number | null;
          return out;
        }),
      );
    };
    widgetApi
      .getData(
        { kind: "flat", fields },
        { queryId: "cases", onDataUpdated: apply },
      )
      .then(apply)
      .catch(() => live && setCases([]));
    return () => {
      live = false;
    };
  }, [widgetApi, chosen, complete]);

  if (!complete) return <AgIncompleteDataMappingOverlay />;
  if (cases === null) return <AgLoadingOverlay />;
  if (!cases.length)
    return (
      <div className="cs-detail cs-detail--empty" data-testid="matrix-empty">
        <p>
          No evaluation report is available yet. Run the attack suite to fill
          this matrix.
        </p>
      </div>
    );
  return <MatrixView cases={cases} />;
}

export const attackMatrixDefinition = {
  id: ATTACK_MATRIX_ID,
  label: "Attack matrix",
  icon: ICON,
  dataMapping: Object.fromEntries(
    (Object.keys(SLOTS) as SlotName[]).map((name) => [
      name,
      {
        type: "field",
        supportedRoles: name.endsWith("Unauthorized")
          ? ["numeric"]
          : ["category"],
        required: true,
        aiDescription: SLOTS[name],
      },
    ]),
  ),
  form: (p: { createDefaults: (o: unknown) => unknown }) =>
    p.createDefaults({
      supportsCrossHighlight: false,
      dataMappingItems: (Object.keys(SLOTS) as SlotName[]).map((name) => ({
        key: name,
        label: SLOTS[name],
      })),
    }),
  comp: AttackMatrixWidget,
  defaultSize: { width: 860, height: 520 },
  minSize: { width: 520, height: 300 },
  featureConfig: { crossFilter: { supportsHighlight: false } },
  ai: {
    description:
      "Every attack case of the latest evaluation, with whether it succeeded under full mode and under " +
      "baseline mode, the reason code, the unauthorized captures, and which cases do not separate the modes.",
  },
};

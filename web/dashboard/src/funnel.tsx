// "Authorization funnel": a custom AG Studio widget that is Countersign's own. It shows how far each
// agent checkout got through the chain of proof (checkout, mandate presented, mandate verified,
// authorized at PayPal, captured after the gate), with the drop at every step. It reads a numeric
// "furthest step" field and a checkout count through Studio's data API, so page filters and cross
// filters from the other widgets apply to it, and clicking a step cross-filters the rest of the
// dashboard to the checkouts that stopped at that step.
import { useEffect, useMemo, useState } from "react";
import type { AgWidgetParams } from "ag-studio";
import {
  AgIncompleteDataMappingOverlay,
  AgLoadingOverlay,
} from "ag-studio-react";

export const FUNNEL_ID = "authorization-funnel";
const FUNNEL_ICON =
  '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" ' +
  'd="M1 2h14v2H1zm2 4h10v2H3zm2 4h6v2H5zm2 4h2v1H7z"/></svg>';

export const STEPS = [
  { label: "Checkout created", hint: "the agent opened a checkout" },
  { label: "Mandate presented", hint: "the agent sent signed mandates" },
  {
    label: "Mandate verified",
    hint: "Merchant and Credential Provider accepted them",
  },
  { label: "Authorized at PayPal", hint: "PayPal held the money" },
  {
    label: "Captured after the gate",
    hint: "live PayPal state matched the signed checkout",
  },
] as const;

type Counts = { all: number[]; shown: number[] | null };
type Slot = { key: string };

// Rows are one per furthest step with its checkout count; a checkout that reached step k counts for
// every step up to k.
function reached(
  rows: Record<string, unknown>[],
  stage: string,
  value: string,
): number[] {
  const stopped = STEPS.map(() => 0);
  for (const row of rows) {
    const at = Number(row[stage]);
    const n = Number(row[value]);
    if (
      Number.isInteger(at) &&
      at >= 0 &&
      at < STEPS.length &&
      Number.isFinite(n)
    )
      stopped[at] += n;
  }
  return STEPS.map((_, i) => stopped.slice(i).reduce((a, b) => a + b, 0));
}

export function FunnelWidget(params: AgWidgetParams) {
  const { widgetApi, dataMapping } = params;
  const slots = dataMapping as Record<string, Slot[] | undefined>;
  const stage = slots.stage?.[0];
  const value = slots.checkouts?.[0];
  const [counts, setCounts] = useState<Counts | null>(null);
  const selected = useMemo(() => {
    const found = widgetApi
      .getCrossFilterSelections()
      ?.find((s) => s.type === "value");
    return found && found.type === "value" && found.values.length === 1
      ? Number(found.values[0])
      : null;
  }, [widgetApi, counts]);

  useEffect(() => {
    if (!stage || !value) return;
    let live = true;
    const apply = (response: {
      results: { rows: Record<string, unknown>[] };
      crossFilter?: { rows: Record<string, unknown>[] };
    }) => {
      if (!live) return;
      setCounts({
        all: reached(response.results.rows, stage.key, value.key),
        shown: response.crossFilter
          ? reached(response.crossFilter.rows, stage.key, value.key)
          : null,
      });
    };
    widgetApi
      .getData(
        { kind: "flat", fields: [stage as never, value as never] },
        { queryId: "stages", crossFilter: "highlight", onDataUpdated: apply },
      )
      .then(apply)
      .catch(() => live && setCounts({ all: STEPS.map(() => 0), shown: null }));
    return () => {
      live = false;
    };
  }, [widgetApi, stage, value]);

  if (!stage || !value) return <AgIncompleteDataMappingOverlay />;
  if (counts === null) return <AgLoadingOverlay />;
  const values = counts.shown ?? counts.all;
  const top = Math.max(values[0], 1);
  // Clicking a step cross-filters the dashboard to the checkouts that stopped there.
  const toggle = (step: number) => {
    if (selected === step) widgetApi.resetCrossFilter();
    else
      widgetApi.toggleCrossFilter({
        type: "value",
        field: stage as never,
        value: String(step),
        group: 0,
        reset: true,
      });
  };
  return (
    <ol
      className="cs-funnel"
      aria-label="Authorization funnel"
      data-testid="funnel"
    >
      {STEPS.map((step, i) => {
        const count = values[i];
        const previous = i === 0 ? count : values[i - 1];
        const dropped = previous - count;
        const share = Math.round((count / top) * 1000) / 10;
        return (
          <li key={step.label} className="cs-funnel__step">
            <button
              type="button"
              className="cs-funnel__button"
              aria-pressed={selected === i}
              onClick={() => toggle(i)}
              title={`Show checkouts that stopped at: ${step.label}`}
              data-testid={`funnel-step-${i}`}
            >
              <span className="cs-funnel__label">
                <span className="cs-funnel__index">{i + 1}</span>
                {step.label}
              </span>
              <span className="cs-funnel__bar" aria-hidden="true">
                <span
                  className="cs-funnel__fill"
                  style={{ width: `${(count / top) * 100}%` }}
                />
              </span>
              <span
                className="cs-funnel__value"
                data-testid={`funnel-value-${i}`}
              >
                {count.toLocaleString("en-US")}
              </span>
              <span className="cs-funnel__meta">
                {share}% of checkouts
                {i > 0 && dropped > 0
                  ? ` · ${dropped.toLocaleString("en-US")} stopped before`
                  : ""}
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

export const funnelDefinition = {
  id: FUNNEL_ID,
  label: "Authorization funnel",
  icon: FUNNEL_ICON,
  dataMapping: {
    stage: {
      type: "field",
      supportedRoles: ["category"],
      required: true,
      aiDescription:
        "The furthest step a checkout reached, 0 (created) to 4 (captured)",
    },
    checkouts: {
      type: "field",
      supportedRoles: ["numeric"],
      required: true,
      aiDescription:
        "The number of checkouts, for example a count of the checkout id",
    },
  },
  form: (p: { createDefaults: (o: unknown) => unknown }) =>
    p.createDefaults({
      supportsCrossHighlight: true,
      dataMappingItems: [
        { key: "stage", label: "Furthest step (0 to 4)" },
        { key: "checkouts", label: "Checkouts" },
      ],
    }),
  comp: FunnelWidget,
  defaultSize: { width: 520, height: 320 },
  minSize: { width: 320, height: 260 },
  featureConfig: { crossFilter: { supportsHighlight: true } },
  ai: {
    description:
      "How far agent checkouts got through Countersign's chain of proof: created, mandate " +
      "presented, mandate verified, authorized at PayPal, captured after the capture gate.",
  },
};

// The Results view's data: small tables built from the frozen full evaluation (`results` in
// eval/reports/latest.json, served read only by /api/dashboard/eval), and the pre-composed Studio state.
// Nothing is typed in here: every number comes from the report, and a tile over no rows reads 0.
import type { Results } from "./api";
import type { Row } from "./fields";
import { TOTAL_ID } from "./kpi";

const t = (table: string, id: string, aggregation?: string) =>
  aggregation
    ? { id: `${table}.${id}`, aggregation }
    : { id: `${table}.${id}` };
const title = (text: string, subtitle?: string) => ({
  title: { text, enabled: true },
  ...(subtitle ? { subtitle: { text: subtitle, enabled: true } } : {}),
});
const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
const ms = (x: number) => `${x.toFixed(1)} ms`;

const int = (id: string, name: string) =>
  ({ id, name, format: "integerFormat" }) as const;
const text = (id: string, name: string, low = false) =>
  ({
    id,
    name,
    format: "textFormat",
    ...(low ? { cardinality: "low" } : { cardinality: "high" }),
  }) as const;

export function modeRows(r: Results): Row[] {
  const row = (mode: "full" | "baseline"): Row => ({
    id: mode,
    unauthorized_captures:
      r.attacks[mode].unauthorized_captures +
      r.adversary[mode].unauthorized_captures +
      r.tasks[mode].unauthorized_captures,
    attacks_succeeded: r.attacks[mode].attacks_succeeded,
    goals_succeeded: r.adversary[mode].attacks_succeeded,
    duplicates:
      r.attacks[mode].duplicate_paypal_objects +
      r.adversary[mode].duplicate_paypal_objects +
      r.tasks[mode].duplicate_paypal_objects,
    false_blocks: r.tasks[mode].false_blocks,
    captures: r.evidence[mode].captures,
    verified_bundles: r.evidence[mode].both_pass,
    without_bundle: r.evidence[mode].captures_without_bundle,
  });
  return [row("full"), row("baseline")];
}
export const MODE_FIELDS = [
  text("id", "Mode", true),
  int("unauthorized_captures", "Unauth. captures"),
  int("attacks_succeeded", "Attacks succeeded"),
  int("goals_succeeded", "Goals succeeded"),
  int("duplicates", "Dup. objects"),
  int("false_blocks", "False blocks"),
  int("captures", "Captures"),
  int("verified_bundles", "With bundle"),
  int("without_bundle", "No bundle"),
] as const; // prettier-ignore

export const ablationRows = (r: Results): Row[] =>
  r.ablations.map((a) => ({
    id: a.flag,
    reopened_count: a.reopened_count,
    reopens: a.reopened_count ? a.reopened : "Nothing",
    unauthorized_captures: a.unauthorized_captures,
    duplicates: a.duplicate_paypal_objects,
    another_defense: a.another_defense,
    verdict:
      a.reopened_count === 0
        ? "Reopens nothing"
        : `Reopens ${a.reopened_count}`,
    note: a.note,
  }));
export const ABLATION_FIELDS = [
  text("id", "Ablation"),
  int("reopened_count", "Cases reopened"),
  text("reopens", "Reopened cases"),
  int("unauthorized_captures", "Unauth. captures"),
  int("duplicates", "Dup. objects"),
  int("another_defense", "Other defense"),
  text("verdict", "Result", true),
  text("note", "Note"),
] as const; // prettier-ignore

// A chart axis clips a long label at its left edge at 1280 px wide; cut it at the end with an ellipsis instead.
export const shortLabel = (id: string, max = 24): string =>
  id.length > max ? `${id.slice(0, max - 1)}…` : id;

export const categoryRows = (r: Results): Row[] =>
  r.categories.map((c) => ({
    id: c.category,
    label: shortLabel(c.category),
    cases: c.cases,
    full_succeeded: c.full_succeeded,
    baseline_succeeded: c.baseline_succeeded,
  }));
export const CATEGORY_FIELDS = [
  text("id", "Category"),
  text("label", "Category (chart)"),
  int("cases", "Cases"),
  int("full_succeeded", "Succeeded in full"),
  int("baseline_succeeded", "Succeeded in baseline"),
] as const; // prettier-ignore

export const targetRows = (r: Results): Row[] =>
  r.targets.map((x, i) => ({
    id: String(i + 1).padStart(2, "0"),
    target: x.target,
    status: x.status === "met" ? "Met" : "Missed",
    met: x.status === "met" ? 1 : 0,
    one: 1,
    evidence: x.evidence,
  }));
export const TARGET_FIELDS = [
  text("id", "No."),
  text("target", "Target"),
  text("status", "Status", true),
  int("met", "Met"),
  text("evidence", "Numbers from the report"),
  int("one", "Targets"),
] as const; // prettier-ignore

export const latencyRows = (r: Results): Row[] =>
  (["full", "baseline"] as const).map((m) => ({
    id: m,
    calls: r.tasks[m].stage_calls,
    p50: ms(r.tasks[m].stage_p50_ms),
    p95: ms(r.tasks[m].stage_p95_ms),
    completion: pct(r.tasks[m].completion_rate),
    false_block_rate: pct(r.tasks[m].false_block_rate),
    runs: r.tasks[m].runs,
  }));
export const LATENCY_FIELDS = [
  text("id", "Mode", true),
  int("runs", "Task runs"),
  text("completion", "Completion rate"),
  text("false_block_rate", "False block rate"),
  int("calls", "Capture stage calls"),
  text("p50", "Capture stage p50 (simulator)"),
  text("p95", "Capture stage p95 (simulator)"),
] as const; // prettier-ignore

export function resultsData(r: Results) {
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
      table("modes", "Totals per mode", modeRows(r), MODE_FIELDS),
      // One row, so a tile totals full mode alone (a tile over "modes" would add baseline in).
      table(
        "full_mode",
        "Full mode",
        modeRows(r).filter((x) => x.id === "full"),
        MODE_FIELDS,
      ),
      table("ablations", "Ablations", ablationRows(r), ABLATION_FIELDS),
      table(
        "categories",
        "Attack categories",
        categoryRows(r),
        CATEGORY_FIELDS,
      ),
      table("targets", "Targets", targetRows(r), TARGET_FIELDS),
      table("latency", "Tasks and latency", latencyRows(r), LATENCY_FIELDS),
    ],
    relationships: [],
  };
}

export function resultsState(r: Results) {
  const full = (id: string) => t("full_mode", id, "sum");
  return {
    pages: [
      {
        id: "results",
        widgets: {
          unauth: {
            type: TOTAL_ID,
            format: title(
              "Unauthorized captures",
              `Full mode. Baseline: ${r.attacks.baseline.unauthorized_captures + r.adversary.baseline.unauthorized_captures + r.tasks.baseline.unauthorized_captures}`,
            ),
            dataMapping: { value: [full("unauthorized_captures")] },
          },
          succeeded: {
            type: TOTAL_ID,
            format: title(
              "Attack cases that succeeded",
              `Full mode, of ${r.attacks.full.cases}. Baseline: ${r.attacks.baseline.attacks_succeeded}`,
            ),
            dataMapping: { value: [full("attacks_succeeded")] },
          },
          duplicates: {
            type: TOTAL_ID,
            format: title("Duplicate PayPal objects", "Full mode"),
            dataMapping: { value: [full("duplicates")] },
          },
          falseBlocks: {
            type: TOTAL_ID,
            format: title(
              "False blocks",
              `Legitimate purchases blocked, of ${r.tasks.full.runs} runs`,
            ),
            dataMapping: { value: [full("false_blocks")] },
          },
          byCategory: {
            type: "bar-chart-grouped",
            format: title(
              "Attack cases that succeeded, by category",
              r.categories.every((c) => c.full_succeeded === 0)
                ? "Bars are baseline; full is 0 in every category"
                : "Baseline against full",
            ),
            dataMapping: {
              categoryKey: [t("categories", "label")],
              valueKey: [
                t("categories", "baseline_succeeded", "sum"),
                t("categories", "full_succeeded", "sum"),
              ],
            },
          },
          byAblation: {
            type: "bar-chart-grouped",
            format: title(
              "Attack cases reopened, by ablation",
              "One protection off at a time, in full mode",
            ),
            dataMapping: {
              categoryKey: [t("ablations", "id")],
              valueKey: [t("ablations", "reopened_count", "sum")],
            },
          },
          ablationGrid: {
            type: "pivot-grid",
            format: title(
              "Ablations",
              "Grouped by result; a zero is a real result",
            ),
            dataMapping: {
              rows: [t("ablations", "verdict"), t("ablations", "id")],
              columns: [],
              values: [
                t("ablations", "reopened_count", "sum"),
                t("ablations", "unauthorized_captures", "sum"),
                t("ablations", "duplicates", "sum"),
                t("ablations", "another_defense", "sum"),
              ],
            },
          },
          targetGrid: {
            type: "pivot-grid",
            format: title("Targets", "Met or missed, from the report"),
            dataMapping: {
              rows: [t("targets", "status"), t("targets", "target")],
              columns: [],
              values: [t("targets", "one", "sum")],
            },
          },
          modes: {
            type: "grid",
            format: title("Totals per mode", "Full against baseline"),
            dataMapping: {
              cols: [
                "id",
                "unauthorized_captures",
                "attacks_succeeded",
                "goals_succeeded",
                "duplicates",
                "false_blocks",
                "captures",
                "verified_bundles",
                "without_bundle",
              ].map((c) => t("modes", c)),
            },
          },
          latency: {
            type: "grid",
            format: title(
              "Legitimate tasks and capture stage time",
              "Time is over the PayPal simulator, not live PayPal",
            ),
            dataMapping: {
              cols: [
                "id",
                "runs",
                "completion",
                "false_block_rate",
                "calls",
                "p50",
                "p95",
              ].map((c) => t("latency", c)),
            },
          },
        },
        widgetLayout: {
          unauth: { xTrack: 0, yTrack: 0, xSpan: 6, ySpan: 3 },
          succeeded: { xTrack: 6, yTrack: 0, xSpan: 6, ySpan: 3 },
          duplicates: { xTrack: 12, yTrack: 0, xSpan: 6, ySpan: 3 },
          falseBlocks: { xTrack: 18, yTrack: 0, xSpan: 6, ySpan: 3 },
          modes: { xTrack: 0, yTrack: 3, xSpan: 24, ySpan: 6 },
          byCategory: { xTrack: 0, yTrack: 9, xSpan: 12, ySpan: 14 },
          byAblation: { xTrack: 12, yTrack: 9, xSpan: 12, ySpan: 14 },
          ablationGrid: { xTrack: 0, yTrack: 23, xSpan: 24, ySpan: 12 },
          latency: { xTrack: 0, yTrack: 35, xSpan: 24, ySpan: 6 },
          targetGrid: { xTrack: 0, yTrack: 41, xSpan: 24, ySpan: 16 },
        },
      },
    ],
    selectedPageId: "results",
  };
}

// Cell renderers for the orders grid: status, mandate state and data source as pills with the shared
// UI's glyphs and tones, so no state depends on colour alone. Values arrive as fixed labels.
import type { AgWidgetCustomCellRendererProps } from "ag-studio-react";
import { TONE_VARS } from "./theme";

type Pill = { tone: keyof typeof TONE_VARS; glyph: string };

const STATUS: Record<string, Pill> = {
  Ready: { tone: "info", glyph: "○" },
  Incomplete: { tone: "neutral", glyph: "○" },
  "In progress": { tone: "warning", glyph: "◐" },
  Completed: { tone: "success", glyph: "✓" },
  Canceled: { tone: "neutral", glyph: "✕" },
  Rejected: { tone: "danger", glyph: "!" },
  Voided: { tone: "neutral", glyph: "⊘" },
};
const MANDATE: Record<string, Pill> = {
  Verified: { tone: "success", glyph: "✓" },
  Refused: { tone: "danger", glyph: "!" },
  "Not presented": { tone: "neutral", glyph: "–" },
};
const SOURCE: Record<string, Pill> = {
  Sandbox: { tone: "accent", glyph: "●" },
  Recorded: { tone: "info", glyph: "◆" },
  Simulated: { tone: "warning", glyph: "◇" },
  Unlabelled: { tone: "neutral", glyph: "?" },
};

const MANDATE_STATE: Record<string, Pill> = {
  Unused: { tone: "info", glyph: "○" },
  "In flight": { tone: "warning", glyph: "◐" },
  Used: { tone: "success", glyph: "✓" },
  Revoked: { tone: "danger", glyph: "⊘" },
  Expired: { tone: "neutral", glyph: "–" },
};

function pill(table: Record<string, Pill>, testid: string) {
  return function PillCell(props: AgWidgetCustomCellRendererProps) {
    const value = typeof props.value === "string" ? props.value : null;
    if (value === null) return null;
    const info = table[value] ?? { tone: "neutral", glyph: "·" };
    const [fg, bg] = TONE_VARS[info.tone];
    return (
      <span
        className="cs-cell-pill"
        style={{ color: fg, background: bg }}
        data-testid={testid}
      >
        <span aria-hidden="true">{info.glyph}</span>
        {value}
      </span>
    );
  };
}

// Long text cells are capped so the grid's auto sizing measures a bounded width, then truncate with
// an ellipsis and carry the full value as a tooltip. Items gets the most room; the grid scales the
// columns up to fill the width, so the grid fits without sideways scrolling.
const CAPS: Record<string, number> = {
  items: Math.max(90, Math.min(300, innerWidth - 1250)),
  id: 100,
  customer: 95,
  agent: 110,
  capture_id: 85,
  reason: 130,
  gate: 100,
};
function truncated(name: string) {
  return function TruncCell(props: AgWidgetCustomCellRendererProps) {
    const value = props.valueFormatted ?? props.value;
    if (value === null || value === undefined || value === "") return null;
    const text = String(value);
    return (
      <span
        className="cs-cell-trunc"
        style={{ maxWidth: CAPS[name] }}
        title={text}
      >
        {text}
      </span>
    );
  };
}

// Dates read "9 Nov 2026, 18:20" (UTC, see format.ts); the floor keeps a two digit day from clipping.
function TimeCell(props: AgWidgetCustomCellRendererProps) {
  const text = props.valueFormatted ?? "";
  return text ? <span className="cs-cell-time">{text}</span> : null;
}

const RENDERERS: Record<string, ReturnType<typeof pill>> = {
  created: TimeCell,
  at: TimeCell,
  expires: TimeCell,
  ...Object.fromEntries(Object.keys(CAPS).map((n) => [n, truncated(n)])),
  status: pill(STATUS, "cell-status"),
  mandate: pill(MANDATE, "cell-mandate"),
  source: pill(SOURCE, "cell-source"),
  state: pill(MANDATE_STATE, "cell-state"),
};

export function cellRendererFor(field: {
  fieldId?: string;
  key?: string;
  rootFieldId?: string;
}) {
  const id = String(field.rootFieldId ?? field.fieldId ?? field.key ?? "");
  const name = id.includes(".") ? id.slice(id.lastIndexOf(".") + 1) : id;
  return RENDERERS[name];
}

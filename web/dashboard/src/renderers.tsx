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

const RENDERERS: Record<string, ReturnType<typeof pill>> = {
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

// The Assistant view: Studio's own assistant panel docked on the right, over the orders grid so a
// citation has something to point at. The panel and chat are Studio's; the agent is ours (assistant.tsx).
import { useEffect, useMemo, useState } from "react";
import { AgStudio, createWidgets } from "ag-studio-react";
import {
  fetchSuggestions,
  type AssistantCite,
  type Order,
  type Suggestion,
} from "./api";
import { dataSources, toRow } from "./fields";
import { cellRendererFor } from "./renderers";
import {
  ASSISTANT_NOTE,
  LOOKUP_TOOL,
  REPLAY_NOTE,
  citeHref,
  harnessFor,
} from "./assistant";
import { buildTheme } from "./theme";

const KIND_LABEL: Record<AssistantCite["kind"], string> = {
  order: "Order",
  evidence_step: "Evidence step",
  eval_case: "Evaluation",
  log: "Log entry",
  mandate: "Mandate",
  code: "Code",
};

function Chip({ cite }: { cite: AssistantCite }) {
  const href = citeHref(cite);
  const body = (
    <>
      <span className="cs-chip__kind">{KIND_LABEL[cite.kind]}</span>{" "}
      {cite.label}
    </>
  );
  return href ? (
    <a
      className="cs-chip"
      href={href}
      target="_blank"
      rel="noopener"
      data-testid="cite-chip"
      data-kind={cite.kind}
      data-id={cite.id}
    >
      {body}
    </a>
  ) : (
    <span
      className="cs-chip"
      data-testid="cite-chip"
      data-kind={cite.kind}
      data-id={cite.id}
    >
      {body}
    </span>
  );
}

// The expanded body of the lookup step: every line of the answer with the sources it came from.
export function LookupDetail(params: {
  status: string;
  result?: { success: boolean; data?: unknown };
}) {
  const data = params.result?.success
    ? (params.result.data as {
        lines: { text: string; cites: AssistantCite[] }[];
        replaced: number;
      })
    : undefined;
  if (!data) return null;
  return (
    <ul className="cs-sources" data-testid="sources">
      {data.lines.map((line, i) => (
        <li key={i} className="cs-sources__line">
          <span className="cs-sources__text">{line.text}</span>
          {line.cites.length > 0 && (
            <span className="cs-sources__chips">
              {line.cites.map((c, j) => (
                <Chip key={`${c.kind}-${c.id}-${c.step ?? ""}-${j}`} cite={c} />
              ))}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

export function AssistantStudio({
  orders,
  dark,
}: {
  orders: Order[];
  dark: boolean;
}) {
  const [suggestions, setSuggestions] = useState<{
    mode: string;
    list: Suggestion[];
  } | null>(null);
  useEffect(() => {
    fetchSuggestions()
      .then((s) => setSuggestions({ mode: s.mode, list: s.suggestions }))
      .catch(() => setSuggestions({ mode: "disabled", list: [] }));
  }, []);
  const data = useMemo(() => dataSources(orders.map(toRow)), [orders]);
  const theme = useMemo(() => buildTheme(), [dark]);
  const ai = useMemo(
    () => (suggestions ? harnessFor(suggestions.list) : null),
    [suggestions],
  );
  const state = useMemo(
    () => ({
      pages: [
        {
          id: "assistant",
          widgets: {
            grid: {
              type: "grid",
              format: {
                title: { text: "Agent orders", enabled: true },
                style: { columnAutoSize: true },
              },
              dataMapping: {
                cols: [
                  "created",
                  "id",
                  "status",
                  "amount_minor",
                  "mandate",
                  "gate",
                  "reason",
                ].map((c) => ({ id: `orders.${c}` })),
              },
              sort: [{ field: { id: "orders.created" }, direction: "desc" }],
            },
          },
          widgetLayout: {
            grid: { xTrack: 0, yTrack: 0, xSpan: 24, ySpan: 22 },
          },
        },
      ],
      selectedPageId: "assistant",
    }),
    [],
  );
  const widgets = useMemo(
    () =>
      createWidgets({
        overrides: [
          {
            id: "grid",
            options: { createCellRenderer: cellRendererFor },
          } as never,
        ],
      } as never),
    [],
  );
  if (!suggestions || !ai) return null;
  return (
    <section
      className="cs-assistant"
      aria-label="Ask Countersign"
      data-testid="assistant"
    >
      <div className="cs-assistant__bar">
        <h1 className="cs-title">Ask Countersign</h1>
        <p className="cs-muted" data-testid="assistant-note">
          {ASSISTANT_NOTE}
        </p>
        {suggestions.mode === "replay" && (
          <p className="cs-muted" data-testid="assistant-replay-note">
            {REPLAY_NOTE}
          </p>
        )}
      </div>
      <div
        className="cs-studio cs-studio--assistant"
        data-testid="assistant-studio"
      >
        <AgStudio
          data={data as never}
          initialState={state as never}
          mode="edit"
          theme={theme as never}
          widgets={widgets as never}
          loadThemeGoogleFonts={false}
          layout={{ columns: 24, rowHeight: 34, minWidth: 560 }}
          panels={{ edit: { left: [], right: ["ai"] } } as never}
          ai={ai as never}
          aiToolDisplay={
            {
              [LOOKUP_TOOL]: {
                label: ({ status }: { status: string }) => ({
                  text:
                    status === "done"
                      ? "Sources for this answer"
                      : "Looking up the data",
                  pill: "read only",
                }),
                detail: LookupDetail,
              },
            } as never
          }
          onErrorRaised={(event: unknown) => console.warn("[studio]", event)}
          style={{ height: "100%", width: "100%" }}
        />
      </div>
    </section>
  );
}

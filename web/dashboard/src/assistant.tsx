// Ask Countersign on the Studio Agent Framework: a Custom Runner that sends the question to the read-only
// assistant endpoint and plays the server's templated, cited answer back as AG-UI events. The model
// (server side) only chooses which lookups to run; this runner has no model, no tools, no data access of
// its own and never reads Studio's AI context, so nothing from the page goes anywhere but the question.
import { createAiHarness } from "ag-studio";
import type { AgAiPromptStarter } from "ag-studio";
import {
  askAssistant,
  type AssistantAnswer,
  type AssistantCite,
  type Suggestion,
} from "./api";

export const AGENT_ID = "ask-countersign";
export const LOOKUP_TOOL = "countersign_lookup";
export const ASSISTANT_NOTE =
  "Answers are generated from data with fixed templates. The model only chooses what to look up.";
export const REPLAY_NOTE =
  "This demo replays recorded questions; pick a suggestion.";

type Event = Record<string, unknown>;
const id = () => crypto.randomUUID();

// A citation chip's target: the Orders view filtered to the order, the Evidence view, or none.
export function citeHref(c: AssistantCite): string | null {
  const safe = encodeURIComponent(c.id);
  if (c.kind === "order") return `#/orders/${safe}`;
  if (c.kind === "evidence_step") return `#/evidence/${safe}`;
  if (c.kind === "mandate" || c.kind === "eval_case") return "#/protection";
  return null;
}

// Studio renders message text as Markdown: escape it so identifiers such as mandate_expired and amounts
// show literally.
export const escapeMarkdown = (text: string) =>
  text.replace(/([\\`*_{}\[\]()#+!|<>~])/g, "\\$1");

function lastQuestion(messages: { role: string; content?: string }[]): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m.role === "user" && typeof m.content === "string") return m.content;
  }
  return "";
}

async function* run(
  input: { threadId: string; runId: string; messages: never[] },
  ctx: { signal?: AbortSignal },
): AsyncGenerator<Event> {
  const { threadId, runId } = input;
  yield { type: "RUN_STARTED", threadId, runId };
  let answer: AssistantAnswer;
  try {
    answer = (await askAssistant(lastQuestion(input.messages), ctx.signal))
      .answer;
  } catch {
    yield { type: "RUN_ERROR", message: "The assistant could not be reached." };
    return;
  }
  if (answer.calls.length) {
    // Shown as a read-only "lookup" step whose detail lists the sources of each line.
    const toolCallId = id();
    yield { type: "TOOL_CALL_START", toolCallId, toolCallName: LOOKUP_TOOL };
    yield {
      type: "TOOL_CALL_ARGS",
      toolCallId,
      delta: JSON.stringify({ calls: answer.calls }),
    };
    yield { type: "TOOL_CALL_END", toolCallId };
    yield {
      type: "TOOL_CALL_RESULT",
      messageId: id(),
      toolCallId,
      content: JSON.stringify({
        success: true,
        response: `${answer.calls.length} read-only lookups`,
        data: { lines: answer.lines, replaced: answer.replaced },
      }),
    };
  }
  const messageId = id();
  yield { type: "TEXT_MESSAGE_START", messageId, role: "assistant" };
  yield {
    type: "TEXT_MESSAGE_CONTENT",
    messageId,
    delta: answer.lines.map((l) => escapeMarkdown(l.text)).join("\n\n"),
  };
  yield { type: "TEXT_MESSAGE_END", messageId };
  yield { type: "RUN_FINISHED", threadId, runId };
}

export function harnessFor(suggestions: Suggestion[]) {
  const starters: AgAiPromptStarter[] = suggestions.map((s) => ({
    label: s.label,
    prompt: s.question,
  }));
  return ({ api }: { api: unknown }) =>
    createAiHarness(api as never, () => ({
      agents: [
        {
          id: AGENT_ID,
          name: "Ask Countersign",
          description:
            "Read-only questions about orders, protection, evidence and evaluation.",
          schema: (s: { undefined: () => unknown }) => s.undefined(),
          instructions: () => "",
          tools: () => [],
          run: run as never,
        },
      ] as never,
      primary: AGENT_ID,
      promptStarters: starters,
    }));
}

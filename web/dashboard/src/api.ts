// The dashboard's only way to the backend: GET requests to the versioned read API on this origin,
// and one Server-Sent Events stream. No write call exists here (the API has none).

export type Source = "live_sandbox" | "recorded" | "simulator" | "unlabelled";

export interface Order {
  id: string;
  created_at: string;
  created_us: number;
  updated_us: number;
  agent: string | null;
  customer_id: string | null;
  items: string;
  amount_minor: number;
  currency: string;
  status: string;
  mandate: string;
  protocol: string;
  gate: string | null;
  refusal: string | null;
  capture_id: string | null;
  source: Source;
  funnel_stage: number;
  captured_minor: number;
  blocked: number;
  reason: string | null;
  unauthorized: number;
}

export interface Status {
  version: number;
  app_env: string;
  mode: string;
  protection: "full" | "baseline";
  ablations: string[];
  paypal_sandbox_configured: boolean;
  data_source: Source;
  ucp_profile_url: string;
  read_only: boolean;
  login: boolean;
}

export const API = "/dashboard/api/v1";

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  });
  if (!response.ok) throw new Error(`request failed: ${response.status}`);
  const body = (await response.json()) as { version?: number } & T;
  if (body.version !== 1) throw new Error("unsupported API version");
  return body;
}

export const fetchStatus = () => getJson<Status>("/status");

export async function fetchOrders(ids?: string[]): Promise<Order[]> {
  const query = ids ? `?ids=${ids.map(encodeURIComponent).join(",")}` : "";
  return (await getJson<{ orders: Order[] }>(`/orders${query}`)).orders;
}

// Announces checkouts that changed; the caller fetches those rows. Reconnects on its own.
export function watchOrders(onChanged: (ids: string[]) => void): () => void {
  const source = new EventSource(`${API}/stream`);
  source.addEventListener("orders", (event) => {
    try {
      const body = JSON.parse((event as MessageEvent<string>).data) as {
        version: number;
        ids: unknown;
      };
      if (body.version !== 1 || !Array.isArray(body.ids)) return;
      onChanged(body.ids.filter((id): id is string => typeof id === "string"));
    } catch {
      // A malformed announcement is ignored; the next one carries the newest ids.
    }
  });
  return () => source.close();
}

export interface Detail {
  version: number;
  checkout_id: string;
  order: Order;
  state: "bundle" | "simulated" | "unmandated" | "missing" | "not_captured";
  bundle_text: string | null;
}
export const fetchDetail = (id: string) =>
  getJson<Detail>(`/orders/${encodeURIComponent(id)}/detail`);

export interface MandateRow {
  id: string;
  customer_id: string;
  agent: string;
  state: string;
  ceiling_minor: number;
  spent_minor: number;
  currency: string;
  expires_at: string;
  created_at: string;
  source: string;
}
export const fetchMandates = async () =>
  (await getJson<{ mandates: MandateRow[] }>("/mandates")).mandates;

export interface EventRow {
  seq: number;
  at: string;
  checkout_id: string | null;
  stage: string;
  outcome: string;
  reason: string;
  source: string;
}
export const fetchEvents = async () =>
  (await getJson<{ events: EventRow[] }>("/events")).events;

export interface EvalCase {
  case: string;
  category: string;
  mode: "full" | "baseline";
  outcome: string;
  reason_code: string | null;
  unauthorized_captures: number;
  captured_minor: number;
}
export interface EvalSummary {
  suite: string;
  generated_at: string | null;
  modes: Record<string, Record<string, number>>;
  cases: EvalCase[];
}
export const fetchEval = async () =>
  (await getJson<{ eval: EvalSummary | null }>("/eval")).eval;

export interface Sample {
  name: string;
  label: string;
  bundle_text: string;
  pinned: { merchant: object; platform: object } | null;
  expected_first_failure: string | null;
}
export const fetchSamples = async () =>
  (await getJson<{ samples: { name: string; label: string }[] }>("/samples"))
    .samples;
export const fetchSample = (name: string) =>
  getJson<Sample>(`/samples/${encodeURIComponent(name)}`);

// The one fetch that is not under the read API: the stored bundle, by capture id.
export async function fetchBundleText(captureId: string): Promise<string> {
  const response = await fetch(`/evidence/${encodeURIComponent(captureId)}`, {
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
  });
  if (!response.ok) throw new Error(`no bundle: ${response.status}`);
  return response.text();
}

export interface PolicyView {
  snapshot: {
    protection: {
      mode: string;
      ablations: string[];
      merchant_lock: {
        version: number;
        mode: string;
        threshold_minor: number | null;
        currency: string | null;
      };
    };
    constraint_families: { checkout: string[]; payment: string[] };
    capture_gate_steps: { code: string; check: string }[];
    dashboard: { read_only: boolean; write_endpoints: number; login: boolean };
    not_enabled: { id: string; label: string; status: string; note?: string }[];
  };
  sha256: string;
}
export const fetchPolicy = async () => getJson<PolicyView>("/policy");

export interface AssistantCite {
  kind: "order" | "evidence_step" | "eval_case" | "log" | "mandate" | "code";
  id: string;
  label: string;
  step: string | null;
}
export interface AssistantLine {
  text: string;
  cites: AssistantCite[];
}
export interface AssistantAnswer {
  status: "answered" | "unsupported" | "replay_only" | "unavailable";
  text: string;
  lines: AssistantLine[];
  calls: { tool: string; args: Record<string, unknown> }[];
  replaced: number;
}
export interface Suggestion {
  label: string;
  question: string;
}
export const fetchSuggestions = async () =>
  getJson<{ mode: string; suggestions: Suggestion[] }>(
    "/assistant/suggestions",
  );
export const askAssistant = async (q: string, signal?: AbortSignal) => {
  const response = await fetch(
    `/dashboard/api/v1/assistant/ask?q=${encodeURIComponent(q)}`,
    { headers: { Accept: "application/json" }, signal },
  );
  if (!response.ok) throw new Error(`ask failed (${response.status})`);
  return (await response.json()) as { mode: string; answer: AssistantAnswer };
};

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

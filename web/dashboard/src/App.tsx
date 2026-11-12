// The merchant dashboard shell: navigation, theme toggle, the mode and environment label, the
// Onboarding status and the Orders view on AG Studio. Everything shown here is read from the
// dashboard read API; nothing in this app can change a credential, a mode or a payment.
import { useCallback, useEffect, useState } from "react";
import { AgStudioProvider } from "ag-studio-react";
import { AgStudioAiModule } from "ag-studio";
import {
  fetchEvents,
  fetchEval,
  fetchMandates,
  fetchOrders,
  fetchResults,
  fetchStatus,
  type EvalCase,
  type EventRow,
  type MandateRow,
  type Order,
  type Results,
  type Status,
} from "./api";
import { OrdersStudio } from "./Studio";
import { ProtectionStudio } from "./ProtectionStudio";
import { ResultsStudio } from "./ResultsStudio";
import { EvidenceView } from "./Evidence";
import { PolicyView_ } from "./Policy";
import { AssistantStudio } from "./AssistantStudio";
import { SOURCE_LABEL, formatDateTime } from "./format";
import { applyScheme, initialScheme, remember, type Scheme } from "./theme";

const LICENSE = __AG_STUDIO_LICENSE_KEY__ || undefined;

const VIEWS = [
  { id: "orders", label: "Orders" },
  { id: "protection", label: "Protection" },
  { id: "results", label: "Results" },
  { id: "evidence", label: "Evidence" },
  { id: "policy", label: "Policy" },
  { id: "assistant", label: "Assistant" },
  { id: "onboarding", label: "Onboarding" },
] as const;
type View = (typeof VIEWS)[number]["id"];

// "#/evidence/<checkout id>" opens the Evidence view on that order.
const parts = () => location.hash.replace(/^#\/?/, "").split("/");
const viewFromHash = (): View =>
  (VIEWS.find((v) => v.id === parts()[0])?.id ?? "orders") as View;
const orderFromHash = (): string =>
  parts()[0] === "orders" && parts()[1] ? decodeURIComponent(parts()[1]) : "";
const evidenceFromHash = (): string | null =>
  parts()[0] === "evidence" && parts()[1]
    ? decodeURIComponent(parts()[1])
    : null;

export function App() {
  const [scheme, setScheme] = useState<Scheme>(initialScheme);
  const [view, setView] = useState<View>(viewFromHash);
  const [evidenceId, setEvidenceId] = useState<string | null>(evidenceFromHash);
  const [protection, setProtection] = useState<{
    events: EventRow[];
    mandates: MandateRow[];
    cases: EvalCase[];
  } | null>(null);
  const [results, setResults] = useState<Results | null | undefined>(undefined);
  const [status, setStatus] = useState<Status | null>(null);
  const [orders, setOrders] = useState<Order[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [mode, setMode] = useState<"view" | "edit">("view");
  const [grouped, setGrouped] = useState(false);
  const [query, setQuery] = useState(() => orderFromHash().toLowerCase());
  const [live, setLive] = useState<{ at: Date; count: number } | null>(null);

  useEffect(() => applyScheme(scheme), [scheme]);
  useEffect(() => {
    const onHash = () => {
      setView(viewFromHash());
      setEvidenceId(evidenceFromHash());
      const order = orderFromHash();
      if (order) setQuery(order.toLowerCase());
    };
    addEventListener("hashchange", onHash);
    return () => removeEventListener("hashchange", onHash);
  }, []);
  useEffect(() => {
    Promise.all([fetchStatus(), fetchOrders()])
      .then(([s, o]) => {
        setStatus(s);
        setOrders(o);
      })
      .catch(() => setFailed(true));
  }, []);
  useEffect(() => {
    if (view !== "protection" || protection) return;
    Promise.all([fetchEvents(), fetchMandates(), fetchEval()])
      .then(([events, mandates, evaluation]) =>
        setProtection({ events, mandates, cases: evaluation?.cases ?? [] }),
      )
      .catch(() => setFailed(true));
  }, [view, protection]);
  useEffect(() => {
    if (view !== "results" || results !== undefined) return;
    fetchResults()
      .then(setResults)
      .catch(() => setFailed(true));
  }, [view, results]);
  const onLive = useCallback(
    (count: number) => setLive({ at: new Date(), count }),
    [],
  );
  const toggleScheme = () => {
    const next = scheme === "dark" ? "light" : "dark";
    remember(next);
    setScheme(next);
  };
  const canEdit = status !== null && !status.read_only;

  return (
    <AgStudioProvider licenseKey={LICENSE} modules={[AgStudioAiModule]}>
      <div className="cs-shell">
        <header className="cs-top">
          <div className="cs-brand">
            <span className="cs-brand__mark" aria-hidden="true">
              ✓
            </span>
            <span className="cs-brand__name">Countersign</span>
            <span className="cs-brand__sub">Merchant dashboard</span>
          </div>
          <div className="cs-top__labels" data-testid="env-label">
            <span className="cs-tag cs-tag--warning">
              Sandbox demo · simulated and recorded data is labelled
            </span>
            {status && (
              <>
                <span className="cs-tag" data-testid="mode-label">
                  Protection: {status.protection}
                </span>
                <span className="cs-tag" data-testid="appenv-label">
                  APP_ENV {status.app_env}
                </span>
              </>
            )}
          </div>
          <button
            type="button"
            className="cs-iconbtn"
            onClick={toggleScheme}
            aria-label={
              scheme === "dark" ? "Use light theme" : "Use dark theme"
            }
            data-testid="theme-toggle"
          >
            {scheme === "dark" ? "☀" : "☾"}
          </button>
        </header>
        <nav className="cs-nav" aria-label="Dashboard">
          {VIEWS.map((v) => (
            <a
              key={v.id}
              href={`#/${v.id}`}
              className="cs-nav__item"
              aria-current={view === v.id ? "page" : undefined}
            >
              {v.label}
            </a>
          ))}
        </nav>
        <main className="cs-main" id="main">
          {failed && (
            <p className="cs-notice cs-notice--danger" role="alert">
              The dashboard could not reach its data. Reload to try again.
            </p>
          )}
          {view === "orders" && orders && (
            <section className="cs-orders" aria-labelledby="orders-title">
              <div className="cs-toolbar">
                <h1 id="orders-title" className="cs-title">
                  Agent orders
                </h1>
                <label className="cs-search">
                  <span className="cs-visually-hidden">Search orders</span>
                  <input
                    type="search"
                    placeholder="Search orders"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    data-testid="quick-filter"
                  />
                </label>
                <label className="cs-switch">
                  <input
                    type="checkbox"
                    checked={grouped}
                    onChange={(e) => setGrouped(e.target.checked)}
                    data-testid="group-toggle"
                  />
                  Group by agent and customer
                </label>
                {canEdit && (
                  <label className="cs-switch">
                    <input
                      type="checkbox"
                      checked={mode === "edit"}
                      onChange={(e) =>
                        setMode(e.target.checked ? "edit" : "view")
                      }
                      data-testid="edit-toggle"
                    />
                    Edit layout
                  </label>
                )}
                <span
                  className="cs-live"
                  data-testid="live-indicator"
                  aria-live="polite"
                >
                  <span className="cs-live__dot" aria-hidden="true" />
                  {live
                    ? `Live · ${live.count} updated ${live.at.toLocaleTimeString()}`
                    : "Live"}
                </span>
              </div>
              <div className="cs-studio" data-testid="studio">
                <OrdersStudio
                  orders={orders}
                  mode={mode}
                  grouped={grouped}
                  query={query}
                  onLive={onLive}
                />
              </div>
            </section>
          )}
          {view === "onboarding" && <Onboarding status={status} />}
          {view === "evidence" && orders && (
            <EvidenceView
              key={evidenceId ?? "none"}
              orders={orders}
              initial={evidenceId}
            />
          )}
          {view === "protection" && orders && protection && (
            <section className="cs-protection" aria-label="Protection activity">
              <div className="cs-studio" data-testid="protection-studio">
                <ProtectionStudio orders={orders} {...protection} />
              </div>
            </section>
          )}
          {view === "results" && results === null && (
            <p className="cs-notice" data-testid="results-empty">
              No full evaluation has been run yet. Run{" "}
              <code>
                python -m eval.run --suite all --mode both --seeds 0,1,2
              </code>
              .
            </p>
          )}
          {view === "results" && results && (
            <section className="cs-protection" aria-label="Evaluation results">
              <p className="cs-muted" data-testid="results-meta">
                Run {results.run_id} · generated{" "}
                {formatDateTime(results.generated_at)} UTC · seeds{" "}
                {results.seeds.join(", ")} · simulator, not live PayPal. Read
                only.
              </p>
              <p className="cs-muted" data-testid="results-note">
                Simulator captures carry no evidence bundle, so the bundle
                columns read 0 there; the recorded sandbox capture is verified
                separately (see Targets).
              </p>
              <div className="cs-studio" data-testid="results-studio">
                <ResultsStudio results={results} />
              </div>
            </section>
          )}
          {view === "policy" && <PolicyView_ />}
          {view === "assistant" && orders && (
            <AssistantStudio orders={orders} dark={scheme === "dark"} />
          )}
        </main>
      </div>
    </AgStudioProvider>
  );
}

function Onboarding({ status }: { status: Status | null }) {
  const [profile, setProfile] = useState<
    "unknown" | "ok" | "failed" | "checking"
  >("unknown");
  if (!status) return null;
  const testProfile = async () => {
    setProfile("checking");
    try {
      const response = await fetch("/.well-known/ucp", {
        headers: { Accept: "application/json" },
      });
      const body = (await response.json()) as Record<string, unknown>;
      const text = JSON.stringify(body);
      setProfile(
        response.ok && text.includes("dev.ucp.common.payment.ap2_mandate")
          ? "ok"
          : "failed",
      );
    } catch {
      setProfile("failed");
    }
  };
  const step = (
    n: number,
    title: string,
    done: boolean,
    body: React.ReactNode,
  ) => (
    <li className="cs-step" data-done={done}>
      <span className="cs-step__n" aria-hidden="true">
        {done ? "✓" : n}
      </span>
      <div>
        <h2 className="cs-step__title">{title}</h2>
        {body}
      </div>
    </li>
  );
  return (
    <section
      className="cs-card cs-onboarding"
      aria-labelledby="onb-title"
      data-testid="onboarding"
    >
      <h1 id="onb-title" className="cs-title">
        Onboarding
      </h1>
      <p className="cs-muted">
        {status.read_only
          ? "Read only in this deployment: a public demo does not let visitors change credentials or the protection mode."
          : "Development: change these through the environment (.env) and restart; the dashboard has no settings form."}
      </p>
      <ol className="cs-steps">
        {step(
          1,
          "PayPal sandbox app",
          status.paypal_sandbox_configured,
          <p data-testid="onb-paypal">
            {status.paypal_sandbox_configured ? "Configured" : "Not configured"}{" "}
            · data source{" "}
            {SOURCE_LABEL[status.data_source] ?? status.data_source}
          </p>,
        )}
        {step(
          2,
          "Protection mode",
          status.protection === "full",
          <p data-testid="onb-mode">
            {status.protection === "full"
              ? "Full: mandate verification, principal lock and the capture gate are on."
              : "Baseline: evaluation only, protections are off on purpose."}
          </p>,
        )}
        {step(
          3,
          "UCP profile published",
          profile === "ok",
          <p>
            <a href={status.ucp_profile_url} data-testid="onb-profile">
              {status.ucp_profile_url}
            </a>{" "}
            <button
              type="button"
              className="cs-btn"
              onClick={testProfile}
              data-testid="onb-test"
            >
              Test profile
            </button>{" "}
            <span data-testid="onb-profile-result">
              {profile === "ok" &&
                "Profile found with the AP2 mandates capability."}
              {profile === "failed" &&
                "The profile could not be read or lacks AP2."}
              {profile === "checking" && "Checking…"}
            </span>
          </p>,
        )}
      </ol>
    </section>
  );
}

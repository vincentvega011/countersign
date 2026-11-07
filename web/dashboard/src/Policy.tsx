// The Policy panel: the active policy as the server reports it, read only, with the SHA-256 of its
// canonical form. Nothing here edits anything; the page says so in fixed words.
import { useEffect, useState } from "react";
import { fetchPolicy, type PolicyView } from "./api";
import { money } from "./format";

export const POLICY_NOTE =
  "This panel is read only. The policy cannot be edited or versioned from the dashboard.";

export function PolicyView_() {
  const [view, setView] = useState<PolicyView | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    fetchPolicy()
      .then(setView)
      .catch(() => setFailed(true));
  }, []);
  if (failed)
    return (
      <p className="cs-notice cs-notice--danger" role="alert">
        The policy could not be read. Reload to try again.
      </p>
    );
  if (!view) return null;
  const s = view.snapshot;
  const lock = s.protection.merchant_lock;
  const lockText =
    lock.mode === "off"
      ? "Off: protection is required only for agents that negotiated AP2"
      : lock.mode === "all"
        ? "Require AP2 mandates for all agents"
        : `Require AP2 mandates over ${money(lock.threshold_minor, lock.currency ?? "USD")}`;
  return (
    <section
      className="cs-card cs-policy"
      data-testid="policy"
      aria-labelledby="pol-title"
    >
      <h1 id="pol-title" className="cs-title">
        Policy
      </h1>
      <p className="cs-muted" data-testid="policy-note">
        {POLICY_NOTE}
      </p>
      <p>
        Policy hash (SHA-256 of the canonical snapshot){" "}
        <code className="cs-hash" data-testid="policy-hash">
          {view.sha256}
        </code>
      </p>
      <h2 className="cs-step__title">Protection mode</h2>
      <p data-testid="policy-mode">
        {s.protection.mode === "full"
          ? "Full: mandate verification, principal lock and the capture gate are on."
          : "Baseline: evaluation only, protections are off on purpose."}{" "}
        Merchant lock: {lockText}.
      </p>
      <h2 className="cs-step__title">Constraint types the verifier enforces</h2>
      <ul className="cs-list">
        {[
          ...s.constraint_families.checkout,
          ...s.constraint_families.payment,
        ].map((c) => (
          <li key={c}>
            <code>{c}</code>
          </li>
        ))}
      </ul>
      <h2 className="cs-step__title">Capture gate steps</h2>
      <ol className="cs-list" data-testid="policy-gate">
        {s.capture_gate_steps.map((g) => (
          <li key={g.code}>
            <code>{g.code}</code> {g.check}
          </li>
        ))}
      </ol>
      <h2 className="cs-step__title">Dashboard and API</h2>
      <p>
        Read only: {s.dashboard.write_endpoints} write endpoints, no merchant
        login.
      </p>
      <h2 className="cs-step__title">Not enabled</h2>
      <ul className="cs-list" data-testid="policy-not-enabled">
        {s.not_enabled.map((n) => (
          <li key={n.id}>
            {n.label}: {n.status}
            {n.note ? ` (${n.note})` : ""}
          </li>
        ))}
      </ul>
    </section>
  );
}

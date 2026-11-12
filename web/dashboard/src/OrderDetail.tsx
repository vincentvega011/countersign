// "Order detail": a custom AG Studio widget (Studio's grid has no master and detail). It follows the
// orders grid through Studio's cross filter: clicking a grid row narrows the cross filtered rows to
// that one checkout, and this widget then asks the read API for that order's stored evidence and shows
// four panels, checked in the browser by the same verifier modules as /verify/.
//
// Everything that came from a bundle or a row (item titles, customer and agent ids, claim values,
// PayPal fields) is rendered as React text. There is no dangerouslySetInnerHTML anywhere in this app.
import { useEffect, useMemo, useState, type ReactNode } from "react";
import type { AgWidgetParams } from "ag-studio";
import { AgIncompleteDataMappingOverlay } from "ag-studio-react";
import { fetchDetail, type Detail } from "./api";
import { describe, type Check, type DetailModel } from "./evidenceModel";
import { groupFingerprint } from "./fingerprint";
import { formatDateTime, money } from "./format";
import { getDefaultOrder } from "./defaultOrder";

export const DETAIL_ID = "order-detail";
const DETAIL_ICON =
  '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" ' +
  'd="M2 1h12v14H2zm2 2v2h8V3zm0 4v1h8V7zm0 3v1h8v-1zm0 3v1h5v-1z"/></svg>';

export const NO_EVIDENCE: Record<Detail["state"], string> = {
  bundle: "",
  simulated: "No evidence bundle: simulated",
  unmandated: "No evidence bundle: captured with no mandate (baseline)",
  missing: "Bundle missing",
  not_captured: "No evidence bundle: nothing was captured",
};

type Tone = "success" | "danger" | "warning" | "info" | "neutral";
export function Pill({
  tone,
  glyph,
  children,
  testid,
}: {
  tone: Tone;
  glyph: string;
  children: ReactNode;
  testid?: string;
}) {
  return (
    <span className="cs-pill" data-tone={tone} data-testid={testid}>
      <span className="cs-pill__glyph" aria-hidden="true">
        {glyph}
      </span>
      {children}
    </span>
  );
}
export const Ok = ({ yes, testid }: { yes: boolean; testid?: string }) =>
  yes ? (
    <Pill tone="success" glyph="✓" testid={testid}>
      Verified
    </Pill>
  ) : (
    <Pill tone="danger" glyph="!" testid={testid}>
      Failed
    </Pill>
  );

const fail = (c: Check) =>
  c.ok ? null : <span className="cs-mono"> {c.code}</span>;
const compact = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v));

// Times in claims (epoch seconds under iat, exp, nbf, or ISO strings) read "9 Nov 2026, 18:20 UTC".
const EPOCH_KEYS = new Set(["iat", "exp", "nbf"]);
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d/;
function shown(key: string, v: unknown): string {
  if (EPOCH_KEYS.has(key) && typeof v === "number" && Number.isSafeInteger(v))
    return `${formatDateTime(v * 1000)} UTC`;
  if (typeof v === "string" && ISO.test(v) && formatDateTime(v))
    return `${formatDateTime(v)} UTC`;
  return compact(v);
}

function Kv({ rows }: { rows: [string, unknown][] }) {
  return (
    <dl className="cs-kv">
      {rows.map(([k, v]) => (
        <div key={k} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{shown(k, v)}</dd>
        </div>
      ))}
    </dl>
  );
}

type Json = Record<string, unknown>;
const obj = (v: unknown): Json =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : {};

function CheckoutPanel({ m }: { m: DetailModel }) {
  const auth = m.merchantAuthorization;
  const checkout = m.checkout.ok ? m.checkout.value : null;
  const currency =
    typeof checkout?.currency === "string" ? checkout.currency : "USD";
  const lines = Array.isArray(checkout?.line_items)
    ? (checkout!.line_items as unknown[])
    : [];
  const totals = Array.isArray(checkout?.totals)
    ? (checkout!.totals as unknown[])
    : [];
  return (
    <section
      className="cs-panel"
      data-testid="panel-checkout"
      aria-labelledby="p1"
    >
      <h3 id="p1">1. Signed checkout</h3>
      <p>
        Merchant authorization:{" "}
        {auth ? (
          <Pill
            tone={auth.ok ? "success" : "danger"}
            glyph={auth.ok ? "✓" : "!"}
            testid="merchant-auth"
          >
            {auth.ok ? "Signature and hash verify" : `Failed: ${auth.code}`}
          </Pill>
        ) : null}
      </p>
      {!checkout ? (
        <p data-testid="checkout-unreadable">
          The signed checkout could not be verified{fail(m.checkout)}
        </p>
      ) : (
        <>
          <Kv
            rows={[
              ["Checkout id", checkout.id],
              ["Currency", checkout.currency],
              ["Status", checkout.status],
            ]}
          />
          <table className="cs-table" data-testid="checkout-lines">
            <thead>
              <tr>
                <th>Item</th>
                <th className="cs-num">Qty</th>
                <th className="cs-num">Unit</th>
              </tr>
            </thead>
            <tbody>
              {lines.map((line, i) => {
                const l = obj(line);
                const item = obj(l.item);
                return (
                  <tr key={i}>
                    <td>{String(item.title ?? "")}</td>
                    <td className="cs-num">{String(l.quantity ?? "")}</td>
                    <td className="cs-num">{money(item.price, currency)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <h4>Totals (integer minor units, formatted)</h4>
          <table className="cs-table" data-testid="checkout-totals">
            <tbody>
              {totals.map((t, i) => (
                <tr key={i}>
                  <td>{String(obj(t).type ?? "")}</td>
                  <td className="cs-num" data-minor={String(obj(t).amount)}>
                    {money(obj(t).amount, currency)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}

function MandatesPanel({ m }: { m: DetailModel }) {
  const consent = m.consent;
  const terms = obj(consent.record?.terms);
  return (
    <section
      className="cs-panel"
      data-testid="panel-mandates"
      aria-labelledby="p2"
    >
      <h3 id="p2">2. Mandates and consent</h3>
      {m.mandates.map((md) => (
        <div key={md.title} data-testid="mandate">
          <h4>{md.title}</h4>
          <ul className="cs-timeline">
            <li>
              <span className="cs-label">
                Open mandate, signed by the platform:
              </span>{" "}
              <Ok yes={md.open.ok} testid="link-open" />
              {fail(md.open)}
            </li>
            <li>
              <span className="cs-label">
                Closed mandate, signed by the agent key the open one names:
              </span>{" "}
              <Ok yes={md.closed.ok} testid="link-closed" />
              {fail(md.closed)}
            </li>
          </ul>
          {md.open.ok && (
            <>
              <Kv
                rows={Object.entries(md.open.value.claims).filter(
                  ([k]) => k !== "constraints" && k !== "cnf",
                )}
              />
              <h4>Constraints the customer signed</h4>
              <ul className="cs-timeline" data-testid="constraints">
                {md.open.value.constraints.map((c, i) => (
                  <li key={i} className="cs-mono">
                    {compact(c)}
                  </li>
                ))}
              </ul>
            </>
          )}
          {md.closed.ok && (
            <>
              <h4>Closed mandate claims (disclosures used)</h4>
              <Kv rows={Object.entries(md.closed.value.claims)} />
            </>
          )}
        </div>
      ))}
      <h4>Device consent</h4>
      <p>
        {consent.step && (
          <Pill
            tone={consent.step.ok ? "success" : "danger"}
            glyph={consent.step.ok ? "✓" : "!"}
            testid="consent-check"
          >
            {consent.step.ok
              ? "Device signature verifies"
              : `Failed: ${consent.step.code}`}
          </Pill>
        )}
      </p>
      <Kv
        rows={[
          ["Customer", consent.customer],
          [
            "Device key",
            consent.device
              ? groupFingerprint(consent.device.slice(0, 16)).join(" ")
              : "unreadable",
          ],
          ...Object.entries(terms).map(([k, v]) => [k, v] as [string, unknown]),
        ]}
      />
    </section>
  );
}

function PaypalPanel({ m }: { m: DetailModel }) {
  return (
    <section
      className="cs-panel cs-panel--wide"
      data-testid="panel-paypal"
      aria-labelledby="p3"
    >
      <h3 id="p3">3. PayPal objects</h3>
      <p className="cs-note" data-testid="paypal-label">
        As fetched at capture time and stored in the evidence bundle. Not live:
        this dashboard has no PayPal credentials and never calls PayPal.
      </p>
      <table className="cs-table cs-table--pp" data-testid="paypal-table">
        <thead>
          <tr>
            <th>Object</th>
            <th>Field</th>
            <th>Stored at PayPal</th>
            <th>Re-derived from the signed checkout</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {m.paypal.rows.map((r) => (
            <tr
              key={`${r.label}.${r.field}`}
              data-differs={String(r.differs)}
              data-field={`${r.label}.${r.field}`}
            >
              <td data-label="Object" className="cs-name">
                {r.label}
              </td>
              <td data-label="Field" className="cs-name">
                {r.field}
              </td>
              <td data-label="Stored at PayPal" className="cs-mono cs-value">
                {r.found}
              </td>
              <td
                data-label="Re-derived from the signed checkout"
                className="cs-mono cs-value"
              >
                {r.expected}
              </td>
              <td data-label="Result">
                {r.differs ? (
                  <Pill tone="danger" glyph="!">
                    Differs
                  </Pill>
                ) : (
                  <Pill tone="success" glyph="✓">
                    Matches
                  </Pill>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function GatePanel({ m }: { m: DetailModel }) {
  return (
    <section className="cs-panel" data-testid="panel-gate" aria-labelledby="p4">
      <h3 id="p4">4. Capture gate and decision log</h3>
      <ol className="cs-timeline" data-testid="gate-timeline">
        {m.gate.map((g) => {
          const passed = g.outcomes.length === 1 && g.outcomes[0] === "pass";
          return (
            <li key={g.code} data-gate={g.code} data-passed={String(passed)}>
              {passed ? (
                <Pill tone="success" glyph="✓">
                  Pass
                </Pill>
              ) : (
                <Pill tone="danger" glyph="!">
                  {g.outcomes.length ? g.outcomes.join(", ") : "Not logged"}
                </Pill>
              )}
              <span className="cs-mono">{g.code}</span>
            </li>
          );
        })}
      </ol>
      <h4>Linked decision log entries</h4>
      <p className="cs-note" data-testid="log-note">
        These checks show the entries hash, chain and are included in the stated
        root. They are consistency checks: the root is not anchored anywhere
        else (L48).
      </p>
      <ul className="cs-timeline" data-testid="log-entries">
        {m.log.rows.map((r) => (
          <li key={r.seq}>
            <Ok yes={r.proof.ok} />
            <span className="cs-mono">
              #{r.seq} {r.kind}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function DetailBody({ detail }: { detail: Detail }) {
  const [model, setModel] = useState<DetailModel | "error" | null>(null);
  useEffect(() => {
    let live = true;
    setModel(null);
    if (detail.state !== "bundle" || detail.bundle_text === null) return;
    describe(detail.bundle_text)
      .then((m) => live && setModel(m))
      .catch(() => live && setModel("error"));
    return () => {
      live = false;
    };
  }, [detail]);
  const order = detail.order;
  const source = {
    live_sandbox: "Sandbox",
    recorded: "Recorded",
    simulator: "Simulated",
    unlabelled: "Unlabelled",
  }[order.source];
  return (
    <div
      className="cs-detail"
      data-testid="order-detail"
      data-checkout={order.id}
    >
      <div className="cs-detail__head">
        <h2 className="cs-detail__title" data-testid="detail-title">
          {order.id}
        </h2>
        <Pill
          tone={order.source === "live_sandbox" ? "info" : "warning"}
          glyph="●"
          testid="detail-source"
        >
          {source}
        </Pill>
        {detail.state === "bundle" && (
          <a
            href={`#/evidence/${encodeURIComponent(order.id)}`}
            data-testid="open-evidence"
          >
            Open in the Evidence view
          </a>
        )}
        <span data-testid="detail-summary">
          {order.status} · {money(order.amount_minor, order.currency)} ·{" "}
          {order.items}
        </span>
      </div>
      {detail.state !== "bundle" ? (
        <p
          className="cs-notice"
          data-testid="no-evidence"
          data-state={detail.state}
        >
          {NO_EVIDENCE[detail.state]}
        </p>
      ) : model === null ? (
        <p>Checking the bundle in this browser…</p>
      ) : model === "error" ? (
        <p
          className="cs-notice cs-notice--danger"
          data-testid="bundle-unreadable"
        >
          The stored bundle could not be read.
        </p>
      ) : (
        <div className="cs-detail__grid">
          <CheckoutPanel m={model} />
          <MandatesPanel m={model} />
          <PaypalPanel m={model} />
          <GatePanel m={model} />
        </div>
      )}
    </div>
  );
}

type Slot = { key: string };

export function OrderDetailWidget(params: AgWidgetParams) {
  const { widgetApi, dataMapping } = params;
  const slot = (dataMapping as Record<string, Slot[] | undefined>)
    .checkout?.[0];
  const [picked, setSelected] = useState<string | null>(null);
  // Until a row is chosen the panel shows the default order, so it is never a blank box.
  const fallback = getDefaultOrder();
  const selected = picked ?? fallback;
  const [detail, setDetail] = useState<Detail | "error" | null>(null);

  useEffect(() => {
    if (!slot) return;
    let live = true;
    const apply = (response: {
      crossFilter?: { rows: Record<string, unknown>[] };
    }) => {
      if (!live) return;
      const rows = response.crossFilter?.rows ?? [];
      const id = rows.length === 1 ? rows[0][slot.key] : null;
      setSelected(typeof id === "string" ? id : null);
    };
    widgetApi
      .getData(
        { kind: "flat", fields: [slot as never] },
        { queryId: "selected", crossFilter: "highlight", onDataUpdated: apply },
      )
      .then(apply)
      .catch(() => live && setSelected(null));
    return () => {
      live = false;
    };
  }, [widgetApi, slot]);

  useEffect(() => {
    setDetail(null);
    if (!selected) return;
    let live = true;
    fetchDetail(selected)
      .then((d) => live && setDetail(d))
      .catch(() => live && setDetail("error"));
    return () => {
      live = false;
    };
  }, [selected]);

  const body = useMemo(() => {
    if (!slot) return null;
    if (!selected)
      return (
        <div className="cs-detail cs-detail--empty" data-testid="detail-empty">
          <p>
            Select an order in the grid to see its signed checkout, mandates,
            stored PayPal objects and gate timeline.
          </p>
        </div>
      );
    if (detail === null)
      return (
        <div className="cs-detail">
          <p>Loading…</p>
        </div>
      );
    if (detail === "error")
      return (
        <div className="cs-detail">
          <p className="cs-notice cs-notice--danger" role="alert">
            This order could not be loaded.
          </p>
        </div>
      );
    return (
      <>
        {picked === null && (
          <p className="cs-muted cs-detail__hint" data-testid="detail-default">
            Showing a default order. Select a row in the grid to change it.
          </p>
        )}
        <DetailBody detail={detail} />
      </>
    );
  }, [slot, selected, picked, detail]);
  if (!slot) return <AgIncompleteDataMappingOverlay />;
  return body;
}

export const orderDetailDefinition = {
  id: DETAIL_ID,
  label: "Order detail",
  icon: DETAIL_ICON,
  dataMapping: {
    checkout: {
      type: "field",
      supportedRoles: ["category"],
      required: true,
      aiDescription: "The checkout id of the order selected in the orders grid",
    },
  },
  form: (p: { createDefaults: (o: unknown) => unknown }) =>
    p.createDefaults({
      supportsCrossHighlight: true,
      dataMappingItems: [{ key: "checkout", label: "Checkout id" }],
    }),
  comp: OrderDetailWidget,
  defaultSize: { width: 900, height: 620 },
  minSize: { width: 420, height: 320 },
  featureConfig: { crossFilter: { supportsHighlight: true } },
  ai: {
    description:
      "The selected agent order in full: the merchant-signed checkout, the open and closed mandates with " +
      "the device consent, the PayPal objects stored at capture time next to the terms re-derived from " +
      "the signed checkout, and the capture gate timeline with decision log entries.",
  },
};

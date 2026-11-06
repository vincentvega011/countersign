// The Evidence view: pick an order and press Verify evidence to run the browser verifier (the same
// modules, step names and wording as /verify/) on its stored bundle, download that bundle, load a
// bundle file from disk, or try one of a few committed tampered samples. Nothing here decides anything
// for the merchant: it shows what the verifier found. All bundle content is rendered as text.
import { useEffect, useRef, useState } from "react";
import {
  fetchBundleText,
  fetchDetail,
  fetchSample,
  fetchSamples,
  type Order,
  type Sample,
} from "./api";
import { NO_EVIDENCE, Pill } from "./OrderDetail";
import type { StepResult } from "./evidenceModel";
import { money } from "./format";
import { verifyText } from "../../ui/evidence/verify.js";
import { STEP_TEXT, TEXT } from "../../verify/verify-text.js";

type Source = {
  label: string;
  text: string;
  pinned: { merchant: object; platform: object } | null;
  captureId: string | null;
  expectedFirstFailure?: string | null;
};
type Copy = Record<string, { title: string; explains: string }>;
const STEPS = STEP_TEXT as Copy;
const T = TEXT as unknown as {
  passed: string;
  failed: string;
  why: string;
  code: string;
  firstFailure: string;
  notPinned: string;
  allPassed: string;
  allPassedBody: string;
  onlyKeysBody: string;
  failedAt: string;
  failedAtBody: (title: string) => string;
};

export function Results({
  results,
  pinned,
}: {
  results: StepResult[];
  pinned: boolean;
}) {
  const failed = results.filter((r) => !r.ok);
  const onlyUnpinned =
    failed.length === 1 &&
    failed[0].name === "trusted_keys" &&
    failed[0].code === "keys_not_pinned";
  const state =
    failed.length === 0 ? "passed" : onlyUnpinned ? "unpinned" : "failed";
  const first = failed[0];
  const body =
    state === "passed"
      ? T.allPassedBody
      : state === "unpinned"
        ? T.onlyKeysBody
        : T.failedAtBody(STEPS[first.name]?.title ?? first.name);
  return (
    <div data-testid="evidence-result">
      <section
        className="cs-panel"
        data-state={state}
        data-testid="summary"
        data-first-failure={first ? first.name : ""}
        data-pinned={String(pinned)}
      >
        <Pill
          tone={
            state === "passed"
              ? "success"
              : state === "unpinned"
                ? "warning"
                : "danger"
          }
          glyph={state === "failed" ? "!" : "✓"}
        >
          {state === "passed"
            ? T.passed
            : state === "unpinned"
              ? T.notPinned
              : T.failed}
        </Pill>
        <h3 data-testid="summary-title">
          {state === "failed" ? T.failedAt : T.allPassed}
        </h3>
        <p>{body}</p>
      </section>
      <ol className="cs-evsteps" data-testid="steps">
        {results.map((r) => {
          const text = STEPS[r.name];
          return (
            <li
              key={r.name}
              className="cs-evstep"
              data-step={r.name}
              data-ok={String(r.ok)}
              data-testid="step"
            >
              <div>
                <Pill
                  tone={r.ok ? "success" : "danger"}
                  glyph={r.ok ? "✓" : "!"}
                  testid="step-status"
                >
                  {r.ok ? T.passed : T.failed}
                </Pill>{" "}
                {r === first && (
                  <Pill tone="danger" glyph="!">
                    {T.firstFailure}
                  </Pill>
                )}
              </div>
              <h4>{text?.title ?? r.name}</h4>
              <p className="cs-muted">{text?.explains ?? ""}</p>
              {!r.ok && (
                <p>
                  <span className="cs-note">{T.why}: </span>
                  <span data-testid="step-message">{r.message}</span>{" "}
                  <span className="cs-note">{T.code}: </span>
                  <code className="cs-mono" data-testid="step-code">
                    {r.code}
                  </code>
                </p>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export function EvidenceView({
  orders,
  initial,
}: {
  orders: Order[];
  initial: string | null;
}) {
  const choices = orders
    .filter((o) => o.capture_id && o.gate === "passed")
    .slice(0, 300);
  const [selected, setSelected] = useState<string>(initial ?? "");
  const [source, setSource] = useState<Source | null>(null);
  const [message, setMessage] = useState("");
  const [results, setResults] = useState<StepResult[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [samples, setSamples] = useState<{ name: string; label: string }[]>([]);
  const [sampleName, setSampleName] = useState("");
  const file = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchSamples()
      .then(setSamples)
      .catch(() => setSamples([]));
  }, []);

  useEffect(() => {
    setResults(null);
    setSource(null);
    if (!selected) {
      setMessage("");
      return;
    }
    let live = true;
    setMessage("Loading the stored bundle…");
    fetchDetail(selected)
      .then((d) => {
        if (!live) return;
        if (d.state === "bundle" && d.bundle_text !== null) {
          setSource({
            label: d.checkout_id,
            text: d.bundle_text,
            pinned: null,
            captureId: d.order.capture_id,
          });
          setMessage(
            "Loaded the stored bundle. Press Verify evidence to check it in this browser.",
          );
        } else setMessage(NO_EVIDENCE[d.state]);
      })
      .catch(() => live && setMessage("This order could not be loaded."));
    return () => {
      live = false;
    };
  }, [selected]);

  const verify = async () => {
    if (!source) return;
    setBusy(true);
    try {
      setResults(
        (await verifyText(source.text, source.pinned as never)) as StepResult[],
      );
    } finally {
      setBusy(false);
    }
  };
  const download = async () => {
    if (!source?.captureId) return;
    try {
      const body = await fetchBundleText(source.captureId);
      const url = URL.createObjectURL(
        new Blob([body], { type: "application/json" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = `${source.captureId}.evidence.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch {
      setMessage("The bundle could not be downloaded.");
    }
  };
  const loadFile = async (picked: File | undefined) => {
    if (!picked) return;
    setResults(null);
    setSelected("");
    setSource({
      label: picked.name,
      text: await picked.text(),
      pinned: null,
      captureId: null,
    });
    setMessage(
      "Read the file. Press Verify evidence to check it in this browser.",
    );
  };
  const loadSample = async () => {
    if (!sampleName) return;
    setResults(null);
    setSource(null);
    try {
      const s: Sample = await fetchSample(sampleName);
      setResults(null);
      setSelected("");
      setSource({
        label: s.label,
        text: s.bundle_text,
        pinned: s.pinned,
        captureId: null,
        expectedFirstFailure: s.expected_first_failure,
      });
      setMessage(
        `Loaded a committed sample${s.pinned ? " with its public keys pinned" : " (its own throwaway keys, not pinned)"}: ${s.label}. ` +
          (s.expected_first_failure
            ? `It should fail at: ${STEPS[s.expected_first_failure]?.title ?? s.expected_first_failure}.`
            : "It should pass every step."),
      );
    } catch {
      setMessage("The sample could not be loaded.");
    }
  };

  return (
    <section
      className="cs-evidence"
      aria-labelledby="evidence-title"
      data-testid="evidence-view"
    >
      <h1 id="evidence-title" className="cs-title">
        Evidence
      </h1>
      <p className="cs-muted">
        The checks run in this browser with the same code as the offline
        verifier. Without pinned keys a bundle only proves it is consistent, not
        whose it is.
      </p>
      <div className="cs-evidence__controls">
        <label>
          <span className="cs-note">Captured order</span>
          <select
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            data-testid="evidence-order"
          >
            <option value="">Choose an order…</option>
            {choices.map((o) => (
              <option key={o.id} value={o.id}>
                {o.capture_id} · {money(o.amount_minor, o.currency)} · {o.id}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className="cs-btn"
          onClick={verify}
          disabled={!source || busy}
          data-testid="verify-evidence"
        >
          Verify evidence
        </button>
        <button
          type="button"
          className="cs-btn"
          onClick={download}
          disabled={!source?.captureId}
          data-testid="download-bundle"
        >
          Download bundle
        </button>
      </div>
      <div className="cs-evidence__controls">
        <button
          type="button"
          className="cs-btn"
          onClick={() => file.current?.click()}
          data-testid="choose-file"
        >
          Load a bundle file…
        </button>
        <input
          ref={file}
          type="file"
          accept=".json,application/json"
          hidden
          data-testid="bundle-file"
          onChange={(e) => loadFile(e.target.files?.[0])}
        />
        <label>
          <span className="cs-note">Try a committed sample</span>
          <select
            value={sampleName}
            onChange={(e) => setSampleName(e.target.value)}
            data-testid="sample-select"
          >
            <option value="">Choose a sample…</option>
            {samples.map((s) => (
              <option key={s.name} value={s.name}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className="cs-btn"
          onClick={loadSample}
          disabled={!sampleName}
          data-testid="sample-load"
        >
          Load sample
        </button>
      </div>
      <p role="status" data-testid="evidence-status">
        {message}
      </p>
      {source && (
        <p className="cs-note" data-testid="evidence-source">
          Bundle: {source.label}
        </p>
      )}
      {results && <Results results={results} pinned={source?.pinned != null} />}
    </section>
  );
}

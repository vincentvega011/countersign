// The Trusted Surface page: enrolment and the Approve intent screen. Deterministic: every sentence
// comes from messages.js, the only store-supplied text is the store's own name and item titles from
// /trusted-surface/store, and the only service-supplied code is one that matches CODE_PATTERN. Nothing
// an agent wrote is shown: a proposal carries item ids, numbers and a key, never text.
import { amount, badge, button, codeBlock, fingerprint } from "../ui/ui.js";
import {
  CHALLENGE_PURPOSE_CONSENT,
  ProposalError,
  buildRecord,
  checkStore,
  proposalFromHash,
  recordBytes,
  termsView,
} from "./consent.js";
import {
  DeviceKeyError,
  checkSupport,
  clearLocal,
  generate,
  loadRecord,
  getJson,
  postJson,
  publicJwk,
  readMarker,
  register,
  requestPersistence,
  saveRecord,
  signBytes,
  thumbprintOf,
  writeMarker,
} from "./device-key.js";
import {
  CODE_PATTERN,
  CONSENT_REFUSALS,
  LABELS,
  MESSAGES,
  NOTES,
} from "./messages.js";

const root = document.getElementById("app");
let persistence = "unavailable";
let first = true;

function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs))
    if (value !== null && value !== undefined && value !== false)
      node.setAttribute(name, value === true ? "" : String(value));
  node.append(...children);
  return node;
}

const TONES = {
  info: "Working",
  success: "Registered",
  warning: "Action needed",
  danger: "Problem",
};

// One screen: a fixed message, optional fingerprint, customer id, error code and note, and actions.
function show(
  kind,
  {
    tone = "info",
    thumbprint,
    thumbprintLabel = LABELS.fingerprint,
    customerId,
    code,
    notes = [],
    sections = [],
    actions = [],
  } = {},
) {
  const message = MESSAGES[kind] ?? MESSAGES.unexpected;
  if (kind === "creating")
    actions = [button(LABELS.working, { loading: true, disabled: true })];
  const title = h(
    "h2",
    { class: "cs-card__title", tabindex: "-1" },
    message.title,
  );
  const parts = [
    h(
      "div",
      { class: "ts-card__tag" },
      badge(TONES[tone], tone === "info" ? "accent" : tone),
    ),
    title,
    h("p", { class: "ts-card__body" }, message.body),
  ];
  if (thumbprint)
    parts.push(
      h(
        "div",
        { class: "ts-field" },
        h("div", { class: "ts-field__label" }, thumbprintLabel),
        fingerprint(thumbprint, thumbprintLabel),
      ),
    );
  if (customerId)
    parts.push(
      h(
        "div",
        { class: "ts-field" },
        h("div", { class: "ts-field__label" }, LABELS.customer),
        h(
          "code",
          { class: "ts-code", "data-testid": "customer-id" },
          customerId,
        ),
      ),
    );
  if (code !== undefined)
    parts.push(
      h(
        "div",
        { class: "ts-field" },
        h("div", { class: "ts-field__label" }, LABELS.code),
        h(
          "code",
          { class: "ts-code", "data-testid": "error-code" },
          CODE_PATTERN.test(code) ? code : "unknown",
        ),
      ),
    );
  parts.push(...sections);
  for (const note of notes)
    parts.push(h("p", { class: "ts-card__note cs-muted" }, note));
  if (actions.length) parts.push(h("div", { class: "ts-actions" }, ...actions));
  const card = h(
    "section",
    { class: "cs-card ts-card", "data-state": kind, "data-tone": tone },
    ...parts,
  );
  root.replaceChildren(card);
  if (!first) title.focus({ preventScroll: false });
  first = false;
}

function action(label, run, variant = "primary") {
  const node = button(label, { variant });
  node.addEventListener("click", () => {
    node.disabled = true;
    run();
  });
  return node;
}

const persistNotes = () =>
  persistence === "denied" ? [NOTES.persist_denied] : [];

function fail(error, retry, extra = {}) {
  const kind = error instanceof DeviceKeyError ? error.kind : "unexpected";
  const known = Object.hasOwn(MESSAGES, kind) ? kind : "unexpected";
  const tone =
    known === "register_rejected" || known === "network" ? "warning" : "danger";
  const actions = retry ? [action(LABELS.retry, retry)] : [];
  show(known, {
    tone,
    actions,
    code: known === "register_rejected" ? (error.code ?? "unknown") : undefined,
    ...extra,
  });
}

async function finish(record) {
  show("creating");
  let result;
  try {
    result = await register(record.keyPair, record.customerId);
  } catch (error) {
    fail(error, () => finish(record));
    return;
  }
  const saved = { ...record, customerId: result.customerId };
  try {
    await saveRecord(saved);
  } catch (error) {
    fail(error, () => finish(saved));
    return;
  }
  writeMarker(result.thumbprint, result.customerId);
  await afterRegistered({
    keyPair: record.keyPair,
    customerId: result.customerId,
    thumbprint: result.thumbprint,
  });
}

async function create() {
  show("creating");
  persistence = await requestPersistence();
  let keyPair;
  try {
    keyPair = await generate();
  } catch (error) {
    fail(error, create);
    return;
  }
  const record = { keyPair, customerId: null, createdAt: Date.now() };
  try {
    await saveRecord(record);
  } catch (error) {
    fail(error, create);
    return;
  }
  await finish(record);
}

async function recreate() {
  await clearLocal();
  await create();
}

// ------------------------------------------------------------------------------------ approve intent

// The request an agent sent in the address (`#intent=...`), read once: a proposal, "invalid" if it is
// there but not usable, or null. It is untrusted; it is validated, shown from fixed templates and
// signed as part of the record, and the store checks it again.
function readProposal() {
  try {
    return proposalFromHash(location.hash);
  } catch (error) {
    if (error instanceof ProposalError) return "invalid";
    throw error;
  }
}
const pending = readProposal();

function leaveRequest() {
  history.replaceState(null, "", location.pathname + location.search);
}

async function afterRegistered(ctx) {
  if (pending === "invalid") {
    show("intent_invalid", { tone: "danger" });
    return;
  }
  if (pending !== null) {
    await startIntent(ctx);
    return;
  }
  show("registered", {
    tone: "success",
    thumbprint: ctx.thumbprint,
    customerId: ctx.customerId,
    notes: persistNotes(),
  });
}

function field(label, ...content) {
  return h(
    "div",
    { class: "ts-field" },
    h("div", { class: "ts-field__label" }, label),
    ...content,
  );
}

function termsSections(record, ctx) {
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const view = termsView(record, zone);
  const value = (id, text) =>
    h("div", { class: "ts-value", "data-testid": id }, text);
  return [
    field(LABELS.merchant, value("terms-merchant", view.merchant)),
    field(
      LABELS.items,
      h(
        "ul",
        { class: "ts-list", "data-testid": "terms-items" },
        ...view.items.map((line) => h("li", {}, line)),
      ),
    ),
    field(
      LABELS.ceiling,
      h(
        "div",
        { class: "ts-value", "data-testid": "terms-ceiling" },
        amount(view.ceilingMinor, { currency: view.currency, large: true }),
      ),
    ),
    field(LABELS.expires, value("terms-expires", view.expires)),
    field(LABELS.agent, fingerprint(view.agentThumbprint, LABELS.agent)),
    field(LABELS.yourKey, fingerprint(ctx.thumbprint, LABELS.yourKey)),
  ];
}

async function startIntent(ctx) {
  show("intent_loading");
  let challenge;
  let store;
  try {
    store = checkStore(await getJson("/trusted-surface/store"));
    challenge = await postJson("/trusted-surface/keys/challenge", {
      purpose: CHALLENGE_PURPOSE_CONSENT,
    });
  } catch (error) {
    if (error instanceof ProposalError) {
      show("intent_invalid", { tone: "danger" });
      return;
    }
    fail(error, () => startIntent(ctx));
    return;
  }
  // One record: it is rendered below, signed on Approve, and sent as it is.
  let record;
  try {
    record = await buildRecord({
      proposal: pending,
      store,
      challenge,
      customerId: ctx.customerId,
      deviceThumbprint: ctx.thumbprint,
      origin: location.origin,
    });
  } catch (error) {
    if (error instanceof ProposalError) {
      show("intent_invalid", { tone: "danger" });
      return;
    }
    throw error;
  }
  show("intent", {
    tone: "info",
    sections: termsSections(record, ctx),
    actions: [
      action(LABELS.approve, () => approveIntent(ctx, record)),
      action(LABELS.decline, declineIntent, "secondary"),
    ],
  });
}

function declineIntent() {
  leaveRequest();
  show("intent_declined", { tone: "warning" });
}

function intentFailure(error, ctx) {
  if (!(error instanceof DeviceKeyError)) {
    show("unexpected", {
      tone: "danger",
      actions: [action(LABELS.retry, () => startIntent(ctx))],
    });
    return;
  }
  if (error.kind === "network") {
    fail(error, () => startIntent(ctx));
    return;
  }
  const code = error.code ?? "unknown";
  const kind = Object.hasOwn(CONSENT_REFUSALS, code)
    ? CONSENT_REFUSALS[code]
    : "intent_refused";
  const fresh = kind === "intent_expired" || kind === "intent_mismatch";
  show(kind, {
    tone: "danger",
    code: kind === "intent_refused" ? code : undefined,
    actions: fresh ? [action(LABELS.refresh, () => startIntent(ctx))] : [],
  });
}

async function approveIntent(ctx, record) {
  show("intent_signing");
  let result;
  try {
    const signature = await signBytes(
      ctx.keyPair.privateKey,
      recordBytes(record),
    );
    result = await postJson("/trusted-surface/consent", {
      record,
      signature,
      agent_jwk: pending.agent_jwk,
    });
  } catch (error) {
    intentFailure(error, ctx);
    return;
  }
  leaveRequest();
  show("intent_approved", {
    tone: "success",
    sections: [
      h(
        "details",
        { class: "ts-details", "data-testid": "mandates" },
        h("summary", {}, LABELS.mandates),
        field(
          LABELS.checkoutMandate,
          codeBlock(result.checkout_mandate, "mandate"),
        ),
        field(
          LABELS.paymentMandate,
          codeBlock(result.payment_mandate, "mandate"),
        ),
      ),
    ],
  });
}

async function boot() {
  show("checking");
  try {
    checkSupport();
  } catch (error) {
    fail(error, null);
    return;
  }
  let record;
  try {
    record = await loadRecord();
  } catch (error) {
    if (error instanceof DeviceKeyError && error.kind === "key_unreadable") {
      show("key_unreadable", {
        tone: "danger",
        actions: [action(LABELS.recreate, recreate)],
      });
    } else {
      fail(error, null);
    }
    return;
  }
  if (record === undefined) {
    const marker = readMarker();
    if (marker !== null) {
      show("key_lost", {
        tone: "danger",
        thumbprint: marker.thumbprint,
        thumbprintLabel: LABELS.previous,
        actions: [action(LABELS.recreate, recreate)],
      });
    } else {
      show("ready", { actions: [action(LABELS.create, create)] });
    }
    return;
  }
  let thumbprint;
  try {
    thumbprint = await thumbprintOf(await publicJwk(record.keyPair));
  } catch {
    show("key_unreadable", {
      tone: "danger",
      actions: [action(LABELS.recreate, recreate)],
    });
    return;
  }
  persistence = await requestPersistence();
  if (record.customerId === null) {
    show("unregistered", {
      tone: "warning",
      thumbprint,
      actions: [action(LABELS.finish, () => finish(record))],
    });
    return;
  }
  await afterRegistered({
    keyPair: record.keyPair,
    customerId: record.customerId,
    thumbprint,
  });
}

boot().catch(() =>
  show("unexpected", { tone: "danger", actions: [action(LABELS.retry, boot)] }),
);

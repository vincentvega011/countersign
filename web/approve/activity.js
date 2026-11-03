// "My agent activity" (docs/PROTOCOL.md Decisions 91 and 92). Reading needs a device key proof that
// buys a short lived session token, kept in this module's memory only (never in storage, a cookie or
// the address). Taking an approval back needs its own signature over a record that names that approval;
// the token alone cannot do it. Everything shown is structured data from the backend rendered through
// fixed templates, with the store's own numbers; nothing a model wrote can reach this page.
import { amount, badge, fingerprint } from "../ui/ui.js";
import { expiryText } from "./consent.js";
import { DeviceKeyError, getJson, postJson, signBytes } from "./device-key.js";
import {
  LABELS,
  MANDATE_STATES,
  MESSAGES,
  REVOKE_REFUSALS,
} from "./messages.js";
import {
  CHALLENGE_PURPOSE_READ,
  CHALLENGE_PURPOSE_REVOKE,
  readRecord,
  recordBytes,
  revokeRecord,
} from "./activity-records.js";
import {
  action,
  field,
  h,
  loadDevice,
  makeScreen,
  value,
  yourKey,
} from "./shell.js";

const root = document.getElementById("app");
const show = makeScreen(root);
const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;

let device = null;
let token = null; // in memory only
let flash = null; // a fixed message key shown above the list after an action
let confirming = null; // the open mandate identity whose revoke is awaiting confirmation

const SESSION_CODES = ["session_unknown", "session_expired"];
const IDENTITY = /^[A-Za-z0-9_-]{43}$/;

function problem(error, retry) {
  if (!(error instanceof DeviceKeyError)) {
    show("unexpected", {
      tone: "danger",
      actions: retry ? [action(LABELS.retry, retry)] : [],
    });
    return;
  }
  if (error.kind === "needs_key") {
    const link = h(
      "a",
      { class: "cs-btn cs-btn--primary", href: "/approve/" },
      LABELS.register,
    );
    show("needs_key", {
      tone: "warning",
      sections: [h("div", { class: "ts-actions" }, link)],
    });
    return;
  }
  if (error.kind === "register_rejected") {
    show("activity_denied", { tone: "danger", code: error.code ?? "unknown" });
    return;
  }
  const network = error.kind === "network";
  show(network ? "network" : "unexpected", {
    tone: network ? "warning" : "danger",
    actions: retry ? [action(LABELS.retry, retry)] : [],
  });
}

async function openSession() {
  const challenge = await postJson("/trusted-surface/keys/challenge", {
    purpose: CHALLENGE_PURPOSE_READ,
  });
  const ctx = {
    challenge,
    customerId: device.customerId,
    deviceThumbprint: device.thumbprint,
    origin: location.origin,
  };
  const signature = await signBytes(
    device.keyPair.privateKey,
    recordBytes(readRecord(ctx)),
  );
  const session = await postJson("/trusted-surface/activity/session", {
    challenge_id: challenge.challenge_id,
    customer_id: device.customerId,
    device_thumbprint: device.thumbprint,
    origin: location.origin,
    signature,
  });
  token = session.token;
}

async function fetchList() {
  if (token === null) await openSession();
  try {
    return await getJson("/trusted-surface/activity", {
      Authorization: `Bearer ${token}`,
    });
  } catch (error) {
    if (error instanceof DeviceKeyError && SESSION_CODES.includes(error.code)) {
      token = null;
      await openSession();
      return getJson("/trusted-surface/activity", {
        Authorization: `Bearer ${token}`,
      });
    }
    throw error;
  }
}

const CHECKOUT_ID = /^chk_[A-Za-z0-9_-]{22}$/;
const CAPTURE_ID = /^[A-Za-z0-9]{1,40}$/;

function checkPurchase(purchase) {
  if (purchase === null) return true;
  return (
    purchase !== null &&
    typeof purchase === "object" &&
    CHECKOUT_ID.test(purchase.checkout_id) &&
    (purchase.capture_id === null || CAPTURE_ID.test(purchase.capture_id)) &&
    (purchase.amount_minor === null ||
      Number.isSafeInteger(purchase.amount_minor)) &&
    (purchase.currency === null || purchase.currency === "USD") &&
    Number.isSafeInteger(purchase.at_us)
  );
}

// The list is the backend's structured data. Anything that is not exactly the expected shape is
// refused as a whole, so a malformed or injected value is never rendered.
function checkList(list) {
  const ok =
    list !== null &&
    typeof list === "object" &&
    Array.isArray(list.mandates) &&
    list.mandates.every(
      (m) =>
        IDENTITY.test(m.id) &&
        Object.hasOwn(MANDATE_STATES, m.state) &&
        Number.isSafeInteger(m.ceiling_minor) &&
        Number.isSafeInteger(m.exp) &&
        m.currency === "USD" &&
        /^[A-Za-z0-9_-]{43}$/.test(m.agent_thumbprint) &&
        checkPurchase(m.purchase),
    );
  if (!ok) throw new DeviceKeyError("unexpected");
  return list;
}

function purchaseBlock(purchase) {
  const rows = [
    field(
      LABELS.checkoutId,
      h("code", { class: "ts-code" }, purchase.checkout_id),
    ),
  ];
  if (purchase.amount_minor !== null)
    rows.push(
      field(
        LABELS.paid,
        h(
          "div",
          { class: "ts-value" },
          amount(purchase.amount_minor, {
            currency: purchase.currency ?? "USD",
          }),
        ),
      ),
    );
  if (purchase.capture_id)
    rows.push(
      field(
        LABELS.captureId,
        h("code", { class: "ts-code" }, purchase.capture_id),
      ),
    );
  rows.push(
    field(
      LABELS.when,
      h(
        "div",
        { class: "ts-value" },
        expiryText(Math.floor(purchase.at_us / 1e6), zone),
      ),
    ),
  );
  return h("div", { class: "ts-purchase", "data-testid": "purchase" }, ...rows);
}

function revokeArea(mandate) {
  if (!["unused", "in_flight"].includes(mandate.state)) return null;
  if (confirming === mandate.id) {
    const ask = MESSAGES.revoke_confirm;
    return h(
      "div",
      { class: "ts-confirm", role: "group", "aria-label": ask.title },
      h("p", { class: "ts-confirm__title" }, ask.title),
      h("p", { class: "ts-card__note" }, ask.body),
      h(
        "div",
        { class: "ts-actions" },
        action(LABELS.revokeYes, () => revoke(mandate), "danger"),
        action(
          LABELS.revokeKeep,
          () => {
            confirming = null;
            render(lastList);
          },
          "secondary",
        ),
      ),
    );
  }
  return h(
    "div",
    { class: "ts-actions" },
    action(
      LABELS.revoke,
      () => {
        confirming = mandate.id;
        render(lastList);
      },
      "secondary",
    ),
  );
}

function mandateCard(mandate) {
  const info = MANDATE_STATES[mandate.state];
  const children = [
    h(
      "div",
      { class: "ts-card__tag" },
      badge(`${info.glyph} ${info.label}`, info.tone),
    ),
    field(
      LABELS.spendLimit,
      h(
        "div",
        { class: "ts-value", "data-testid": "mandate-ceiling" },
        amount(mandate.ceiling_minor, {
          currency: mandate.currency,
          large: true,
        }),
      ),
    ),
    field(
      LABELS.expires,
      value("mandate-expires", expiryText(mandate.exp, zone)),
    ),
    field(LABELS.agent, fingerprint(mandate.agent_thumbprint, LABELS.agent)),
  ];
  if (mandate.purchase) children.push(purchaseBlock(mandate.purchase));
  const area = revokeArea(mandate);
  if (area) children.push(area);
  return h(
    "li",
    {
      class: "cs-card ts-mandate",
      "data-testid": "mandate",
      "data-mandate": mandate.id,
      "data-mandate-state": mandate.state,
    },
    ...children,
  );
}

let lastList = null;

function render(list) {
  lastList = list;
  const sections = [yourKey(device.thumbprint)];
  if (flash)
    sections.push(
      h(
        "p",
        { class: "ts-flash", role: "status", "data-testid": "flash" },
        MESSAGES[flash].title + ". " + MESSAGES[flash].body,
      ),
    );
  if (list.mandates.length === 0) {
    show("activity_empty", {
      sections,
      actions: [action(LABELS.refreshActivity, refresh, "secondary")],
    });
    return;
  }
  sections.push(
    h(
      "ul",
      { class: "ts-mandates", "data-testid": "mandates" },
      ...list.mandates.map(mandateCard),
    ),
  );
  show("activity", {
    sections,
    wide: true,
    actions: [action(LABELS.refreshActivity, refresh, "secondary")],
  });
}

async function refresh() {
  confirming = null;
  try {
    render(checkList(await fetchList()));
  } catch (error) {
    problem(error, refresh);
  }
}

async function revoke(mandate) {
  let outcome = "revoke_done";
  try {
    const challenge = await postJson("/trusted-surface/keys/challenge", {
      purpose: CHALLENGE_PURPOSE_REVOKE,
    });
    const ctx = {
      challenge,
      customerId: device.customerId,
      deviceThumbprint: device.thumbprint,
      origin: location.origin,
    };
    const signature = await signBytes(
      device.keyPair.privateKey,
      recordBytes(revokeRecord(ctx, mandate.id)),
    );
    await postJson("/trusted-surface/activity/revoke", {
      challenge_id: challenge.challenge_id,
      customer_id: device.customerId,
      device_thumbprint: device.thumbprint,
      open_mandate: mandate.id,
      origin: location.origin,
      signature,
    });
  } catch (error) {
    if (error instanceof DeviceKeyError && error.kind === "register_rejected") {
      outcome = Object.hasOwn(REVOKE_REFUSALS, error.code ?? "")
        ? REVOKE_REFUSALS[error.code]
        : "revoke_refused";
    } else {
      problem(error, refresh);
      return;
    }
  }
  flash = outcome;
  confirming = null;
  await refresh();
}

async function boot() {
  show("activity_loading");
  try {
    device = await loadDevice();
  } catch (error) {
    problem(error, null);
    return;
  }
  await refresh();
}

boot().catch(() =>
  show("unexpected", { tone: "danger", actions: [action(LABELS.retry, boot)] }),
);

// The Approve purchase screen (Human Present, docs/PROTOCOL.md Decisions 29 and 90). It shows the
// terms of the checkout the store signed, only after the backend verified that signature, from fixed
// templates; the device key signs a consent record naming exactly those terms; the backend rebuilds the
// closed mandates from its own copy of the checkout and signs only if they are byte for byte equal.
import { amount, codeBlock } from "../ui/ui.js";
import { DeviceKeyError, postJson, signBytes } from "./device-key.js";
import { LABELS, PURCHASE_REFUSALS } from "./messages.js";
import {
  CHALLENGE_PURPOSE_CHECKOUT,
  OfferError,
  buildPurchaseRecord,
  checkOffer,
  checkoutIdFromHash,
  purchaseBytes,
  purchaseView,
} from "./purchase-consent.js";
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

function problem(error, retry) {
  if (error instanceof OfferError) {
    show("purchase_unsigned", { tone: "danger" });
    return;
  }
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
    const kind = Object.hasOwn(PURCHASE_REFUSALS, error.code ?? "")
      ? PURCHASE_REFUSALS[error.code]
      : "purchase_refused";
    show(kind, {
      tone: "danger",
      code: kind === "purchase_refused" ? (error.code ?? "unknown") : undefined,
    });
    return;
  }
  const known = error.kind === "network";
  show(known ? "network" : "unexpected", {
    tone: known ? "warning" : "danger",
    actions: retry ? [action(LABELS.retry, retry)] : [],
  });
}

function termsSections(offer, device) {
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const view = purchaseView(offer.terms, zone);
  const money = (minor) => amount(minor, { currency: view.currency });
  const rows = [
    ...view.items.map((item) =>
      h(
        "li",
        { class: "ts-line" },
        h("span", {}, item.text),
        money(item.lineMinor),
      ),
    ),
  ];
  const adjust = view.adjustments.map((row) =>
    h("li", { class: "ts-line" }, h("span", {}, row.label), money(row.minor)),
  );
  return [
    field(LABELS.merchant, value("terms-merchant", view.merchant)),
    field(
      LABELS.items,
      h("ul", { class: "ts-lines", "data-testid": "terms-items" }, ...rows),
    ),
    ...(adjust.length
      ? [
          h(
            "ul",
            { class: "ts-lines", "data-testid": "terms-adjustments" },
            ...adjust,
          ),
        ]
      : []),
    field(
      LABELS.total,
      h(
        "div",
        { class: "ts-value", "data-testid": "terms-total" },
        amount(view.totalMinor, { currency: view.currency, large: true }),
      ),
    ),
    field(LABELS.checkoutValid, value("terms-expires", view.expires)),
    yourKey(device.thumbprint),
  ];
}

async function start(device, checkoutId) {
  show("purchase_loading");
  let offer;
  try {
    offer = checkOffer(
      await postJson("/trusted-surface/purchases/offer", {
        checkout_id: checkoutId,
      }),
    );
  } catch (error) {
    problem(error, () => start(device, checkoutId));
    return;
  }
  show("purchase", {
    sections: termsSections(offer, device),
    actions: [
      action(LABELS.approve, () => approve(device, checkoutId, offer)),
      action(LABELS.decline, decline, "secondary"),
    ],
  });
}

function decline() {
  history.replaceState(null, "", location.pathname + location.search);
  show("purchase_declined", { tone: "warning" });
}

async function approve(device, checkoutId, offer) {
  show("purchase_signing");
  let result;
  try {
    const challenge = await postJson("/trusted-surface/keys/challenge", {
      purpose: CHALLENGE_PURPOSE_CHECKOUT,
    });
    const record = buildPurchaseRecord({
      offer,
      challenge,
      customerId: device.customerId,
      deviceThumbprint: device.thumbprint,
      origin: location.origin,
    });
    const signature = await signBytes(
      device.keyPair.privateKey,
      purchaseBytes(record),
    );
    result = await postJson("/trusted-surface/purchases/consent", {
      record,
      signature,
    });
  } catch (error) {
    problem(error, () => start(device, checkoutId));
    return;
  }
  history.replaceState(null, "", location.pathname + location.search);
  show("purchase_approved", {
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
  let checkoutId;
  try {
    checkoutId = checkoutIdFromHash(location.hash);
  } catch {
    show("purchase_missing", { tone: "danger" });
    return;
  }
  if (checkoutId === null) {
    show("purchase_missing", { tone: "danger" });
    return;
  }
  let device;
  try {
    device = await loadDevice();
  } catch (error) {
    problem(error, null);
    return;
  }
  await start(device, checkoutId);
}

boot().catch(() =>
  show("unexpected", { tone: "danger", actions: [action(LABELS.retry, boot)] }),
);

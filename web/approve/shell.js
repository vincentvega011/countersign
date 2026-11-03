// What the purchase and activity pages share: building nodes, one-card screens made only from
// messages.js templates, and loading the device key this browser already registered. No model text,
// no markup from strings (everything is set with textContent through createElement), no network
// except same-origin requests made by device-key.js.
import { badge, button, fingerprint } from "../ui/ui.js";
import {
  DeviceKeyError,
  checkSupport,
  loadRecord,
  publicJwk,
  thumbprintOf,
} from "./device-key.js";
import { CODE_PATTERN, LABELS, MESSAGES } from "./messages.js";

export function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs))
    if (value !== null && value !== undefined && value !== false)
      node.setAttribute(name, value === true ? "" : String(value));
  node.append(...children);
  return node;
}

export function field(label, ...content) {
  return h(
    "div",
    { class: "ts-field" },
    h("div", { class: "ts-field__label" }, label),
    ...content,
  );
}

export function value(testid, text) {
  return h("div", { class: "ts-value", "data-testid": testid }, text);
}

export function action(label, run, variant = "primary") {
  const node = button(label, { variant });
  node.addEventListener("click", () => {
    node.disabled = true;
    run();
  });
  return node;
}

const TONES = {
  info: "Working",
  success: "Done",
  warning: "Action needed",
  danger: "Problem",
};

// A screen holder: `show(kind, options)` replaces the card in `root`. `kind` must be a key of MESSAGES.
export function makeScreen(root) {
  let first = true;
  return function show(
    kind,
    {
      tone = "info",
      code,
      sections = [],
      notes = [],
      actions = [],
      wide = false,
    } = {},
  ) {
    const message = MESSAGES[kind] ?? MESSAGES.unexpected;
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
    if (code !== undefined)
      parts.push(
        field(
          LABELS.code,
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
    if (actions.length)
      parts.push(h("div", { class: "ts-actions" }, ...actions));
    const card = h(
      "section",
      {
        class: `cs-card ts-card${wide ? " ts-card--wide" : ""}`,
        "data-state": kind,
        "data-tone": tone,
      },
      ...parts,
    );
    root.replaceChildren(card);
    if (!first) title.focus({ preventScroll: false });
    first = false;
    return card;
  };
}

// The registered device of this browser: `{keyPair, customerId, thumbprint}`. Throws a DeviceKeyError
// with a kind that has a fixed message, or `needs_key` when there is no registered key to use.
export async function loadDevice() {
  checkSupport();
  const record = await loadRecord();
  if (record === undefined || record.customerId === null)
    throw new DeviceKeyError("needs_key");
  const thumbprint = await thumbprintOf(await publicJwk(record.keyPair));
  return { keyPair: record.keyPair, customerId: record.customerId, thumbprint };
}

export const yourKey = (thumbprint) =>
  field(LABELS.yourKey, fingerprint(thumbprint, LABELS.yourKey));

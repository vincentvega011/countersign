// Small, dependency free helpers for the shared components. Plain ES module: no build step.
// Money is integer minor units only; a float is a programming error and is rejected.

const CURRENCIES = { USD: { symbol: "$", exponent: 2 } };

export function formatAmount(minor, currency = "USD") {
  const info = CURRENCIES[currency];
  if (info === undefined)
    throw new RangeError(`unsupported currency: ${String(currency)}`);
  if (
    typeof minor !== "bigint" &&
    !(typeof minor === "number" && Number.isSafeInteger(minor))
  ) {
    throw new TypeError("amount must be an integer number of minor units");
  }
  const value = BigInt(minor);
  const negative = value < 0n;
  const digits = (negative ? -value : value)
    .toString()
    .padStart(info.exponent + 1, "0");
  const whole = digits
    .slice(0, -info.exponent)
    .replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const fraction = digits.slice(-info.exponent);
  return `${negative ? "-" : ""}${info.symbol}${whole}.${fraction}`;
}

// Groups of four, so a fingerprint can be read aloud and compared at 375 px.
export function groupFingerprint(value, size = 4) {
  if (typeof value !== "string" || value.length === 0)
    throw new TypeError("empty fingerprint");
  if (!Number.isInteger(size) || size < 1)
    throw new RangeError("bad group size");
  const groups = [];
  for (let i = 0; i < value.length; i += size)
    groups.push(value.slice(i, i + size));
  return groups;
}

// Checkout and attempt states -> tone and a glyph that carries the meaning without colour.
export const STATUS = Object.freeze({
  ready_for_complete: { label: "Ready", tone: "info", glyph: "○" },
  complete_in_progress: { label: "In progress", tone: "warning", glyph: "◐" },
  completed: { label: "Completed", tone: "success", glyph: "✓" },
  canceled: { label: "Canceled", tone: "neutral", glyph: "✕" },
  rejected: { label: "Rejected", tone: "danger", glyph: "!" },
  voided: { label: "Voided", tone: "neutral", glyph: "⊘" },
});

export function statusInfo(state) {
  const info = Object.hasOwn(STATUS, state) ? STATUS[state] : undefined;
  if (info === undefined)
    throw new RangeError(`unknown state: ${String(state)}`);
  return info;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === false || value === null || value === undefined) continue;
    node.setAttribute(key, value === true ? "" : String(value));
  }
  node.append(...children);
  return node;
}

export async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = el("textarea", { "aria-hidden": "true", readonly: true });
  area.value = text;
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.append(area);
  area.select();
  document.execCommand("copy");
  area.remove();
}

function copyButton(label, text) {
  const button = el(
    "button",
    { type: "button", class: "cs-btn cs-btn--secondary" },
    "Copy",
  );
  button.setAttribute("aria-label", label);
  button.addEventListener("click", async () => {
    try {
      await copyText(text);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    setTimeout(() => {
      button.textContent = "Copy";
    }, 1600);
  });
  return button;
}

export function button(
  label,
  { variant = "primary", disabled = false, loading = false } = {},
) {
  const node = el(
    "button",
    {
      type: "button",
      class: `cs-btn cs-btn--${variant}${loading ? " is-loading" : ""}`,
      disabled: disabled,
      "aria-busy": loading,
    },
    label,
  );
  return node;
}

export function card(title, ...body) {
  return el(
    "section",
    { class: "cs-card" },
    el("h3", { class: "cs-card__title" }, title),
    ...body,
  );
}

export function badge(text, tone = "neutral") {
  return el(
    "span",
    { class: `cs-badge${tone === "neutral" ? "" : ` cs-badge--${tone}`}` },
    text,
  );
}

export function statusPill(state) {
  const { label, tone, glyph } = statusInfo(state);
  return el(
    "span",
    { class: "cs-pill", "data-tone": tone, "data-state": state },
    el("span", { class: "cs-pill__glyph", "aria-hidden": "true" }, glyph),
    label,
  );
}

export function amount(minor, { currency = "USD", large = false } = {}) {
  const text = formatAmount(minor, currency);
  const negative = text.startsWith("-");
  return el(
    "span",
    {
      class: `cs-amount${large ? " cs-amount--lg" : ""}${negative ? " cs-amount--negative" : ""}`,
    },
    text,
  );
}

export function fingerprint(value, label = "Key fingerprint") {
  const groups = groupFingerprint(value).map((g) =>
    el("span", { class: "cs-fingerprint__group" }, g),
  );
  return el(
    "div",
    { class: "cs-fingerprint", role: "group", "aria-label": label },
    el("span", { class: "cs-fingerprint__value" }, ...groups),
    copyButton(`Copy ${label.toLowerCase()}`, value),
  );
}

export function codeBlock(text, language = "text") {
  const pre = el(
    "pre",
    { tabindex: "0", role: "region", "aria-label": `${language} code` },
    text,
  );
  return el(
    "div",
    { class: "cs-code" },
    el(
      "div",
      { class: "cs-code__bar" },
      el("span", {}, language),
      copyButton(`Copy ${language}`, text),
    ),
    pre,
  );
}

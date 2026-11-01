import {
  amount,
  badge,
  button,
  card,
  codeBlock,
  fingerprint,
  statusPill,
  STATUS,
} from "./ui.js";

const SWATCHES = [
  "page",
  "surface",
  "sunken",
  "text",
  "muted",
  "border",
  "border-strong",
  "accent",
  "accent-surface",
  "success",
  "warning",
  "danger",
  "info",
];
const SAMPLE_FINGERPRINT = "q7Hk2vN0cX9bR4tLw1ZmP8sJdY3fUaE6gO5iVnC1xKM";
const SAMPLE_CODE = JSON.stringify(
  {
    checkout_id: "chk_demo",
    status: "complete_in_progress",
    note: "a long line scrolls sideways and never wraps: ".repeat(3),
  },
  null,
  2,
);

function group(title, ...children) {
  const section = document.createElement("section");
  section.className = "group";
  const heading = document.createElement("h3");
  heading.textContent = title;
  const body = document.createElement("div");
  body.className = "cs-row";
  body.append(...children);
  section.append(heading, body);
  return section;
}

function stack(...children) {
  const wrap = document.createElement("div");
  wrap.className = "cs-stack";
  wrap.style.width = "100%";
  wrap.append(...children);
  return wrap;
}

function swatch(name) {
  const item = document.createElement("div");
  item.className = "swatch";
  const chip = document.createElement("i");
  chip.style.background = `var(--color-${name})`;
  item.append(chip, document.createTextNode(name));
  return item;
}

function text(tag, className, content) {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = content;
  return node;
}

function panel(theme) {
  const root = document.createElement("section");
  root.className = "panel cs-scope";
  root.dataset.theme = theme;
  root.setAttribute("aria-label", `${theme} theme`);
  const title = document.createElement("h2");
  title.textContent = `${theme[0].toUpperCase()}${theme.slice(1)} theme`;
  root.append(
    title,
    group(
      "Type",
      text("p", "specimen-display", "Countersign proves what was approved"),
      text("p", "cs-mono", "chk_8uwurtgtk3uL0vZHV  0123456789"),
    ),
    group("Colour roles", ...SWATCHES.map(swatch)),
    group(
      "Button",
      button("Approve", { variant: "primary" }),
      button("Review", { variant: "secondary" }),
      button("Revoke", { variant: "danger" }),
      button("Approve", { variant: "primary", disabled: true }),
      button("Review", { variant: "secondary", disabled: true }),
      button("Revoke", { variant: "danger", disabled: true }),
      button("Working", { variant: "primary", loading: true }),
      button("Working", { variant: "secondary", loading: true }),
      button("Working", { variant: "danger", loading: true }),
    ),
    group(
      "Card",
      card(
        "Purchase approved",
        text("p", "cs-muted", "Headphones, up to $80.00, until Sunday 18:00."),
      ),
    ),
    group(
      "Badge",
      badge("Neutral"),
      badge("Accent", "accent"),
      badge("Success", "success"),
      badge("Warning", "warning"),
      badge("Danger", "danger"),
      badge("Info", "info"),
    ),
    group(
      "Status pill",
      ...Object.keys(STATUS).map((state) => statusPill(state)),
    ),
    group(
      "Key fingerprint",
      fingerprint(SAMPLE_FINGERPRINT, "Device key fingerprint"),
    ),
    group(
      "Amount",
      stack(
        ...[0, 1, 99, 100, 123456789, -250].map((minor) => {
          const line = document.createElement("div");
          line.className = "cs-row";
          line.append(
            amount(minor),
            text("span", "cs-muted cs-mono", `${minor} minor units`),
          );
          return line;
        }),
        amount(8500, { large: true }),
      ),
    ),
    group("Code block", stack(codeBlock(SAMPLE_CODE, "json"))),
  );
  return root;
}

const params = new URLSearchParams(location.search);
const only = params.get("theme");
const themes = only === "light" || only === "dark" ? [only] : ["light", "dark"];
const mount = document.getElementById("gallery");
mount.dataset.panels = String(themes.length);
mount.append(...themes.map(panel));
if (themes.length === 1) document.documentElement.dataset.theme = themes[0];

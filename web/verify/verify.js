// The evidence verifier page. Everything runs in this browser with the ES modules in ../ui/evidence/;
// the only request this page makes is the optional load by capture id, to its own origin. Every text
// comes from verify-text.js or from the verifier's own fixed messages, and is set with textContent.
import { badge, fingerprint } from "../ui/ui.js";
import { thumbprint } from "../ui/evidence/crypto.js";
import { dict, isDict, loads } from "../ui/evidence/json.js";
import { verifyText } from "../ui/evidence/verify.js";
import { STEP_TEXT, TEXT } from "./verify-text.js";

const CAPTURE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const $ = (id) => document.getElementById(id);

function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs))
    if (value !== null && value !== undefined && value !== false)
      node.setAttribute(name, value === true ? "" : String(value));
  node.append(...children);
  return node;
}

function pill(ok) {
  return h(
    "span",
    {
      class: "cs-pill",
      "data-tone": ok ? "success" : "danger",
      "data-testid": "step-status",
    },
    h(
      "span",
      { class: "cs-pill__glyph", "aria-hidden": "true" },
      ok ? "✓" : "!",
    ),
    ok ? TEXT.passed : TEXT.failed,
  );
}

const result = $("result");
const status = h("p", {
  class: "vf-status",
  role: "status",
  "data-testid": "status",
});
$("verify").after(status);

function say(text) {
  status.textContent = text;
}

function readKey(id, who) {
  const text = $(id).value.trim();
  if (!text) return undefined;
  try {
    const key = loads(text);
    if (!isDict(key)) throw new Error("not an object");
    return key;
  } catch {
    throw new Error(TEXT.badKey(who));
  }
}

async function keyRow(who, key) {
  let print;
  try {
    print = await thumbprint(key);
  } catch {
    return null;
  }
  return h(
    "div",
    { class: "vf-key" },
    h("div", { class: "vf-label" }, TEXT.keyFingerprint(who)),
    fingerprint(print, TEXT.keyFingerprint(who)),
  );
}

async function keysNotice(pinned, bundleKeys, device) {
  const count = Object.keys(pinned).length;
  const text =
    count === 2 ? TEXT.pinned : count === 1 ? TEXT.partlyPinned : TEXT.unpinned;
  const notice = h(
    "p",
    {
      class: `vf-keys vf-keys--${count === 2 ? "pinned" : "unpinned"}`,
      "data-testid": "keys-notice",
      "data-pinned": String(count),
    },
    text,
  );
  const rows = [];
  for (const [name, who] of [
    ["merchant", TEXT.merchant],
    ["platform", TEXT.platform],
  ]) {
    const key =
      pinned[name] ?? (isDict(bundleKeys) ? bundleKeys[name] : undefined);
    const row = key === undefined ? null : await keyRow(who, key);
    if (row) rows.push(row);
  }
  if (isDict(device)) {
    const row = await keyRow(TEXT.device, device);
    if (row) rows.push(row);
  }
  return [notice, ...rows];
}

function stepItem(r, first) {
  const text = STEP_TEXT[r.name];
  const parts = [
    h(
      "div",
      { class: "vf-step__head" },
      pill(r.ok),
      first ? badge(TEXT.firstFailure, "danger") : "",
    ),
    h("h3", { class: "vf-step__title" }, text.title),
    h("p", { class: "vf-step__explains cs-muted" }, text.explains),
  ];
  if (!r.ok)
    parts.push(
      h(
        "div",
        { class: "vf-step__why" },
        h("div", { class: "vf-label" }, TEXT.why),
        h(
          "p",
          { class: "vf-step__message", "data-testid": "step-message" },
          r.message,
        ),
        h("div", { class: "vf-label" }, TEXT.code),
        h("code", { class: "vf-code", "data-testid": "step-code" }, r.code),
      ),
    );
  return h(
    "li",
    {
      class: `vf-step${r.ok ? "" : " vf-step--failed"}${first ? " vf-step--first" : ""}`,
      "data-step": r.name,
      "data-ok": String(r.ok),
      "data-first": first ? "true" : null,
      "data-testid": "step",
    },
    ...parts,
  );
}

async function show(results, pinned, bundleKeys, device) {
  const failed = results.filter((r) => !r.ok);
  const onlyUnpinned =
    failed.length === 1 &&
    failed[0].name === "trusted_keys" &&
    failed[0].code === "keys_not_pinned";
  const state =
    failed.length === 0 ? "passed" : onlyUnpinned ? "unpinned" : "failed";
  const first = failed[0];
  const title = h(
    "h2",
    {
      class: "vf-summary__title",
      tabindex: "-1",
      "data-testid": "summary-title",
    },
    state === "failed" ? TEXT.failedAt : TEXT.allPassed,
  );
  const body =
    state === "passed"
      ? TEXT.allPassedBody
      : state === "unpinned"
        ? TEXT.onlyKeysBody
        : TEXT.failedAtBody(STEP_TEXT[first.name].title);
  const summary = h(
    "section",
    {
      class: "cs-card vf-summary",
      "data-state": state,
      "data-testid": "summary",
      "data-first-failure": first ? first.name : null,
    },
    badge(
      state === "passed"
        ? TEXT.passed
        : state === "unpinned"
          ? TEXT.notPinned
          : TEXT.failed,
      state === "passed"
        ? "success"
        : state === "unpinned"
          ? "warning"
          : "danger",
    ),
    title,
    h("p", { class: "vf-summary__body" }, body),
    ...(await keysNotice(pinned, bundleKeys, device)),
  );
  const list = h(
    "ol",
    { class: "vf-steps", "data-testid": "steps" },
    ...results.map((r) => stepItem(r, r === first)),
  );
  result.replaceChildren(summary, list);
  title.focus();
}

async function run() {
  const button = $("verify");
  const text = $("bundle-text").value;
  if (!text.trim()) {
    say(TEXT.emptyBundle);
    return;
  }
  const pinned = dict();
  try {
    const merchant = readKey("merchant-key", "merchant");
    const platform = readKey("platform-key", "platform");
    if (merchant !== undefined) pinned.merchant = merchant;
    if (platform !== undefined) pinned.platform = platform;
  } catch (error) {
    say(error.message);
    return;
  }
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  say(TEXT.working);
  try {
    const results = await verifyText(
      text,
      Object.keys(pinned).length ? pinned : null,
    );
    let bundleKeys;
    let device;
    try {
      const parsed = loads(text);
      bundleKeys = parsed.keys;
      device = isDict(parsed.consent) ? parsed.consent.device_jwk : undefined;
    } catch {
      bundleKeys = undefined;
    }
    await show(results, pinned, bundleKeys, device);
    say("");
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

async function load() {
  const id = $("capture-id").value.trim();
  if (!CAPTURE_ID.test(id)) {
    say(TEXT.badId);
    return;
  }
  say(TEXT.loading);
  try {
    const response = await fetch(`/evidence/${encodeURIComponent(id)}`, {
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
    });
    if (response.status === 404) {
      say(TEXT.notFound);
      return;
    }
    if (!response.ok) throw new Error("load failed");
    $("bundle-text").value = await response.text();
    result.replaceChildren();
    say(TEXT.loaded);
  } catch {
    say(TEXT.loadFailed);
  }
}

async function readFile(file) {
  try {
    $("bundle-text").value = await file.text();
    result.replaceChildren();
    say(TEXT.fileRead);
  } catch {
    say(TEXT.fileFailed);
  }
}

$("verify").addEventListener("click", run);
$("load").addEventListener("click", load);
$("choose").addEventListener("click", () => $("bundle-file").click());
$("capture-id").addEventListener("keydown", (event) => {
  if (event.key === "Enter") load();
});
$("bundle-file").addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  if (file) readFile(file);
});
const drop = $("drop");
drop.addEventListener("dragover", (event) => {
  event.preventDefault();
  drop.classList.add("is-over");
});
drop.addEventListener("dragleave", () => drop.classList.remove("is-over"));
drop.addEventListener("drop", (event) => {
  event.preventDefault();
  drop.classList.remove("is-over");
  const file = event.dataTransfer?.files?.[0];
  if (file) readFile(file);
});

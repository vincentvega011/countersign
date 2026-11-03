// Shared helpers of the browser tests: the browser, pages, the independent templates and proposals.
import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";
import { chromium } from "playwright";

export const base = process.env.APPROVE_BASE_URL;
assert.ok(base, "APPROVE_BASE_URL must name the running app");

let browser;
export async function launch() {
  browser = await chromium.launch();
  return browser;
}
export async function close() {
  await browser.close();
}

export async function open(
  t,
  {
    width = 375,
    init,
    scheme = "light",
    reducedMotion = "no-preference",
    route,
    timezoneId = "UTC",
    context: shared,
  } = {},
) {
  const context =
    shared ??
    (await browser.newContext({
      viewport: { width, height: 800 },
      colorScheme: scheme,
      reducedMotion,
      timezoneId,
      hasTouch: width <= 500,
    }));
  if (!shared) t.after(() => context.close());
  await serveOverrides(context);
  if (init) await context.addInitScript(init);
  const page = await context.newPage();
  page.requests = [];
  page.on("request", (r) =>
    page.requests.push({
      url: r.url(),
      method: r.method(),
      body: r.postData(),
    }),
  );
  if (route) await route(page);
  return { context, page };
}

export const state = (page, name) =>
  page.waitForSelector(`#app [data-state="${name}"]`, { timeout: 15000 });

export const text = (page) => page.innerText("#app");
export const fingerprints = (page) =>
  page.$$eval(".cs-fingerprint", (nodes) =>
    nodes.map((n) =>
      [...n.querySelectorAll(".cs-fingerprint__group")]
        .map((g) => g.textContent)
        .join(""),
    ),
  );

export async function enrol(page) {
  await page.goto(`${base}/approve/`);
  await page.getByRole("button", { name: "Create key" }).click();
  await state(page, "registered");
  return page.textContent('[data-testid="customer-id"]');
}

// A line of the report the Python side compares with the consent table.
export function report(line) {
  if (process.env.APPROVE_REPORT)
    appendFileSync(process.env.APPROVE_REPORT, `${line}\n`);
}

export async function store() {
  const response = await fetch(`${base}/trusted-surface/store`);
  assert.equal(response.status, 200);
  return response.json();
}

const privateKeys = new WeakMap(); // public jwk -> its private key, for signing as the agent

export function agentKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const { kty, crv, x, y } = publicKey.export({ format: "jwk" });
  const jwk = { kty, crv, x, y };
  privateKeys.set(jwk, privateKey);
  return jwk;
}

export function proposal(
  items,
  { ceiling = 8000, days = 7, agent = agentKey() } = {},
) {
  return {
    items,
    ceiling_minor: ceiling,
    currency: "USD",
    mandate_expires_at: Math.floor(Date.now() / 1000) + days * 86400,
    agent_jwk: agent,
  };
}

// RFC 8785 for the shapes used here, written again and not imported from the page.
export function jcs(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
}

export function thumbprint(jwk) {
  return createHash("sha256")
    .update(jcs({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
    .digest("base64url");
}

export function sign(privateKey, text) {
  return cryptoSign("sha256", Buffer.from(text), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64url");
}

export async function post(path, body) {
  const response = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

// An agent files a proposal with the backend, proving its key over a server challenge. Returns the
// id (or the refusal code).
export async function fileProposal(prop) {
  const { agent_jwk: jwk, ...terms } = prop;
  const key = privateKeys.get(jwk);
  if (key === undefined) return { status: 0, body: {} }; // a crafted key no agent holds
  const challenge = (
    await post("/trusted-surface/keys/challenge", { purpose: "agent_proposal" })
  ).body;
  const record = jcs({
    v: 1,
    purpose: "countersign.agent.proposal.v1",
    challenge_id: challenge.challenge_id,
    challenge: challenge.nonce,
    agent_thumbprint: thumbprint(jwk),
    origin: base,
    proposal: terms,
  });
  return post("/trusted-surface/proposals", {
    challenge_id: challenge.challenge_id,
    agent_jwk: jwk,
    proposal: terms,
    origin: base,
    signature: sign(key, record),
  });
}

// Proposals the backend would refuse, which a test wants the PAGE to be shown anyway (a compromised
// backend or a proxy): the id of a good proposal, and the view to serve for it instead.
const overrides = new Map();

// `#proposal=<id>` for a proposal object. A proposal the backend refuses is filed as a good one and
// served to the page in its crafted form.
export async function hashFor(value) {
  if (typeof value === "string") return `#proposal=${value}`;
  const filed = await fileProposal(value);
  if (filed.status === 201) return `#proposal=${filed.body.proposal_id}`;
  const id = (await fileProposal(goodProposal())).body.proposal_id;
  overrides.set(id, {
    proposal_id: id,
    expires_us: Date.now() * 1000 + 9e8,
    ...value,
  });
  return `#proposal=${id}`;
}

let catalogItem = null;
export function setCatalogItem(id) {
  catalogItem = id;
}
function goodProposal() {
  return proposal([{ id: catalogItem, quantity: 1 }]);
}

async function serveOverrides(context) {
  await context.route("**/trusted-surface/proposals/*", async (route) => {
    const request = route.request();
    const id = request.url().split("/").pop();
    if (request.method() === "GET" && overrides.has(id))
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(overrides.get(id)),
      });
    return route.fallback();
  });
}

// ---- the templates, written out again here and not imported from the page --------------------------

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

export function expectedExpiry(seconds) {
  const d = new Date(seconds * 1000); // the context's time zone is UTC
  const p = (n) => String(n).padStart(2, "0");
  return `${DAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}, ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} (UTC)`;
}

export function expectedMoney(minor) {
  const whole = Math.trunc(minor / 100)
    .toString()
    .replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return `$${whole}.${String(minor % 100).padStart(2, "0")}`;
}

// What the screen must say for a proposal, from the store's own description.
export function expectedTerms(prop, shop) {
  const titles = new Map(shop.items.map((i) => [i.id, i.title]));
  return {
    merchant: shop.merchant.name,
    items: prop.items.map((i) => `${i.quantity} × ${titles.get(i.id)}`),
    ceiling: expectedMoney(prop.ceiling_minor),
    expires: expectedExpiry(prop.mandate_expires_at),
  };
}

export async function shownTerms(page) {
  return page.evaluate(() => ({
    merchant: document.querySelector('[data-testid="terms-merchant"]')
      .textContent,
    items: [...document.querySelectorAll('[data-testid="terms-items"] li')].map(
      (li) => li.textContent,
    ),
    ceiling: document.querySelector('[data-testid="terms-ceiling"]')
      .textContent,
    expires: document.querySelector('[data-testid="terms-expires"]')
      .textContent,
  }));
}

export const decode = (part) =>
  JSON.parse(Buffer.from(part, "base64url").toString("utf8"));

// Every text node under <body> that is not in `known` (fingerprint groups are checked by pattern).
export async function strayText(page, known) {
  return page.evaluate((list) => {
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
    );
    const out = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const value = n.textContent.replace(/\s+/g, " ").trim();
      if (!value || n.parentElement.closest("script, noscript, style"))
        continue;
      if (n.parentElement.classList.contains("cs-fingerprint__group")) continue;
      if (!list.includes(value)) out.push(value);
    }
    return out;
  }, known);
}

export const PAGE_CHROME = [
  "Countersign",
  "Trusted Surface",
  "The private part of the key cannot be exported. Countersign never sees it.",
  "Working",
  "Done",
  "Copy",
  "Copied",
  "Action needed",
  "Problem",
  "Registered",
];

export const sameOrigin = (page) =>
  page.requests.every(
    (r) => r.url.startsWith(base) || r.url.startsWith("data:"),
  );

export async function overflow(page) {
  return page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
}

export async function targetsAreBigEnough(page) {
  for (const control of await page.locator("button, a.cs-btn, summary").all()) {
    const box = await control.boundingBox();
    if (box === null) continue;
    assert.ok(
      box.height >= 44 && box.width >= 44,
      `target ${box.width}x${box.height}`,
    );
  }
}

export async function focusRing(page) {
  await page.keyboard.press("Tab");
  const ring = await page.evaluate(() => {
    const style = getComputedStyle(document.activeElement);
    return { width: parseFloat(style.outlineWidth), style: style.outlineStyle };
  });
  assert.ok(ring.width >= 2 && ring.style !== "none", "no visible focus ring");
}

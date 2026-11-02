// Shared helpers of the browser tests: the browser, pages, the independent templates and proposals.
import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
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

export function agentKey() {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { kty, crv, x, y } = publicKey.export({ format: "jwk" });
  return { kty, crv, x, y };
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

export const hashFor = (value) =>
  `#intent=${Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url")}`;

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

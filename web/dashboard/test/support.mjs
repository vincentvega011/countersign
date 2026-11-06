// Shared helpers of the dashboard browser tests (not a test file).
import assert from "node:assert/strict";
import { chromium } from "playwright";

export const base = process.env.DASHBOARD_BASE_URL;
export const expected = JSON.parse(process.env.DASHBOARD_EXPECT ?? "{}");
assert.ok(base, "DASHBOARD_BASE_URL must name the running app");

export async function launch() {
  return chromium.launch();
}

export async function open(
  browser,
  t,
  { width = 1280, hash = "", ready } = {},
) {
  const context = await browser.newContext({
    viewport: { width, height: 1400 },
    colorScheme: "light",
  });
  const page = await context.newPage();
  page.messages = [];
  page.requests = [];
  page.on("console", (m) =>
    page.messages.push({ type: m.type(), text: m.text() }),
  );
  page.on("pageerror", (e) =>
    page.messages.push({ type: "pageerror", text: e.message }),
  );
  page.on("request", (r) => page.requests.push(r.url()));
  t.after(() => context.close());
  await page.goto(`${base}/dashboard/${hash}`);
  await page.waitForSelector(ready ?? '[data-testid="funnel-value-0"]', {
    timeout: 45000,
  });
  return page;
}

// Narrow the orders grid to one checkout with the quick filter, then click its row.
export async function selectOrder(page, id) {
  await page.fill('[data-testid="quick-filter"]', id.toLowerCase());
  const cell = page
    .locator(".ag-studio-layout-widget .ag-cell", { hasText: id })
    .first();
  await cell.waitFor({ timeout: 15000 });
  await cell.click();
  await page.waitForSelector(
    `[data-testid="order-detail"][data-checkout="${id}"]`,
    { timeout: 20000 },
  );
}

export function outsideOrigin(page) {
  return page.requests.filter((u) => !u.startsWith(base));
}

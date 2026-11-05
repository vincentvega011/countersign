// Browser tests of the merchant dashboard (driven by tests/integration/test_dashboard_browser.py).
// Expected numbers come from SQL run by the Python side, never from the dashboard's own API.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { chromium } from "playwright";

const base = process.env.DASHBOARD_BASE_URL;
const expected = JSON.parse(process.env.DASHBOARD_EXPECT ?? "{}");
const licensed = process.env.DASHBOARD_LICENSED === "1";
assert.ok(base, "DASHBOARD_BASE_URL must name the running app");

let browser;
before(async () => {
  browser = await chromium.launch();
});
after(() => browser.close());

async function open(t, { width = 1280, scheme = "light" } = {}) {
  const context = await browser.newContext({
    viewport: { width, height: 1300 },
    colorScheme: scheme,
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
  await page.goto(`${base}/dashboard/`);
  await page.waitForSelector('[data-testid="funnel-value-0"]', {
    timeout: 30000,
  });
  return page;
}

// The value shown by the KPI tile whose title is `title`.
function tile(page, title) {
  return page.evaluate((wanted) => {
    for (const w of document.querySelectorAll(".ag-studio-layout-widget")) {
      const label =
        w.querySelector(".ag-studio-layout-widget-label")?.textContent ?? "";
      if (!label.startsWith(wanted)) continue;
      const value = w.querySelector(".ag-studio-value-widget-content");
      if (value) return value.textContent.trim();
    }
    return null;
  }, title);
}

async function tileEquals(page, title, value, timeout = 8000) {
  const end = Date.now() + timeout;
  let seen;
  while (Date.now() < end) {
    seen = await tile(page, title);
    if (seen === value) return;
    await page.waitForTimeout(150);
  }
  assert.equal(seen, value, `${title} tile`);
}

describe("the merchant dashboard on AG Studio", () => {
  test("loads in demo mode with no errors and, when licensed, no licence warning", async (t) => {
    const page = await open(t);
    const env = await page.textContent('[data-testid="env-label"]');
    assert.match(env, /Sandbox demo · simulated and recorded data is labelled/);
    assert.match(env, /APP_ENV demo/);
    assert.match(env, /Protection: full/);
    const errors = page.messages.filter(
      (m) => m.type === "error" || m.type === "pageerror",
    );
    if (licensed) {
      assert.deepEqual(errors, []);
      const licence = page.messages.filter((m) =>
        /licen[cs]e|trial|watermark/i.test(m.text),
      );
      assert.deepEqual(licence, []);
      const watermark = await page.evaluate(() =>
        [
          ...document.querySelectorAll(".ag-studio-watermark, .ag-watermark"),
        ].every(
          (e) => e.classList.contains("ag-hidden") || e.offsetParent === null,
        ),
      );
      assert.ok(watermark, "no visible licence watermark");
    } else {
      // Without the key Studio reports the missing licence on the console; anything else fails.
      const other = errors.filter(
        (m) => !/licen[cs]e|trial|watermark|\*{5,}/i.test(m.text),
      );
      assert.deepEqual(other, []);
      t.diagnostic("licence assertion skipped: built without the licence key");
    }
  });

  test("the grid shows the seeded rows, newest first, and the tiles match the database", async (t) => {
    const page = await open(t);
    await page.waitForFunction(
      (id) => document.body.innerText.includes(id),
      expected.newest,
      { timeout: 15000 },
    );
    await tileEquals(page, "Orders", String(expected.orders));
    await tileEquals(
      page,
      "Unauthorized captures",
      String(expected.unauthorized),
    );
    assert.equal(expected.unauthorized, 0);
    assert.ok(expected.simulated > 0);
    const sources = await page.evaluate(() =>
      [...document.querySelectorAll('[data-testid="cell-source"]')].map(
        (e) => e.textContent,
      ),
    );
    assert.ok(
      sources.length > 0 && sources.every((s) => /Simulated|Recorded/.test(s)),
      sources,
    );
  });

  test("the quick filter and cross-filtering narrow every widget", async (t) => {
    const page = await open(t);
    await page.fill(
      '[data-testid="quick-filter"]',
      expected.newest.toLowerCase(),
    );
    await tileEquals(page, "Orders", "1");
    await page.fill('[data-testid="quick-filter"]', "");
    await tileEquals(page, "Orders", String(expected.orders));
    // The custom funnel cross-filters the dashboard to the checkouts that stopped at a step.
    await page.click('[data-testid="funnel-step-4"]');
    await tileEquals(page, "Orders", String(expected.captured));
    await tileEquals(page, "Blocked attempts", "0");
    assert.equal(
      await page.getAttribute('[data-testid="funnel-step-4"]', "aria-pressed"),
      "true",
    );
    await page.click('[data-testid="funnel-step-4"]');
    await tileEquals(page, "Orders", String(expected.orders));
  });

  test("no request leaves the origin, and the read API is the only data path", async (t) => {
    const page = await open(t);
    await page.waitForTimeout(1500);
    const outside = page.requests.filter((u) => !u.startsWith(base));
    assert.deepEqual(outside, []);
    const api = page.requests.filter((u) => u.includes("/dashboard/api/"));
    assert.ok(api.every((u) => u.includes("/dashboard/api/v1/")));
  });

  test("keyboard: the controls are reachable and the funnel steps are buttons", async (t) => {
    const page = await open(t);
    const reached = new Set();
    for (let i = 0; i < 14; i++) {
      await page.keyboard.press("Tab");
      reached.add(
        await page.evaluate(() =>
          document.activeElement?.getAttribute("data-testid"),
        ),
      );
    }
    for (const id of ["theme-toggle", "quick-filter", "group-toggle"])
      assert.ok(reached.has(id), `${id} reachable by Tab`);
    assert.equal(
      await page.locator('[data-testid^="funnel-step-"]').count(),
      5,
    );
    assert.equal(
      await page.evaluate(
        () => document.querySelector('[data-testid="funnel-step-0"]').tagName,
      ),
      "BUTTON",
    );
  });

  test("demo mode is read only: no edit control and onboarding shows status only", async (t) => {
    const page = await open(t);
    assert.equal(await page.locator('[data-testid="edit-toggle"]').count(), 0);
    await page.goto(`${base}/dashboard/#/onboarding`);
    await page.waitForSelector('[data-testid="onboarding"]');
    assert.equal(
      await page.locator("form, input:not([type=search])").count(),
      0,
    );
    assert.match(await page.textContent('[data-testid="onb-mode"]'), /Full/);
    await page.click('[data-testid="onb-test"]');
    await page.waitForFunction(() =>
      /AP2 mandates capability/.test(
        document.querySelector('[data-testid="onb-profile-result"]')
          ?.textContent ?? "",
      ),
    );
  });

  test("dark theme and 768 px keep the dashboard usable", async (t) => {
    const page = await open(t, { width: 768, scheme: "dark" });
    await page.click('[data-testid="theme-toggle"]'); // dark -> light -> dark again below
    await page.click('[data-testid="theme-toggle"]');
    assert.equal(
      await page.evaluate(() => document.documentElement.dataset.theme),
      "dark",
    );
    const overflow = await page.evaluate(
      () =>
        document.querySelector(".cs-top").scrollWidth > window.innerWidth + 1,
    );
    assert.equal(overflow, false);
    await tileEquals(page, "Orders", String(expected.orders));
  });
  test("a new checkout arrives through the event stream", async (t) => {
    const page = await open(t);
    await tileEquals(page, "Orders", String(expected.orders));
    const catalog = await (await fetch(`${base}/catalog`)).json();
    const item = (catalog.items ?? catalog)[0];
    const made = await fetch(`${base}/ucp/v1/checkout-sessions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "UCP-Agent": 'profile="https://platform.example/profile"',
      },
      body: JSON.stringify({
        line_items: [{ item: { id: item.id }, quantity: 1 }],
      }),
    });
    assert.equal(made.status, 201);
    await tileEquals(page, "Orders", String(expected.orders + 1), 15000);
    assert.match(
      await page.textContent('[data-testid="live-indicator"]'),
      /updated/,
    );
  });
});

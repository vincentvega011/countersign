// A dashboard over no rows: every KPI tile that can legitimately be zero reads 0 (L61), never blank.
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { launch, open } from "./support.mjs";

let browser;
before(async () => {
  browser = await launch();
});
after(() => browser.close());

async function tiles(page) {
  return page.evaluate(() => {
    const out = {};
    for (const w of document.querySelectorAll(".ag-studio-layout-widget")) {
      const label =
        w.querySelector(".ag-studio-layout-widget-label")?.textContent ?? "";
      const value = w.querySelector('[data-testid="kpi-value"]');
      if (value) out[label] = value.textContent.trim();
    }
    return out;
  });
}

async function settled(page, titles) {
  const end = Date.now() + 15000;
  let seen = {};
  while (Date.now() < end) {
    seen = await tiles(page);
    if (titles.every((t) => Object.keys(seen).some((k) => k.startsWith(t))))
      return seen;
    await page.waitForTimeout(150);
  }
  assert.fail(`tiles missing: ${JSON.stringify(seen)}`);
}
const valueOf = (seen, title) =>
  seen[Object.keys(seen).find((k) => k.startsWith(title))];

describe("tiles over no rows", () => {
  test("the Orders tiles read 0, computed from the data", async (t) => {
    const page = await open(browser, t);
    const seen = await settled(page, [
      "Captured",
      "Orders",
      "Blocked attempts",
      "Unauthorized captures",
    ]);
    assert.equal(valueOf(seen, "Unauthorized captures"), "0");
    assert.equal(valueOf(seen, "Orders"), "0");
    assert.equal(valueOf(seen, "Blocked attempts"), "0");
    assert.match(valueOf(seen, "Captured"), /^\D*0(\.00)?$/);
  });

  test("the Protection tiles read 0", async (t) => {
    const page = await open(browser, t, {
      hash: "#/protection",
      ready: '[data-testid="funnel-value-0"]',
    });
    const seen = await settled(page, [
      "Blocked or voided attempts",
      "Voided authorizations",
      "Open mandates",
      "Spent under open mandates",
    ]);
    assert.equal(valueOf(seen, "Blocked or voided attempts"), "0");
    assert.equal(valueOf(seen, "Voided authorizations"), "0");
    assert.equal(valueOf(seen, "Open mandates"), "0");
    assert.match(valueOf(seen, "Spent under open mandates"), /^\D*0(\.00)?$/);
  });
});

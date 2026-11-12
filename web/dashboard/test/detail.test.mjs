// The Order detail widget against a database holding one verifying bundle (driven by
// tests/integration/test_dashboard_detail_browser.py).
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import {
  expected,
  launch,
  open,
  outsideOrigin,
  selectOrder,
} from "./support.mjs";

let browser;
before(async () => {
  browser = await launch();
});
after(() => browser.close());

describe("order detail", () => {
  test("a default order is shown at first, then a selected row shows the four panels checked in the browser", async (t) => {
    const page = await open(browser, t);
    await page.waitForSelector('[data-testid="order-detail"]');
    await page.waitForSelector('[data-testid="detail-default"]');
    await selectOrder(page, expected.checkout_id);
    const text = (id) => page.textContent(`[data-testid="${id}"]`);
    await page.waitForSelector('[data-testid="merchant-auth"]');
    assert.match(await text("merchant-auth"), /Signature and hash verify/);
    assert.match(await text("checkout-lines"), /Ostrander Trail Sport Earbuds/);
    assert.match(await text("checkout-totals"), /\$45\.00/);
    assert.equal(await page.locator('[data-testid="mandate"]').count(), 2);
    for (const id of ["link-open", "link-closed"]) {
      const pills = await page
        .locator(`[data-testid="${id}"]`)
        .allTextContents();
      assert.equal(pills.length, 2);
      assert.ok(
        pills.every((p) => /Verified/.test(p)),
        pills.join(),
      );
    }
    assert.match(await text("consent-check"), /Device signature verifies/);
    assert.match(
      await text("panel-mandates"),
      /Device key\s*[A-Za-z0-9_-]{4} /,
    );
    assert.match(await text("paypal-label"), /as fetched at capture time/i);
    assert.match(await text("paypal-label"), /Not live/);
    assert.equal(
      await page
        .locator('[data-testid="paypal-table"] tr[data-differs="true"]')
        .count(),
      0,
    );
    const gate = await page
      .locator('[data-testid="gate-timeline"] li')
      .evaluateAll((l) => l.map((e) => e.dataset.passed));
    assert.equal(gate.length, 9);
    assert.ok(
      gate.every((v) => v === "true"),
      gate.join(),
    );
    assert.match(await text("log-note"), /consistency checks/);
    const entries = await page
      .locator('[data-testid="log-entries"] li')
      .allTextContents();
    assert.ok(
      entries.length > 5 && entries.every((e) => /Verified/.test(e)),
      entries.join("|"),
    );
  });

  test("a row without a bundle shows the fixed message and no invented detail", async (t) => {
    const page = await open(browser, t);
    await selectOrder(page, expected.simulated_no_bundle);
    const note = page.locator('[data-testid="no-evidence"]');
    await note.waitFor();
    assert.equal(await note.getAttribute("data-state"), "simulated");
    assert.equal(
      (await note.textContent()).trim(),
      "No evidence bundle: simulated",
    );
    assert.equal(await page.locator('[data-testid^="panel-"]').count(), 0);
  });

  test("the layout holds at 1280 px, and no request leaves the origin", async (t) => {
    const page = await open(browser, t, { width: 1280 });
    await selectOrder(page, expected.checkout_id);
    await page.waitForSelector('[data-testid="panel-gate"]');
    const sizes = await page.evaluate(() => {
      const d = document.querySelector(".cs-detail");
      return [
        d.scrollWidth,
        d.clientWidth,
        document.documentElement.scrollWidth,
        innerWidth,
      ];
    });
    assert.ok(
      sizes[0] <= sizes[1] + 1 && sizes[2] <= sizes[3] + 1,
      sizes.join(" "),
    );
    assert.deepEqual(outsideOrigin(page), []);
    const paths = page.requests.filter(
      (u) => u.includes("/evidence/") || u.includes("/dashboard/api/"),
    );
    assert.ok(
      paths.every(
        (u) => u.includes("/dashboard/api/v1/") || u.includes("/evidence/"),
      ),
    );
  });
});

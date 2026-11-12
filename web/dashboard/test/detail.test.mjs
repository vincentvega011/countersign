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

  for (const width of [1280, 1440]) {
    test(`PayPal objects names are never broken mid-word and there is one default-order note at ${width} px`, async (t) => {
      const page = await open(browser, t, { width });
      await page.waitForSelector('[data-testid="paypal-table"]');
      assert.equal(
        await page.locator('[data-testid="detail-default"]').count(),
        1,
      );
      assert.equal(await page.getByText(/Shows a default order/).count(), 0);
      // A cell whose text is not broken mid-word renders no taller than one line and at least as wide as
      // its longest word, so compare each header word and field name with its unbroken width.
      const broken = await page.evaluate(() => {
        const out = [];
        const probe = document.createElement("span");
        probe.style.cssText =
          "position:absolute;visibility:hidden;white-space:nowrap";
        document.body.appendChild(probe);
        const cells = document.querySelectorAll(
          '[data-testid="paypal-table"] th, [data-testid="paypal-table"] td.cs-name',
        );
        for (const c of cells) {
          const cs = getComputedStyle(c);
          probe.style.font = cs.font;
          const longest = Math.max(
            0,
            ...c.textContent
              .trim()
              .split(/\s+/)
              .map((w) => {
                probe.textContent = w;
                return probe.getBoundingClientRect().width;
              }),
          );
          const inner =
            c.getBoundingClientRect().width -
            parseFloat(cs.paddingLeft) -
            parseFloat(cs.paddingRight);
          if (inner + 1 < longest) out.push(c.textContent.trim());
        }
        probe.remove();
        return { out, n: cells.length };
      });
      assert.ok(broken.n > 5, "table has cells");
      assert.deepEqual(broken.out, []);
      const sizes = await page.evaluate(() => [
        document.documentElement.scrollWidth,
        innerWidth,
      ]);
      assert.ok(sizes[0] <= sizes[1] + 1, sizes.join(" "));
    });
  }
});

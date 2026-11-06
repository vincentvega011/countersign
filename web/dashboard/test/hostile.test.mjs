// Untrusted text: item titles, customer ids, claim values and PayPal fields that are HTML or script
// payloads must show as literal text and never run (driven by tests/integration/test_dashboard_detail_browser.py).
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { expected, launch, open, selectOrder } from "./support.mjs";

const IMG = '<img src=x onerror="window.__xss=1">';
const SCRIPT = "<script>window.__xss=2</script>";
const BOLD = '<b onmouseover="window.__xss=4">bold</b>';

let browser;
before(async () => {
  browser = await launch();
});
after(() => browser.close());

async function inert(page) {
  assert.equal(await page.evaluate(() => window.__xss), undefined);
  const injected = await page.evaluate(
    () =>
      document.querySelectorAll(
        ".cs-detail img, .cs-detail script, .cs-detail b, .cs-detail svg[onload], .ag-cell img, .ag-cell b",
      ).length,
  );
  assert.equal(injected, 0, "no element was created from a payload");
  const handlers = await page.evaluate(
    () =>
      document.querySelectorAll("[onerror], [onmouseover], [onload]").length,
  );
  assert.equal(handlers, 0, "no element carries an event handler attribute");
}

describe("untrusted text is data", () => {
  test("a bundle with payloads in PayPal fields and the consent shows them as literal text", async (t) => {
    const page = await open(browser, t);
    page.on("dialog", async (d) => {
      page.messages.push({ type: "dialog", text: d.message() });
      await d.dismiss();
    });
    await selectOrder(page, expected.checkout_id);
    await page.waitForSelector('[data-testid="panel-paypal"]');
    const paypal = await page.textContent('[data-testid="paypal-table"]');
    assert.ok(paypal.includes(SCRIPT), "custom_id payload shown literally");
    assert.ok(paypal.includes(IMG), "item name payload shown literally");
    const mandates = await page.textContent('[data-testid="panel-mandates"]');
    assert.ok(mandates.includes(BOLD), "consent term payload shown literally");
    await page.hover('[data-testid="panel-mandates"]');
    await page.waitForTimeout(500);
    await inert(page);
    assert.deepEqual(
      page.messages.filter((m) => m.type === "dialog"),
      [],
    );
    // The forged members are flagged as differences, in words as well as colour.
    for (const field of ["Order.custom_id", "Order.item 1 name"]) {
      const row = page.locator(
        `[data-testid="paypal-table"] tr[data-field="${field}"]`,
      );
      assert.equal(await row.getAttribute("data-differs"), "true", field);
      assert.match(await row.textContent(), /Differs/);
    }
    const ok = page.locator(
      '[data-testid="paypal-table"] tr[data-field="Order.amount"]',
    );
    assert.equal(await ok.getAttribute("data-differs"), "false");
  });

  test("an order without a bundle shows its hostile title and customer as text in the grid and header", async (t) => {
    const page = await open(browser, t);
    await selectOrder(page, expected.hostile_plain);
    const summary = await page.textContent('[data-testid="detail-summary"]');
    assert.ok(
      summary.includes('<img src=x onerror="window.__xss=3">'),
      summary,
    );
    await page.waitForTimeout(500);
    await inert(page);
    const grid = await page.evaluate(() => document.body.innerText);
    assert.ok(
      grid.includes("cus_<b onmouseover"),
      "customer payload shown literally in the grid",
    );
  });
});

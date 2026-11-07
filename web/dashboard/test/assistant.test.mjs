// Ask Countersign in Studio's assistant panel, driven by tests/integration/test_assistant_browser.py:
// recorded questions replay offline, free text outside the recordings gets the fixed message, answers come
// from templates with the database's own numbers, and every cited line has chips.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { base, expected, launch, open, outsideOrigin } from "./support.mjs";

let browser;
before(async () => {
  browser = await launch();
});
after(() => browser.close());

const READY = '[data-testid="assistant-studio"]';
async function panel(t) {
  const page = await open(browser, t, { hash: "#/assistant", ready: READY });
  await page
    .getByText("How many orders are there?")
    .waitFor({ timeout: 30000 });
  return page;
}
const messages = (page) =>
  page.locator(".ag-studio-ai-chat, .ag-studio-ai-panel").first();

describe("the Assistant view", () => {
  test("it shows the fixed note, the recorded questions and Studio's own panel", async (t) => {
    const page = await panel(t);
    assert.match(
      await page.textContent('[data-testid="assistant-note"]'),
      /generated from data with fixed templates.*only chooses what to look up/,
    );
    assert.match(
      await page.textContent('[data-testid="assistant-replay-note"]'),
      /replays recorded questions; pick a suggestion/,
    );
    for (const label of [
      "How many orders are there?",
      "Blocked by reason",
      "Open mandates",
      "What is mandate_expired?",
      "Full versus baseline",
    ])
      assert.ok(await page.getByText(label, { exact: true }).count(), label);
    const width = await page.evaluate(() => [
      document.documentElement.scrollWidth,
      innerWidth,
    ]);
    assert.ok(width[0] <= width[1] + 1, width.join(" "));
    assert.deepEqual(outsideOrigin(page), []);
  });

  test("a recorded question is answered from the data, cited, and the sources expand into chips", async (t) => {
    const page = await panel(t);
    await page.getByText("How many orders are there?", { exact: true }).click();
    const line = `There are ${expected.orders} orders in total.`;
    await page.getByText(line).first().waitFor({ timeout: 20000 });
    await page.getByText("Sources for this answer").click();
    const chips = page.locator('[data-testid="cite-chip"][data-kind="order"]');
    await chips.first().waitFor();
    assert.ok((await chips.count()) >= 1);
    const href = await chips.first().getAttribute("href");
    assert.match(href, /^#\/orders\/[A-Za-z0-9_%-]+$/);
    assert.deepEqual(outsideOrigin(page), []);
  });

  test("blocked attempts by reason match the decision log, and identifiers show literally", async (t) => {
    const page = await panel(t);
    await page.getByText("Blocked by reason", { exact: true }).click();
    const line = `There are ${expected.events} blocked or voided attempts in the decision log.`;
    await page.getByText(line).first().waitFor({ timeout: 20000 });
    const text = await page.locator("body").innerText();
    assert.ok(
      text.includes("mandate_scope_mismatch"),
      "underscores are not eaten as markdown",
    );
  });

  test("free text with no recording gets the fixed message, and no plan is invented", async (t) => {
    const page = await panel(t);
    await page.fill("textarea", "tell me a joke about attacks");
    await page.getByText("Send", { exact: true }).click();
    await page
      .getByText("This demo replays recorded questions; pick a suggestion.")
      .nth(0)
      .waitFor({ timeout: 20000 });
    assert.equal(await page.locator('[data-testid="cite-chip"]').count(), 0);
  });

  test("the edit-mode view sends only GET requests, to this origin, and no step of its chat can write", async (t) => {
    const context = await browser.newContext({
      viewport: { width: 1280, height: 1400 },
    });
    t.after(() => context.close());
    const page = await context.newPage();
    const methods = [];
    page.on("request", (r) => methods.push(`${r.method()} ${r.url()}`));
    await page.goto(`${base}/dashboard/#/assistant`);
    await page
      .getByText("How many orders are there?")
      .waitFor({ timeout: 30000 });
    await page.getByText("Blocked by reason", { exact: true }).click();
    await page.getByText("Sources for this answer").waitFor({ timeout: 20000 });
    await page.getByText("Sources for this answer").click();
    await page.fill("textarea", "unrecorded text");
    await page.getByText("Send", { exact: true }).click();
    await page
      .getByText("pick a suggestion.")
      .first()
      .waitFor({ timeout: 20000 });
    assert.ok(methods.length > 5);
    assert.deepEqual(
      methods.filter((m) => !m.startsWith("GET ") || !m.includes(base)),
      [],
    );
  });
});

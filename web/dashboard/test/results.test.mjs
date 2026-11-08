// The Results view: the frozen full evaluation from eval/reports/latest.json, read only. Expected values
// come from that file, never from the dashboard's own API.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, describe, test } from "node:test";
import { launch, open, outsideOrigin } from "./support.mjs";

const latest = JSON.parse(
  readFileSync(
    new URL("../../../eval/reports/latest.json", import.meta.url),
    "utf8",
  ),
);
const R = latest.results;

let browser;
before(async () => {
  browser = await launch();
});
after(() => browser.close());

async function tile(page, title) {
  return page.evaluate((wanted) => {
    for (const w of document.querySelectorAll(".ag-studio-layout-widget")) {
      const label =
        w.querySelector(".ag-studio-layout-widget-label")?.textContent ?? "";
      if (!label.startsWith(wanted)) continue;
      return (
        w.querySelector('[data-testid="kpi-value"]')?.textContent.trim() ?? null
      );
    }
    return null;
  }, title);
}
async function tileEquals(page, title, value) {
  const end = Date.now() + 15000;
  let seen;
  while (Date.now() < end) {
    seen = await tile(page, title);
    if (seen === value) return;
    await page.waitForTimeout(150);
  }
  assert.equal(seen, value, `${title} tile`);
}

const opened = (t) =>
  open(browser, t, {
    width: 1440,
    hash: "#/results",
    ready: '[data-testid="results-meta"]',
  });

describe("the Results view", () => {
  test("the report has a full evaluation block", () => {
    assert.ok(
      R,
      "latest.json carries no results block: run the full evaluation",
    );
    assert.equal(R.attacks.full.attacks_succeeded, 0);
  });

  test("the tiles show the report's numbers, and zeros read 0", async (t) => {
    const page = await opened(t);
    const full = (k) =>
      R.attacks.full[k] + R.adversary.full[k] + R.tasks.full[k];
    await tileEquals(
      page,
      "Unauthorized captures",
      String(full("unauthorized_captures")),
    );
    await tileEquals(
      page,
      "Attack cases that succeeded",
      String(R.attacks.full.attacks_succeeded),
    );
    await tileEquals(
      page,
      "Duplicate PayPal objects",
      String(full("duplicate_paypal_objects")),
    );
    await tileEquals(page, "False blocks", String(R.tasks.full.false_blocks));
  });

  test("the meta line names the frozen run, and the ablation table lists every ablation", async (t) => {
    const page = await opened(t);
    const meta = await page.textContent('[data-testid="results-meta"]');
    assert.ok(meta.includes(R.run_id), meta);
    const names = R.ablations.map((a) => a.flag);
    await page.waitForFunction(
      (wanted) =>
        wanted.every((n) =>
          [...document.querySelectorAll(".ag-cell")].some((c) =>
            c.textContent.includes(n),
          ),
        ),
      names,
      { timeout: 20000 },
    );
    const titles = await page
      .locator(".ag-studio-layout-widget-label")
      .allTextContents();
    for (const want of ["Ablations", "Targets", "Totals per mode"])
      assert.ok(
        titles.some((x) => x.startsWith(want)),
        `${want} widget in ${JSON.stringify(titles)}`,
      );
  });

  test("the targets grid shows met and missed groups from the report", async (t) => {
    const page = await opened(t);
    const missed = R.targets.filter((x) => x.status === "missed").length;
    assert.ok(missed >= 1, "the report is expected to list missed targets");
    await page.waitForFunction(
      () => document.body.textContent.includes("Missed"),
      null,
      { timeout: 20000 },
    );
    const text = await page.textContent("body");
    assert.ok(text.includes("Met"));
    // The Missed group row must carry the count of missed targets, never a 0 (a sum of "met" flags did).
    const row = await page.evaluate(() => {
      for (const r of document.querySelectorAll(".ag-row"))
        if (/^\s*Missed/.test(r.textContent ?? "")) return r.textContent;
      return null;
    });
    assert.ok(row, "a Missed group row");
    assert.ok(
      row.includes(String(missed)),
      `Missed row "${row}" lacks ${missed}`,
    );
  });

  test("it reads only this origin and loads without console errors", async (t) => {
    const page = await opened(t);
    await page.waitForTimeout(1500);
    assert.deepEqual(outsideOrigin(page), []);
    assert.deepEqual(
      page.messages.filter((m) => m.type === "error" || m.type === "pageerror"),
      [],
    );
  });
});

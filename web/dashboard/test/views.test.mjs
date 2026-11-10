// The Evidence view, the Protection dashboard and the attack matrix (driven by
// tests/integration/test_dashboard_detail_browser.py). Expected numbers come from SQL and from the
// eval report file, never from the dashboard's own API.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, describe, test } from "node:test";
import { base, expected, launch, open, outsideOrigin } from "./support.mjs";

const STEP_NAMES = [
  "bundle_structure", "checkout_mandate", "checkout_jwt_hash", "checkout_receipt", "payment_mandate",
  "payment_receipt", "consent_signature", "paypal_objects", "paypal_custom_id", "gate_result",
  "decision_log", "trusted_keys",
]; // prettier-ignore

let browser;
before(async () => {
  browser = await launch();
});
after(() => browser.close());

const getJson = async (path) => (await fetch(`${base}${path}`)).json();

async function tile(page, title) {
  return page.evaluate((wanted) => {
    for (const w of document.querySelectorAll(".ag-studio-layout-widget")) {
      const label =
        w.querySelector(".ag-studio-layout-widget-label")?.textContent ?? "";
      if (!label.startsWith(wanted)) continue;
      const value =
        w.querySelector('[data-testid="kpi-value"]') ??
        w.querySelector(".ag-studio-value-widget-content");
      if (value) return value.textContent.trim();
    }
    return null;
  }, title);
}
async function tileEquals(page, title, value, timeout = 10000) {
  const end = Date.now() + timeout;
  let seen;
  while (Date.now() < end) {
    seen = await tile(page, title);
    if (seen === value) return;
    await page.waitForTimeout(150);
  }
  assert.equal(seen, value, `${title} tile`);
}

async function stepsOf(page) {
  await page.waitForSelector('[data-testid="evidence-result"]');
  return page
    .locator('[data-testid="step"]')
    .evaluateAll((l) =>
      l.map((e) => ({ name: e.dataset.step, ok: e.dataset.ok === "true" })),
    );
}

describe("the Evidence view", () => {
  test("a stored bundle verifies in the browser; only the unpinned-keys step reports, as on /verify/", async (t) => {
    const page = await open(browser, t, {
      hash: `#/evidence/${expected.checkout_id}`,
      ready: '[data-testid="evidence-view"]',
    });
    await page.waitForFunction(() =>
      /Loaded the stored bundle/.test(
        document.querySelector('[data-testid="evidence-status"]')
          ?.textContent ?? "",
      ),
    );
    await page.click('[data-testid="verify-evidence"]');
    const steps = await stepsOf(page);
    assert.deepEqual(
      steps.map((s) => s.name),
      STEP_NAMES,
    );
    assert.ok(
      steps.slice(0, 11).every((s) => s.ok),
      JSON.stringify(steps),
    );
    assert.equal(steps[11].ok, false);
    assert.equal(
      await page.textContent(
        '[data-step="trusted_keys"] [data-testid="step-code"]',
      ),
      "keys_not_pinned",
    );
    assert.equal(
      await page.getAttribute('[data-testid="summary"]', "data-state"),
      "unpinned",
    );
  });

  test("the committed valid sample, with its public keys pinned, passes every step", async (t) => {
    const page = await open(browser, t, {
      hash: "#/evidence",
      ready: '[data-testid="evidence-view"]',
    });
    await page.selectOption('[data-testid="sample-select"]', "valid");
    await page.click('[data-testid="sample-load"]');
    await page.click('[data-testid="verify-evidence"]');
    const steps = await stepsOf(page);
    assert.ok(
      steps.length === 12 && steps.every((s) => s.ok),
      JSON.stringify(steps),
    );
    assert.equal(
      await page.getAttribute('[data-testid="summary"]', "data-state"),
      "passed",
    );
  });

  test("tampered samples and a tampered file from disk fail at the expected named step", async (t) => {
    const page = await open(browser, t, {
      hash: "#/evidence",
      ready: '[data-testid="evidence-view"]',
    });
    for (const name of ["amount-raised", "custom-id", "payee"]) {
      const sample = await getJson(`/dashboard/api/v1/samples/${name}`);
      assert.ok(sample.expected_first_failure, name);
      await page.selectOption('[data-testid="sample-select"]', name);
      await page.click('[data-testid="sample-load"]');
      await page.click('[data-testid="verify-evidence"]');
      await page.waitForSelector('[data-testid="summary"]');
      assert.equal(
        await page.getAttribute(
          '[data-testid="summary"]',
          "data-first-failure",
        ),
        sample.expected_first_failure,
        name,
      );
      assert.equal(
        await page.getAttribute('[data-testid="summary"]', "data-state"),
        "failed",
        name,
      );
    }
    // The same bundle from a file on disk, with no keys pinned.
    const sample = await getJson("/dashboard/api/v1/samples/custom-id");
    await page.setInputFiles('[data-testid="bundle-file"]', {
      name: "tampered.json",
      mimeType: "application/json",
      buffer: Buffer.from(sample.bundle_text),
    });
    await page.waitForFunction(() =>
      /Read the file/.test(
        document.querySelector('[data-testid="evidence-status"]')
          ?.textContent ?? "",
      ),
    );
    await page.click('[data-testid="verify-evidence"]');
    await page.waitForFunction(
      (n) =>
        document.querySelector('[data-testid="summary"]')?.dataset
          .firstFailure === n,
      sample.expected_first_failure,
    );
  });

  test("download gives the bundle the API serves, and an order without a bundle says so", async (t) => {
    const page = await open(browser, t, {
      hash: `#/evidence/${expected.checkout_id}`,
      ready: '[data-testid="evidence-view"]',
    });
    await page.waitForFunction(
      () => !document.querySelector('[data-testid="download-bundle"]').disabled,
    );
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.click('[data-testid="download-bundle"]'),
    ]);
    assert.equal(
      download.suggestedFilename(),
      `${expected.capture_id}.evidence.json`,
    );
    const body = readFileSync(await download.path(), "utf8");
    const served = await (
      await fetch(`${base}/evidence/${expected.capture_id}`)
    ).text();
    assert.equal(body, served);
    // A captured simulated order that has no stored bundle.
    const value = await page.evaluate(
      (own) =>
        [...document.querySelectorAll('[data-testid="evidence-order"] option')]
          .map((o) => o.value)
          .find((v) => v && v !== own),
      expected.checkout_id,
    );
    assert.ok(value, "the seed has captured orders without bundles");
    await page.selectOption('[data-testid="evidence-order"]', value);
    await page.waitForFunction(() =>
      /^No evidence bundle: simulated$/.test(
        document.querySelector('[data-testid="evidence-status"]')
          ?.textContent ?? "",
      ),
    );
    assert.equal(
      await page.isDisabled('[data-testid="verify-evidence"]'),
      true,
    );
    assert.equal(
      await page.isDisabled('[data-testid="download-bundle"]'),
      true,
    );
    assert.deepEqual(outsideOrigin(page), []);
  });
});

describe("the Protection view", () => {
  test("tiles equal independent database queries, and the funnel narrows the attempts", async (t) => {
    const page = await open(browser, t, {
      hash: "#/protection",
      ready: '[data-testid="funnel-value-0"]',
    });
    await tileEquals(
      page,
      "Blocked or voided attempts",
      String(expected.events),
    );
    await tileEquals(page, "Voided authorizations", String(expected.voids));
    await tileEquals(page, "Open mandates", String(expected.mandates));
    assert.ok(expected.events > 0 && expected.mandates === 3);
    await page.click('[data-testid="funnel-step-4"]');
    // A tile over no rows reads 0 (L61 fixed), never blank.
    await tileEquals(
      page,
      "Blocked or voided attempts",
      String(expected.events_of_captured),
    );
    await page.click('[data-testid="funnel-step-4"]');
    await tileEquals(
      page,
      "Blocked or voided attempts",
      String(expected.events),
    );
  });

  test("the layout holds at 1280 px and no request leaves the origin", async (t) => {
    const page = await open(browser, t, {
      hash: "#/protection",
      ready: '[data-testid="funnel-value-0"]',
    });
    await page.waitForSelector('[data-testid="attack-matrix"]');
    const sizes = await page.evaluate(() => [
      document.documentElement.scrollWidth,
      innerWidth,
    ]);
    assert.ok(sizes[0] <= sizes[1] + 1, sizes.join(" "));
    assert.deepEqual(outsideOrigin(page), []);
  });
});

describe("the attack matrix", () => {
  test("it shows every case under both modes with totals from the latest report, and labels the shared ones", async (t) => {
    const report = JSON.parse(
      readFileSync(
        new URL("../../../eval/reports/latest.json", import.meta.url),
        "utf8",
      ),
    );
    const by = new Map();
    for (const c of report.cases)
      by.set(c.case, { ...(by.get(c.case) ?? {}), [c.mode]: c });
    const wantFull = [...by.values()].filter(
      (v) => v.full.outcome === "success",
    ).length;
    const wantBase = [...by.values()].filter(
      (v) => v.baseline.outcome === "success",
    ).length;
    const wantUnauth = [...by.values()].reduce(
      (n, v) => n + v.baseline.unauthorized_captures,
      0,
    );
    const shared = [...by.values()].filter(
      (v) => v.full.outcome === v.baseline.outcome,
    ).length;
    const page = await open(browser, t, {
      hash: "#/protection",
      ready: '[data-testid="funnel-value-0"]',
    });
    await page.waitForSelector('[data-testid="matrix-table"]');
    assert.equal(
      await page.locator('[data-testid="matrix-table"] tbody tr').count(),
      by.size,
    );
    assert.equal(
      await page.textContent('[data-testid="full-succeeded"]'),
      String(wantFull),
    );
    assert.equal(wantFull, 0);
    assert.equal(
      await page.textContent('[data-testid="full-unauthorized"]'),
      "0",
    );
    assert.equal(
      await page.textContent('[data-testid="baseline-succeeded"]'),
      String(wantBase),
    );
    assert.equal(
      await page.textContent('[data-testid="baseline-unauthorized"]'),
      String(wantUnauth),
    );
    assert.match(
      await page.textContent('[data-testid="matrix-honest"]'),
      new RegExp(`^${shared} of ${by.size} cases do not separate the modes`),
    );
    assert.equal(
      await page
        .locator('[data-testid="matrix-table"] tr[data-separates="false"]')
        .count(),
      shared,
    );
    const first = await page
      .locator('[data-testid="matrix-table"] tbody tr')
      .first()
      .getAttribute("data-separates");
    assert.equal(first, "true");
  });
});

describe("Run attack", () => {
  test("it runs one scripted attack against baseline and full and shows the judge's verdicts", async (t) => {
    const page = await open(browser, t, {
      hash: "#/protection",
      ready: '[data-testid="funnel-value-0"]',
    });
    await page.waitForSelector('[data-testid="run-panel"]');
    await page.selectOption(
      '[data-testid="run-select"]',
      "protocol_downgrade_acp",
    );
    await page.click('[data-testid="run-button"]');
    await page.waitForSelector('[data-testid="run-result"]', {
      timeout: 90000,
    });
    assert.match(await page.textContent('[data-testid="run-baseline"]'), /Yes/);
    assert.match(await page.textContent('[data-testid="run-full"]'), /No/);
    assert.deepEqual(outsideOrigin(page), []);
  });
});

describe("the Policy panel", () => {
  test("it shows the server's policy hash, says it is read only and has no editing control", async (t) => {
    const page = await open(browser, t, {
      hash: "#/policy",
      ready: '[data-testid="policy-hash"]',
    });
    const api = await getJson("/dashboard/api/v1/policy");
    assert.equal(
      await page.textContent('[data-testid="policy-hash"]'),
      api.sha256,
    );
    assert.match(
      await page.textContent('[data-testid="policy-note"]'),
      /read only.*cannot be edited or versioned/,
    );
    const gate = await page.locator('[data-testid="policy-gate"] li').count();
    assert.equal(gate, api.snapshot.capture_gate_steps.length);
    const notEnabled = await page.textContent(
      '[data-testid="policy-not-enabled"]',
    );
    for (const word of ["velocity", "Category policy", "without a mandate"])
      assert.ok(notEnabled.toLowerCase().includes(word.toLowerCase()), word);
    const controls = await page
      .locator(
        '[data-testid="policy"] input, [data-testid="policy"] button, [data-testid="policy"] form, [data-testid="policy"] textarea',
      )
      .count();
    assert.equal(controls, 0);
    assert.deepEqual(outsideOrigin(page), []);
  });
});

// Layout checks from the P4 design review (P5 polish): no clipping at the common desktop widths, no
// horizontal page scroll and 44 px controls on a phone.
describe("layout", () => {
  for (const width of [1280, 1440]) {
    test(`Protection (with the Run attack panel) and Results do not overflow the page at ${width} px`, async (t) => {
      for (const hash of ["#/protection", "#/results"]) {
        const page = await open(browser, t, {
          width,
          hash,
          ready: '[data-testid="app-main"], .cs-main',
        });
        await page.waitForTimeout(1500);
        const box = await page.evaluate(() => ({
          scroll: document.documentElement.scrollWidth,
          client: document.documentElement.clientWidth,
        }));
        assert.ok(
          box.scroll <= box.client,
          `${hash} at ${width}: ${JSON.stringify(box)}`,
        );
        if (hash === "#/protection") {
          const panel = page.locator('[data-testid="attack-matrix"]');
          await panel.waitFor({ timeout: 20000 });
          const b = await panel.boundingBox();
          assert.ok(
            b.x >= 0 && b.x + b.width <= width,
            `attack matrix ${JSON.stringify(b)}`,
          );
        }
      }
    });
  }

  test("at 375 px the page does not scroll sideways and the navigation and header controls are 44 px", async (t) => {
    const page = await open(browser, t, { width: 375, ready: ".cs-nav" });
    await page.waitForTimeout(1500);
    const box = await page.evaluate(() => ({
      scroll: document.documentElement.scrollWidth,
      client: document.documentElement.clientWidth,
    }));
    assert.ok(box.scroll <= box.client, JSON.stringify(box));
    const small = await page.evaluate(
      () =>
        [...document.querySelectorAll(".cs-nav__item, .cs-top button")]
          .map((e) => e.getBoundingClientRect())
          .filter((r) => r.height < 43.5 || r.width < 43.5).length,
    );
    assert.equal(small, 0);
  });
});

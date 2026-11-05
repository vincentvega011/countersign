// Browser tests of the evidence verifier page, against the running app (VERIFY_BASE_URL).
// Run by tests/integration/test_verify_page_browser.py.
import assert from "node:assert/strict";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const base = process.env.VERIFY_BASE_URL;
assert.ok(base, "VERIFY_BASE_URL must name the running app");
const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(here, "..", "..", "..", "tests", "vectors", "evidence");
const shots = join(here, "..", ".artifacts");
mkdirSync(shots, { recursive: true });
const read = (name) => readFileSync(join(VECTORS, name), "utf8");
const index = JSON.parse(read("index.json"));
const VALID = read("valid.json");
const CAPTURE = JSON.parse(VALID).capture_id;

let browser;
before(async () => {
  browser = await chromium.launch();
});
after(() => browser.close());

async function open(t, { width = 375, scheme = "light" } = {}) {
  const context = await browser.newContext({
    viewport: { width, height: 900 },
    colorScheme: scheme,
    hasTouch: width <= 500,
  });
  t.after(() => context.close());
  const page = await context.newPage();
  page.requests = [];
  page.on("request", (r) => page.requests.push(r.url()));
  await page.goto(`${base}/verify/`);
  await page.waitForLoadState("networkidle");
  return page;
}

// Paste, optionally pin, verify; returns the requests made while verifying.
async function check(page, bundle, { pin = true } = {}) {
  await page.fill("#bundle-text", bundle);
  await page.fill("#merchant-key", pin ? read("merchant.key.json") : "");
  await page.fill("#platform-key", pin ? read("platform.key.json") : "");
  const before = page.requests.length;
  await page.click("#verify");
  await page.waitForSelector('[data-testid="summary"]');
  return page.requests.slice(before);
}

const summary = (page) =>
  page.$eval('[data-testid="summary"]', (n) => ({
    state: n.dataset.state,
    first: n.dataset.firstFailure ?? null,
  }));
const steps = (page) =>
  page.$$eval('[data-testid="step"]', (nodes) =>
    nodes.map((n) => ({
      name: n.dataset.step,
      ok: n.dataset.ok === "true",
      first: n.dataset.first === "true",
      code: n.querySelector('[data-testid="step-code"]')?.textContent ?? null,
    })),
  );

test("a valid bundle with pinned keys passes every step, and nothing leaves the page", async (t) => {
  const page = await open(t);
  const during = await check(page, VALID);
  assert.deepEqual(during, [], "a request was made while verifying");
  assert.deepEqual(await summary(page), { state: "passed", first: null });
  const list = await steps(page);
  assert.equal(list.length, 12);
  assert.ok(list.every((s) => s.ok && !s.first));
  const notice = await page.$eval('[data-testid="keys-notice"]', (n) => [
    n.dataset.pinned,
    n.textContent,
  ]);
  assert.equal(notice[0], "2");
  assert.match(notice[1], /Both keys are pinned/);
  assert.ok(page.requests.every((u) => u.startsWith(base)));
});

test("without pinned keys the page says the keys come from the bundle and are not pinned", async (t) => {
  const page = await open(t);
  await check(page, VALID, { pin: false });
  assert.deepEqual(await summary(page), {
    state: "unpinned",
    first: "trusted_keys",
  });
  const notice = await page.textContent('[data-testid="keys-notice"]');
  assert.match(notice, /taken from the bundle itself and are not pinned/);
  const failed = (await steps(page)).filter((s) => !s.ok);
  assert.deepEqual(failed, [
    { name: "trusted_keys", ok: false, first: true, code: "keys_not_pinned" },
  ]);
});

const TAMPERED = [
  "tampered/checkout_amount_raised.json",
  "tampered/checkout_receipt_reference.json",
  "tampered/payment_closed_signature.json",
  "tampered/consent_record_altered.json",
  "tampered/paypal_capture_amount.json",
  "tampered/paypal_custom_id.json",
  "tampered/log_middle_entry_dropped.json",
  "tampered/gate_step_missing.json",
  "strict/true_for_version.json",
  "strict/infinity_amount.json",
];

for (const file of TAMPERED) {
  const entry = [...index.tampered, ...index.strict].find(
    (e) => e.file === file,
  );
  test(`${file} fails at ${entry.first_failure}, highlighted`, async (t) => {
    const page = await open(t);
    const during = await check(page, read(file));
    assert.deepEqual(during, []);
    assert.deepEqual(await summary(page), {
      state: "failed",
      first: entry.first_failure,
    });
    const list = await steps(page);
    const first = list.filter((s) => s.first);
    assert.equal(first.length, 1);
    assert.equal(first[0].name, entry.first_failure);
    if (entry.code) assert.equal(first[0].code, entry.code);
    const highlighted = await page.$eval(
      ".vf-step--first",
      (n) => n.dataset.step,
    );
    assert.equal(highlighted, entry.first_failure);
  });
}

test("load by capture id fetches only that bundle from the same origin", async (t) => {
  const page = await open(t);
  const before = page.requests.length;
  await page.fill("#capture-id", CAPTURE);
  await page.click("#load");
  await page.waitForFunction(() =>
    document
      .querySelector('[data-testid="status"]')
      .textContent.startsWith("Loaded"),
  );
  assert.deepEqual(page.requests.slice(before), [
    `${base}/evidence/${CAPTURE}`,
  ]);
  const during = await check(page, await page.inputValue("#bundle-text"));
  assert.deepEqual(during, []);
  assert.equal((await summary(page)).state, "passed");

  await page.fill("#capture-id", "NO_SUCH_CAPTURE");
  await page.click("#load");
  await page.waitForFunction(() =>
    document
      .querySelector('[data-testid="status"]')
      .textContent.startsWith("No stored"),
  );
  await page.fill("#capture-id", "bad id!");
  const count = page.requests.length;
  await page.click("#load");
  assert.equal(page.requests.length, count, "a malformed id is not sent");
});

test("a file chosen from disk is read locally", async (t) => {
  const page = await open(t);
  await page.setInputFiles(
    "#bundle-file",
    join(VECTORS, "tampered", "paypal_status.json"),
  );
  await page.waitForFunction(() =>
    document
      .querySelector('[data-testid="status"]')
      .textContent.startsWith("Read"),
  );
  await check(page, await page.inputValue("#bundle-text"));
  assert.equal((await summary(page)).first, "paypal_objects");
});

test("a key that is not JSON stops before anything is checked", async (t) => {
  const page = await open(t);
  await page.fill("#bundle-text", VALID);
  await page.fill("#merchant-key", "{not json");
  await page.click("#verify");
  assert.match(
    await page.textContent('[data-testid="status"]'),
    /merchant key is not a valid/,
  );
  assert.equal(await page.$('[data-testid="summary"]'), null);
});

for (const width of [375, 1280])
  for (const scheme of ["light", "dark"])
    test(`layout at ${width} px, ${scheme}: no overflow, 44 px targets, visible focus`, async (t) => {
      const page = await open(t, { width, scheme });
      await check(page, read("tampered/paypal_custom_id.json"));
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - window.innerWidth,
      );
      assert.ok(overflow <= 0, `horizontal overflow ${overflow}`);
      for (const control of await page
        .locator("button, input:not([type=file]), textarea")
        .all()) {
        const box = await control.boundingBox();
        if (box === null) continue;
        assert.ok(
          box.height >= 44 && box.width >= 44,
          `target ${box.width}x${box.height}`,
        );
      }
      await page.focus("#bundle-text");
      await page.keyboard.press("Tab");
      const ring = await page.evaluate(() => {
        const s = getComputedStyle(document.activeElement);
        return { width: parseFloat(s.outlineWidth), style: s.outlineStyle };
      });
      assert.ok(
        ring.width >= 2 && ring.style !== "none",
        "no visible focus ring",
      );
      await page.screenshot({
        path: join(shots, `verify-${scheme}-${width}.png`),
        fullPage: true,
      });
    });

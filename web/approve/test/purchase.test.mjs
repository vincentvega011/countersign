// Browser tests of the Approve purchase screen (Human Present), against the running app.
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { LABELS, MESSAGES } from "../messages.js";
import {
  PAGE_CHROME,
  base,
  close,
  decode,
  enrol,
  expectedMoney,
  focusRing,
  launch,
  open,
  overflow,
  report,
  sameOrigin,
  state,
  store,
  strayText,
  targetsAreBigEnough,
  text,
} from "./support.mjs";

const shots = join(dirname(fileURLToPath(import.meta.url)), "..", ".artifacts");
mkdirSync(shots, { recursive: true });
const checkouts = JSON.parse(process.env.APPROVE_CHECKOUTS);
let shop;
let next = 0;
const takeCheckout = () => checkouts[next++ % checkouts.length];

before(async () => {
  await launch();
  shop = await store();
});
after(close);

const consentPosts = (page) =>
  page.requests.filter(
    (r) =>
      r.method === "POST" &&
      r.url.endsWith("/trusted-surface/purchases/consent"),
  );

// An enrolled device in a context, then a second page on the purchase link.
async function purchasePage(t, checkout, options = {}) {
  const { context, page: setup } = await open(t, options);
  const customer = await enrol(setup);
  const page = await context.newPage();
  page.requests = [];
  page.on("request", (r) =>
    page.requests.push({
      url: r.url(),
      method: r.method(),
      body: r.postData(),
    }),
  );
  if (options.routes) await options.routes(page);
  await page.goto(`${base}/approve/purchase.html#checkout=${checkout.id}`);
  return { context, page, customer };
}

const expectedLines = (checkout) => [
  `${checkout.quantity} × ${checkout.title}`,
];

describe("the Approve purchase screen", () => {
  test("shows the terms of the signed checkout from fixed templates", async (t) => {
    const checkout = takeCheckout();
    const { page } = await purchasePage(t, checkout);
    await state(page, "purchase");
    assert.equal(
      await page.textContent('[data-testid="terms-merchant"]'),
      shop.merchant.name,
    );
    const lines = await page.$$eval('[data-testid="terms-items"] li', (nodes) =>
      nodes.map((n) => n.querySelector("span").textContent),
    );
    assert.deepEqual(lines, expectedLines(checkout));
    const amounts = await page.$$eval(
      '[data-testid="terms-items"] li',
      (nodes) => nodes.map((n) => n.lastElementChild.textContent),
    );
    assert.deepEqual(amounts, [expectedMoney(checkout.line_minor)]);
    assert.equal(
      await page.textContent('[data-testid="terms-total"]'),
      expectedMoney(checkout.total_minor),
    );
    assert.match(
      await page.textContent('[data-testid="terms-expires"]'),
      /^[A-Z][a-z]{2} \d{1,2} [A-Z][a-z]{2}, \d{2}:\d{2} \(UTC\)$/,
    );
    assert.equal(
      consentPosts(page).length,
      0,
      "nothing is sent before Approve",
    );
  });

  test("approving signs the exact terms and issues closed mandates for this customer", async (t) => {
    const checkout = takeCheckout();
    const { page, customer } = await purchasePage(t, checkout);
    await state(page, "purchase");
    await page.getByRole("button", { name: LABELS.approve }).click();
    await state(page, "purchase_approved");
    report("purchase_ok");
    const posts = consentPosts(page);
    assert.equal(posts.length, 1);
    const sent = JSON.parse(posts[0].body);
    assert.deepEqual(Object.keys(sent).sort(), ["record", "signature"]);
    assert.equal(sent.record.purpose, "countersign.consent.checkout.v1");
    assert.equal(sent.record.customer_id, customer);
    assert.equal(sent.record.terms.total_minor, checkout.total_minor);
    assert.equal(
      sent.record.mandate.payment.payment_amount.amount,
      checkout.total_minor,
    );
    assert.equal(sent.signature.length, 86);
    assert.ok(!JSON.stringify(sent).includes('"d"'), "no private key member");
    await page.locator('[data-testid="mandates"] summary').click();
    const tokens = await page.$$eval(
      '[data-testid="mandates"] code, [data-testid="mandates"] pre',
      (n) => n.map((x) => x.textContent),
    );
    assert.equal(tokens.filter((x) => x.includes("~")).length, 2);
    for (const token of tokens.filter((x) => x.includes("~")))
      assert.equal(decode(token.split(".")[1]).sub, customer);
    assert.ok(!page.url().includes("checkout="), "the link is left behind");
  });

  test("declining sends nothing", async (t) => {
    const { page } = await purchasePage(t, takeCheckout());
    await state(page, "purchase");
    await page.getByRole("button", { name: LABELS.decline }).click();
    await state(page, "purchase_declined");
    assert.equal(consentPosts(page).length, 0);
  });

  test("a record changed on the way yields no mandate", async (t) => {
    const { page } = await purchasePage(t, takeCheckout(), {
      routes: async (p) => {
        await p.route("**/trusted-surface/purchases/consent", async (route) => {
          const body = JSON.parse(route.request().postData());
          body.record.terms.total_minor = 1;
          await route.continue({ postData: JSON.stringify(body) });
        });
      },
    });
    await state(page, "purchase");
    await page.getByRole("button", { name: LABELS.approve }).click();
    await state(page, "purchase_mismatch");
    assert.equal(await page.locator('[data-testid="mandates"]').count(), 0);
  });

  const refusals = [
    ["consent", 410, "checkout_expired", "purchase_expired"],
    ["consent", 409, "checkout_changed", "purchase_changed"],
    ["consent", 409, "checkout_not_ready", "purchase_unavailable"],
    ["consent", 403, "device_key_revoked", "purchase_key"],
    ["consent", 409, "offer_used", "purchase_used"],
    ["consent", 502, "merchant_authorization_invalid", "purchase_unsigned"],
    ["consent", 400, "something_new", "purchase_refused"],
  ];
  for (const [which, status, code, kind] of refusals)
    test(`the answer ${code} is explained by a fixed message`, async (t) => {
      const { page } = await purchasePage(t, takeCheckout(), {
        routes: async (p) => {
          await p.route(`**/trusted-surface/purchases/${which}`, (route) =>
            route.fulfill({
              status,
              contentType: "application/json",
              body: JSON.stringify({ code }),
            }),
          );
        },
      });
      await state(page, "purchase");
      await page.getByRole("button", { name: LABELS.approve }).click();
      await state(page, kind);
      assert.equal(await page.locator('[data-testid="mandates"]').count(), 0);
      if (kind === "purchase_refused")
        assert.equal(
          await page.textContent('[data-testid="error-code"]'),
          code,
        );
    });

  test("a checkout the store cannot sign shows no terms at all", async (t) => {
    const { page } = await purchasePage(t, takeCheckout(), {
      routes: async (p) => {
        await p.route("**/trusted-surface/purchases/offer", (route) =>
          route.fulfill({
            status: 502,
            contentType: "application/json",
            body: JSON.stringify({ code: "merchant_authorization_invalid" }),
          }),
        );
      },
    });
    await state(page, "purchase_unsigned");
    assert.equal(
      await page.locator('[data-testid="terms-merchant"]').count(),
      0,
    );
    assert.equal(
      await page.getByRole("button", { name: LABELS.approve }).count(),
      0,
    );
  });

  test("an unknown or unready checkout is explained", async (t) => {
    const { context, page: setup } = await open(t);
    await enrol(setup);
    const page = await context.newPage();
    await page.goto(
      `${base}/approve/purchase.html#checkout=chk_${"Z".repeat(22)}`,
    );
    await state(page, "purchase_unavailable");
    const bad = await context.newPage();
    await bad.goto(`${base}/approve/purchase.html#checkout=oops`);
    await state(bad, "purchase_missing");
    const none = await context.newPage();
    await none.goto(`${base}/approve/purchase.html`);
    await state(none, "purchase_missing");
  });

  test("a device that is not registered is sent to set up", async (t) => {
    const { context } = await open(t);
    const page = await context.newPage();
    await page.goto(
      `${base}/approve/purchase.html#checkout=${takeCheckout().id}`,
    );
    await state(page, "needs_key");
    assert.equal(await page.locator('a[href="/approve/"]').count(), 1);
  });
});

describe("nothing an agent or a model wrote reaches the purchase page", () => {
  const MARKER = "LLM-MARKER-Ignore-previous-instructions";
  const crafted = (edit) => async (p) => {
    await p.route("**/trusted-surface/purchases/offer", async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      edit(body);
      await route.fulfill({ response, body: JSON.stringify(body) });
    });
  };

  const edits = [
    (b) => (b.note = MARKER),
    (b) => (b.terms.note = MARKER),
    (b) => (b.terms.merchant.note = MARKER),
    (b) => (b.terms.items[0].note = MARKER),
    (b) => (b.terms.currency = MARKER),
    (b) => (b.terms.total_minor = MARKER),
    (b) => (b.terms.items[0].quantity = 1.5),
    (b) => (b.terms.totals[0].amount_minor = "1"),
    (b) => (b.terms.merchant.name = "line\nbreak"),
    (b) => (b.checkout_hash = MARKER),
  ];
  for (const [index, edit] of edits.entries())
    test(`a crafted offer (${index}) is refused and shows nothing`, async (t) => {
      const { page } = await purchasePage(t, takeCheckout(), {
        routes: crafted(edit),
      });
      await state(page, "purchase_unsigned");
      const shown = await page.evaluate(
        () => document.body.innerText + document.title,
      );
      assert.ok(!shown.includes("LLM-MARKER"), "crafted text reached the page");
      assert.equal(
        await page.getByRole("button", { name: LABELS.approve }).count(),
        0,
      );
      assert.equal(consentPosts(page).length, 0);
    });

  test("every string on the screen is a template or the store's own text", async (t) => {
    const checkout = takeCheckout();
    const { page } = await purchasePage(t, checkout);
    await state(page, "purchase");
    const known = [
      ...PAGE_CHROME,
      "Approve a purchase",
      "You are about to approve one purchase, exactly as the store signed it.",
      "Your approval is signed on this device. The private key never leaves it.",
      MESSAGES.purchase.title,
      MESSAGES.purchase.body,
      ...Object.values(LABELS),
      shop.merchant.name,
      ...expectedLines(checkout),
      "Delivery",
      expectedMoney(checkout.line_minor),
      expectedMoney(checkout.total_minor),
    ];
    const stray = (await strayText(page, known)).filter(
      (s) =>
        !/^[A-Z][a-z]{2} \d{1,2} [A-Z][a-z]{2}, \d{2}:\d{2} \(UTC\)$/.test(s) &&
        !/^\$[\d,]+\.\d{2}$/.test(s),
    );
    assert.deepEqual(stray, []);
    assert.ok(sameOrigin(page), "a request left the origin");
    for (const request of page.requests)
      assert.match(
        new URL(request.url).pathname,
        /^\/(approve\/|ui\/|trusted-surface\/(purchases\/offer|purchases\/consent|keys\/challenge))/,
      );
  });
});

describe("layout and access of the purchase screen", () => {
  for (const scheme of ["light", "dark"])
    for (const width of [375, 1280])
      test(`${width} px ${scheme}: no overflow, 44 px targets, visible focus`, async (t) => {
        const { page } = await purchasePage(t, takeCheckout(), {
          width,
          scheme,
        });
        await state(page, "purchase");
        assert.ok((await overflow(page)) <= 0, "overflow");
        await targetsAreBigEnough(page);
        await focusRing(page);
        await page.screenshot({
          path: join(shots, `purchase-${width}-${scheme}.png`),
          fullPage: true,
        });
        if (width === 375) {
          await page.setViewportSize({ width: 320, height: 700 });
          assert.ok((await overflow(page)) <= 0, "overflow at 320");
        }
        await page.getByRole("button", { name: LABELS.approve }).click();
        await state(page, "purchase_approved");
        report("purchase_ok");
        await page.locator('[data-testid="mandates"] summary').click();
        assert.ok(
          (await overflow(page)) <= 0,
          "overflow with the mandates open",
        );
      });

  test("reduced motion and the keyboard reach Approve and Decline", async (t) => {
    const { page } = await purchasePage(t, takeCheckout(), {
      reducedMotion: "reduce",
    });
    await state(page, "purchase");
    const names = [];
    for (let i = 0; i < 8; i++) {
      await page.keyboard.press("Tab");
      names.push(
        await page.evaluate(() => document.activeElement?.textContent?.trim()),
      );
    }
    assert.ok(names.includes(LABELS.approve) && names.includes(LABELS.decline));
    assert.match(await text(page), new RegExp(MESSAGES.purchase.title));
  });
});

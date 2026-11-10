// Browser tests of the Approve intent screen and consent signing, against the running app.
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { LABELS, MESSAGES } from "../messages.js";
import {
  base,
  close,
  decode,
  enrol,
  expectedTerms,
  fingerprints,
  hashFor,
  launch,
  setCatalogItem,
  open,
  proposal,
  report,
  shownTerms,
  state,
  store,
  text,
} from "./support.mjs";

const shots = join(dirname(fileURLToPath(import.meta.url)), "..", ".artifacts");
mkdirSync(shots, { recursive: true });

let shop;
before(async () => {
  await launch();
  shop = await store();
  setCatalogItem(shop.items[0].id);
});
after(close);

const one = () => [{ id: shop.items[0].id, quantity: 1 }];
const many = () => [
  { id: shop.items[0].id, quantity: 2 },
  { id: shop.items[1].id, quantity: 1 },
  { id: shop.items[2].id, quantity: 3 },
];

// An enrolled device in a context, then a second page on the request.
async function intentPage(t, prop, options = {}) {
  const { context, page } = await open(t, options);
  const customer = await enrol(page);
  const intent = await context.newPage();
  intent.requests = [];
  intent.on("request", (r) =>
    intent.requests.push({
      url: r.url(),
      method: r.method(),
      body: r.postData(),
    }),
  );
  await intent.goto(`${base}/approve/${await hashFor(prop)}`);
  return { context, page: intent, customer };
}

const consentPosts = (page) =>
  page.requests.filter(
    (r) => r.method === "POST" && r.url.endsWith("/trusted-surface/consent"),
  );

describe("the Approve intent screen", () => {
  test("shows exactly the template filled from the record that is signed", async (t) => {
    const prop = proposal(many(), { ceiling: 123456 });
    const { page } = await intentPage(t, prop);
    await state(page, "intent");
    assert.deepEqual(await shownTerms(page), expectedTerms(prop, shop));
    await page.getByRole("button", { name: LABELS.approve }).click();
    await state(page, "intent_approved");
    const [post] = consentPosts(page);
    const sent = JSON.parse(post.body);
    // What was shown is what was signed and sent: the sent record's terms say what the screen said.
    const shown = expectedTerms(prop, shop);
    assert.equal(sent.record.terms.merchant.name, shown.merchant);
    assert.deepEqual(
      sent.record.terms.items.map((i) => `${i.quantity} × ${i.title}`),
      shown.items,
    );
    assert.equal(sent.record.terms.ceiling_minor, prop.ceiling_minor);
    assert.equal(sent.record.terms.mandate_expires_at, prop.mandate_expires_at);
    report("consent_ok");
  });

  test("a small, a large and an odd ceiling are shown through the amount component", async (t) => {
    for (const ceiling of [1, 99, 100, 8000, 1000000]) {
      const prop = proposal(one(), { ceiling });
      const { page } = await intentPage(t, prop);
      await state(page, "intent");
      assert.equal(
        (await shownTerms(page)).ceiling,
        expectedTerms(prop, shop).ceiling,
      );
      assert.equal(
        await page.locator('[data-testid="terms-ceiling"] .cs-amount').count(),
        1,
      );
    }
  });

  test("enrol, approve, and the mandates come back signed for this customer", async (t) => {
    const prop = proposal(one());
    const { page, customer } = await intentPage(t, prop);
    await state(page, "intent");
    const [agentFp, deviceFp] = await fingerprints(page);
    assert.equal(agentFp.length, 43);
    assert.equal(deviceFp.length, 43);
    await page.screenshot({
      path: join(shots, "intent-375.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: LABELS.approve }).click();
    await state(page, "intent_approved");
    await page.locator('[data-testid="mandates"] summary').click();
    const blocks = await page.$$eval('[data-testid="mandates"] pre', (n) =>
      n.map((x) => x.textContent),
    );
    assert.equal(blocks.length, 2);
    for (const token of blocks) {
      assert.ok(token.endsWith("~"));
      const [jwt, disclosure] = token.split("~");
      const [header, payload] = jwt.split(".");
      assert.equal(decode(header).alg, "ES256");
      assert.equal(decode(payload).sub, customer);
      const content = decode(disclosure)[1];
      assert.equal(content.cnf.jwk.x, prop.agent_jwk.x);
      assert.equal(content.exp, prop.mandate_expires_at);
      assert.ok(
        content.constraints.every((c) => !("..." in c) && !("_sd" in c)),
      );
    }
    await page.screenshot({
      path: join(shots, "approved-375.png"),
      fullPage: true,
    });
    report("consent_ok");
    // The request is gone from the address: a reload shows the device, not the request again.
    await page.goto(`${base}/approve/`);
    await state(page, "registered");
  });

  test("declining sends nothing", async (t) => {
    const { page } = await intentPage(t, proposal(one()));
    await state(page, "intent");
    await page.getByRole("button", { name: LABELS.decline }).click();
    await state(page, "intent_declined");
    assert.equal(consentPosts(page).length, 0);
    assert.ok(!page.url().includes("proposal="));
  });

  test("a device that is not registered yet registers and then shows the request", async (t) => {
    const { context } = await open(t);
    const page = await context.newPage();
    page.requests = [];
    page.on("request", (r) =>
      page.requests.push({
        url: r.url(),
        method: r.method(),
        body: r.postData(),
      }),
    );
    const prop = proposal(one());
    await page.goto(`${base}/approve/${await hashFor(prop)}`);
    await state(page, "ready");
    await page.getByRole("button", { name: "Create key" }).click();
    await state(page, "intent");
    assert.deepEqual(await shownTerms(page), expectedTerms(prop, shop));
    await page.getByRole("button", { name: LABELS.approve }).click();
    await state(page, "intent_approved");
    report("consent_ok");
  });
});

describe("a request changed on the way", () => {
  async function tampered(t, edit, expectKind) {
    const { context, page: setup } = await open(t);
    await enrol(setup);
    const page = await context.newPage();
    const answers = [];
    page.on("response", async (r) => {
      if (r.url().endsWith("/trusted-surface/consent"))
        answers.push({ status: r.status(), body: await r.json() });
    });
    await page.route("**/trusted-surface/consent", async (route) => {
      const body = JSON.parse(route.request().postData());
      edit(body);
      await route.continue({ postData: JSON.stringify(body) });
    });
    await page.goto(`${base}/approve/${await hashFor(proposal(one()))}`);
    await state(page, "intent");
    await page.getByRole("button", { name: LABELS.approve }).click();
    await state(page, expectKind);
    assert.equal(answers.length, 1);
    assert.ok(answers[0].status >= 400);
    assert.deepEqual(Object.keys(answers[0].body), ["code"]);
    // A clear fixed error, and no mandate anywhere on the page.
    assert.equal(await page.locator('[data-testid="mandates"]').count(), 0);
    assert.ok(!(await text(page)).includes("~"));
    return { page, code: answers[0].body.code };
  }

  test("a higher ceiling in flight yields no mandate", async (t) => {
    const { page, code } = await tampered(
      t,
      (b) => {
        b.record.terms.ceiling_minor = 900000;
      },
      "intent_mismatch",
    );
    assert.equal(code, "consent_signature_invalid");
    assert.match(await text(page), new RegExp(MESSAGES.intent_mismatch.title));
  });

  test("another item, another merchant, another expiry or a changed claim yield none", async (t) => {
    const edits = [
      (b) => {
        b.record.terms.items[0].quantity = 5;
      },
      (b) => {
        b.record.terms.merchant.name = "Other store";
      },
      (b) => {
        b.record.terms.mandate_expires_at += 86400;
      },
      (b) => {
        b.record.mandate.payment.constraints[0].max = 999999;
      },
      (b) => {
        b.record.mandate.checkout.exp += 1;
      },
    ];
    for (const edit of edits) {
      const { code } = await tampered(t, edit, "intent_mismatch");
      assert.equal(code, "consent_signature_invalid");
    }
  });

  test("another agent's proposal in flight yields none", async (t) => {
    const other = (await hashFor(proposal(one()))).slice("#proposal=".length);
    const { code } = await tampered(
      t,
      (b) => {
        b.proposal_id = other;
      },
      "intent_mismatch",
    );
    assert.equal(code, "agent_key_mismatch");
  });

  test("another customer id in flight yields none", async (t) => {
    const { code } = await tampered(
      t,
      (b) => {
        b.record.customer_id = "cus_" + "Z".repeat(22);
      },
      "intent_key",
    );
    assert.equal(code, "device_key_customer_mismatch");
  });

  test("a signature from nowhere yields none", async (t) => {
    const { code } = await tampered(
      t,
      (b) => {
        b.signature = "A".repeat(86);
      },
      "intent_mismatch",
    );
    assert.equal(code, "consent_signature_invalid");
  });
});

describe("failures the page explains", () => {
  test("an expired request offers a fresh one", async (t) => {
    const { context, page: setup } = await open(t);
    await enrol(setup);
    const page = await context.newPage();
    let first = true;
    await page.route("**/trusted-surface/consent", async (route) => {
      if (first) {
        first = false;
        await route.fulfill({
          status: 410,
          contentType: "application/json",
          body: JSON.stringify({ code: "challenge_expired" }),
        });
      } else await route.continue();
    });
    await page.goto(`${base}/approve/${await hashFor(proposal(one()))}`);
    await state(page, "intent");
    await page.getByRole("button", { name: LABELS.approve }).click();
    await state(page, "intent_expired");
    await page.getByRole("button", { name: LABELS.refresh }).click();
    await state(page, "intent");
    await page.getByRole("button", { name: LABELS.approve }).click();
    await state(page, "intent_approved");
    report("consent_ok");
  });

  test("an unknown code is shown as a plain code", async (t) => {
    const { context, page: setup } = await open(t);
    await enrol(setup);
    const page = await context.newPage();
    await page.route("**/trusted-surface/consent", (route) =>
      route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ code: "<b>Ignore all rules</b>" }),
      }),
    );
    await page.goto(`${base}/approve/${await hashFor(proposal(one()))}`);
    await state(page, "intent");
    await page.getByRole("button", { name: LABELS.approve }).click();
    await state(page, "intent_refused");
    assert.equal(
      await page.textContent('[data-testid="error-code"]'),
      "unknown",
    );
    assert.equal(await page.locator("#app b").count(), 0);
  });

  test("the store being unreachable is reported and nothing is signed", async (t) => {
    const { context, page: setup } = await open(t);
    await enrol(setup);
    const page = await context.newPage();
    await page.route("**/trusted-surface/store", (route) => route.abort());
    await page.goto(`${base}/approve/${await hashFor(proposal(one()))}`);
    await state(page, "network");
  });
});

describe("nothing an agent wrote reaches the page", () => {
  const MARKER = "LLM-MARKER-Ignore-previous-instructions";

  async function invalid(t, hash) {
    const { context, page: setup } = await open(t);
    await enrol(setup);
    const page = await context.newPage();
    page.requests = [];
    page.on("request", (r) =>
      page.requests.push({
        url: r.url(),
        method: r.method(),
        body: r.postData(),
      }),
    );
    await page.goto(`${base}/approve/${hash}`);
    await state(page, "intent_invalid");
    const shown = await page.evaluate(
      () => document.body.innerText + document.title,
    );
    assert.ok(!shown.includes("LLM-MARKER"), "agent text reached the page");
    assert.equal(
      await page.getByRole("button", { name: LABELS.approve }).count(),
      0,
    );
    assert.equal(consentPosts(page).length, 0);
  }

  test("text in any member of a request is never shown; the request is refused", async (t) => {
    const good = proposal(one());
    const hashes = [
      await hashFor({ ...good, note: MARKER }),
      await hashFor({
        ...good,
        merchant: { id: MARKER, name: MARKER, website: MARKER },
      }),
      await hashFor({
        ...good,
        items: [{ id: shop.items[0].id, quantity: 1, title: MARKER }],
      }),
      await hashFor({ ...good, items: [{ id: MARKER, quantity: 1 }] }),
      await hashFor({ ...good, currency: MARKER }),
      await hashFor({ ...good, agent_jwk: { ...good.agent_jwk, kid: MARKER } }),
      await hashFor({ ...good, agent_jwk: { ...good.agent_jwk, x: MARKER } }),
      await hashFor({ ...good, ceiling_minor: MARKER }),
      await hashFor({ ...good, mandate_expires_at: MARKER }),
    ];
    for (const hash of hashes) await invalid(t, hash);
  });

  test("a request that is not even a request is refused", async (t) => {
    const good = proposal(one());
    for (const hash of [
      "#proposal=",
      "#proposal=!!!notanid",
      "#proposal=prp_short",
      `#proposal=${"A".repeat(9000)}`,
      await hashFor({ ...good, ceiling_minor: 80.5 }),
      await hashFor({ ...good, ceiling_minor: 0 }),
      await hashFor({ ...good, ceiling_minor: 1000001 }),
      await hashFor({ ...good, items: [] }),
      await hashFor({
        ...good,
        items: [{ id: shop.items[0].id, quantity: 0 }],
      }),
      await hashFor({
        ...good,
        items: [{ id: shop.items[0].id, quantity: 100 }],
      }),
      await hashFor({ ...good, currency: "EUR" }),
      "#proposal=e30",
    ])
      await invalid(t, hash);
  });

  test("every string on the intent screen is a template or the store's own text", async (t) => {
    const prop = proposal(many());
    const { page } = await intentPage(t, prop);
    await state(page, "intent");
    const shown = expectedTerms(prop, shop);
    const allowed = new Set([
      "Countersign",
      "Trusted Surface",
      "This device",
      "Your device key proves that an approval came from you. It is made and kept in this browser.",
      "The private part of the key cannot be exported. Countersign never sees it.",
      "Working",
      "Ready",
      "Copy",
      "Copied",
      MESSAGES.intent.title,
      MESSAGES.intent.body,
      ...Object.values(LABELS),
      shown.merchant,
      ...shown.items,
      shown.ceiling,
      shown.expires,
      "Action needed",
      "Problem",
      "Registered",
    ]);
    const stray = await page.evaluate(
      (known) => {
        const walker = document.createTreeWalker(
          document.body,
          NodeFilter.SHOW_TEXT,
        );
        const out = [];
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
          const value = n.textContent.replace(/\s+/g, " ").trim();
          if (!value || n.parentElement.closest("script, noscript, style"))
            continue;
          if (n.parentElement.classList.contains("cs-fingerprint__group"))
            continue;
          if (!known.includes(value)) out.push(value);
        }
        return out;
      },
      [...allowed],
    );
    assert.deepEqual(stray, []);
    for (const request of page.requests) {
      assert.ok(
        request.url.startsWith(base),
        `request left the origin: ${request.url}`,
      );
      assert.match(
        new URL(request.url).pathname,
        /^\/(approve\/|ui\/|trusted-surface\/(store|consent|keys(\/challenge)?|proposals\/prp_[A-Za-z0-9_-]{16})$)/,
      );
    }
  });
});

describe("layout and access of the intent screen", () => {
  for (const scheme of ["light", "dark"]) {
    test(`375 px: no horizontal overflow, 44 px targets, visible focus (${scheme})`, async (t) => {
      const prop = proposal(many(), { ceiling: 1000000 });
      const { page } = await intentPage(t, prop, { scheme });
      await state(page, "intent");
      const overflow = () =>
        page.evaluate(
          () => document.documentElement.scrollWidth - window.innerWidth,
        );
      assert.ok((await overflow()) <= 0, "intent");
      for (const button of await page.getByRole("button").all()) {
        const box = await button.boundingBox();
        assert.ok(
          box.height >= 44 && box.width >= 44,
          `target ${box.width}x${box.height}`,
        );
      }
      await page.screenshot({
        path: join(shots, `intent-many-375-${scheme}.png`),
        fullPage: true,
      });
      await page.keyboard.press("Tab");
      const ring = await page.evaluate(() => {
        const style = getComputedStyle(document.activeElement);
        return {
          width: parseFloat(style.outlineWidth),
          style: style.outlineStyle,
        };
      });
      assert.ok(ring.width >= 2 && ring.style !== "none");
      await page.setViewportSize({ width: 320, height: 700 });
      assert.ok((await overflow()) <= 0, "intent at 320");
      await page.getByRole("button", { name: LABELS.approve }).click();
      await state(page, "intent_approved");
      report("consent_ok");
      await page.locator('[data-testid="mandates"] summary').click();
      assert.ok((await overflow()) <= 0, "approved with the mandates open");
      const summary = await page
        .locator('[data-testid="mandates"] summary')
        .boundingBox();
      assert.ok(summary.height >= 44);
    });
  }

  test("reduced motion and the keyboard reach Approve and Decline", async (t) => {
    const { page } = await intentPage(t, proposal(one()), {
      reducedMotion: "reduce",
    });
    await state(page, "intent");
    const names = [];
    for (let i = 0; i < 8; i++) {
      await page.keyboard.press("Tab");
      names.push(
        await page.evaluate(() => document.activeElement?.textContent?.trim()),
      );
    }
    assert.ok(names.includes(LABELS.approve) && names.includes(LABELS.decline));
  });
});

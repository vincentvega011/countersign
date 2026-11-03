// Browser tests of "My agent activity", against the running app.
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { LABELS, MANDATE_STATES, MESSAGES } from "../messages.js";
import {
  PAGE_CHROME,
  base,
  close,
  enrol,
  expectedExpiry,
  expectedMoney,
  focusRing,
  hashFor,
  launch,
  open,
  overflow,
  proposal,
  report,
  sameOrigin,
  setCatalogItem,
  state,
  store,
  strayText,
  targetsAreBigEnough,
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

// A customer with a device key and `count` approvals, then the activity page in the same context.
async function activityPage(
  t,
  { count = 2, ceilings = [], routes, ...options } = {},
) {
  const { context, page: setup } = await open(t, options);
  const customer = await enrol(setup);
  const made = [];
  for (let i = 0; i < count; i++) {
    const prop = proposal(one(), { ceiling: ceilings[i] ?? 8000 + i * 100 });
    const approve = await context.newPage();
    await approve.goto(`${base}/approve/${await hashFor(prop)}`);
    await state(approve, "intent");
    await approve.getByRole("button", { name: LABELS.approve }).click();
    await state(approve, "intent_approved");
    report("consent_ok");
    made.push(prop);
    await approve.close();
  }
  const page = await context.newPage();
  page.requests = [];
  page.on("request", (r) =>
    page.requests.push({
      url: r.url(),
      method: r.method(),
      body: r.postData(),
      headers: r.headers(),
    }),
  );
  if (routes) await routes(page);
  await page.goto(`${base}/approve/activity.html`);
  return { context, page, customer, made };
}

const cards = (page) => page.locator('[data-testid="mandate"]');
const posts = (page, suffix) =>
  page.requests.filter((r) => r.method === "POST" && r.url.endsWith(suffix));

const identity = (n) => String.fromCharCode(65 + n).repeat(43);
const sample = (extra = {}) => ({
  id: identity(0),
  state: "unused",
  ceiling_minor: 8000,
  currency: "USD",
  exp: Math.floor(Date.now() / 1000) + 86400,
  created_us: 1,
  agent_thumbprint: identity(5),
  purchase: null,
  ...extra,
});
const served = (mandates) => async (page) => {
  await page.route("**/trusted-surface/activity", async (route) => {
    if (route.request().method() !== "GET") return route.fallback();
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        customer_id: "cus_" + "A".repeat(22),
        now: 1,
        mandates,
      }),
    });
  });
};

describe("the activity screen", () => {
  test("lists each approval with its state, limit and expiry from fixed templates", async (t) => {
    const { page, made } = await activityPage(t, {
      count: 2,
      ceilings: [8000, 123456],
    });
    await state(page, "activity");
    assert.equal(await cards(page).count(), 2);
    const shown = await cards(page).evaluateAll((nodes) =>
      nodes.map((n) => ({
        state: n.dataset.mandateState,
        ceiling: n.querySelector('[data-testid="mandate-ceiling"]').textContent,
        expires: n.querySelector('[data-testid="mandate-expires"]').textContent,
      })),
    );
    const wanted = [...made]
      .map((p) => ({
        ceiling: expectedMoney(p.ceiling_minor),
        expires: expectedExpiry(p.mandate_expires_at),
      }))
      .sort((a, b) => a.ceiling.localeCompare(b.ceiling));
    assert.deepEqual(
      shown
        .map(({ ceiling, expires }) => ({ ceiling, expires }))
        .sort((a, b) => a.ceiling.localeCompare(b.ceiling)),
      wanted,
    );
    assert.ok(shown.every((s) => s.state === "unused"));
  });

  test("the session token lives in memory only and a signed proof opened it", async (t) => {
    const { page, customer } = await activityPage(t, { count: 1 });
    await state(page, "activity");
    const sessionPost = posts(page, "/trusted-surface/activity/session");
    assert.equal(sessionPost.length, 1);
    const sent = JSON.parse(sessionPost[0].body);
    assert.equal(sent.customer_id, customer);
    assert.equal(sent.signature.length, 86);
    const list = page.requests.find(
      (r) => r.method === "GET" && r.url.endsWith("/trusted-surface/activity"),
    );
    assert.match(list.headers.authorization, /^Bearer ats_[A-Za-z0-9_-]{43}$/);
    const token = list.headers.authorization.slice(7);
    const stored = await page.evaluate(async (needle) => {
      const dump =
        JSON.stringify({ ...localStorage }) +
        JSON.stringify({ ...sessionStorage }) +
        document.cookie +
        location.href;
      const dbs = (await indexedDB.databases?.()) ?? [];
      return { text: dump.includes(needle), dbs: dbs.map((d) => d.name) };
    }, token);
    assert.equal(stored.text, false, "the token was stored");
    assert.deepEqual(stored.dbs, ["countersign-trusted-surface"]);
  });

  test("taking an approval back needs a confirm and its own signature", async (t) => {
    const { page, customer } = await activityPage(t, { count: 2 });
    await state(page, "activity");
    const target = cards(page).first();
    await target.getByRole("button", { name: LABELS.revoke }).click();
    // Keeping it sends nothing.
    await target.getByRole("button", { name: LABELS.revokeKeep }).click();
    assert.equal(posts(page, "/trusted-surface/activity/revoke").length, 0);
    await target.getByRole("button", { name: LABELS.revoke }).click();
    await page.getByRole("button", { name: LABELS.revokeYes }).click();
    await page.waitForSelector('[data-testid="flash"]');
    assert.match(
      await page.textContent('[data-testid="flash"]'),
      new RegExp(MESSAGES.revoke_done.title),
    );
    const sent = posts(page, "/trusted-surface/activity/revoke");
    assert.equal(sent.length, 1);
    const body = JSON.parse(sent[0].body);
    assert.equal(body.customer_id, customer);
    assert.equal(body.signature.length, 86);
    assert.ok(!("token" in body));
    assert.ok(
      !(sent[0].headers.authorization ?? "").length,
      "the bearer token is not what authorizes a revoke",
    );
    const states = await cards(page).evaluateAll((n) =>
      n.map((x) => x.dataset.mandateState).sort(),
    );
    assert.deepEqual(states, ["revoked", "unused"]);
    // A reload shows the same.
    await page.reload();
    await state(page, "activity");
    const again = await cards(page).evaluateAll((n) =>
      n.map((x) => x.dataset.mandateState).sort(),
    );
    assert.deepEqual(again, ["revoked", "unused"]);
    assert.equal(
      await page
        .locator('[data-mandate-state="revoked"]')
        .getByRole("button", { name: LABELS.revoke })
        .count(),
      0,
      "a revoked approval has no button",
    );
    report("revoke_ok");
  });

  test("a manual refresh reloads the list and an expired session is renewed with a new proof", async (t) => {
    let expire = true;
    const { page } = await activityPage(t, {
      count: 1,
      routes: async (p) => {
        await p.route("**/trusted-surface/activity", async (route) => {
          if (route.request().method() === "GET" && expire) {
            expire = false;
            return route.fulfill({
              status: 401,
              contentType: "application/json",
              body: JSON.stringify({ code: "session_expired" }),
            });
          }
          return route.fallback();
        });
      },
    });
    await state(page, "activity");
    assert.equal(
      posts(page, "/trusted-surface/activity/session").length,
      2,
      "renewed with a second proof",
    );
    await page.getByRole("button", { name: LABELS.refreshActivity }).click();
    await state(page, "activity");
    assert.equal(
      page.requests.filter(
        (r) =>
          r.method === "GET" && r.url.endsWith("/trusted-surface/activity"),
      ).length,
      3,
    );
  });

  test("every state, the purchase made and the in-flight answer render from structured data", async (t) => {
    const ids = [0, 1, 2, 3, 4].map(identity);
    const list = [
      sample({ id: ids[0], state: "unused" }),
      sample({ id: ids[1], state: "in_flight" }),
      sample({
        id: ids[2],
        state: "used",
        purchase: {
          checkout_id: "chk_" + "Q".repeat(22),
          capture_id: "5O190127TN364715T",
          amount_minor: 7900,
          currency: "USD",
          at_us: 1_800_000_000_000_000,
        },
      }),
      sample({ id: ids[3], state: "revoked" }),
      sample({ id: ids[4], state: "expired" }),
    ];
    const { page } = await activityPage(t, {
      count: 0,
      routes: async (p) => {
        await served(list)(p);
        await p.route("**/trusted-surface/activity/revoke", (route) =>
          route.fulfill({
            status: 409,
            contentType: "application/json",
            body: JSON.stringify({ code: "in_flight" }),
          }),
        );
      },
    });
    await state(page, "activity");
    const states = await cards(page).evaluateAll((n) =>
      n.map((x) => x.dataset.mandateState),
    );
    assert.deepEqual(states, [
      "unused",
      "in_flight",
      "used",
      "revoked",
      "expired",
    ]);
    const purchase = page.locator('[data-testid="purchase"]');
    assert.equal(await purchase.count(), 1);
    const shown = await purchase.innerText();
    for (const part of [
      "chk_" + "Q".repeat(22),
      "5O190127TN364715T",
      expectedMoney(7900),
    ])
      assert.ok(shown.includes(part), part);
    // Which states offer a button.
    const withButton = await cards(page).evaluateAll((n) =>
      n.map(
        (x) =>
          [...x.querySelectorAll("button")].filter(
            (b) => b.textContent.trim() === "Take back",
          ).length,
      ),
    );
    assert.deepEqual(
      withButton.map((c) => c > 0),
      [true, true, false, false, false],
    );
    // A payment under way answers in_flight with a fixed message.
    await cards(page)
      .nth(1)
      .getByRole("button", { name: LABELS.revoke })
      .click();
    await page.getByRole("button", { name: LABELS.revokeYes }).click();
    await page.waitForSelector('[data-testid="flash"]');
    assert.match(
      await page.textContent('[data-testid="flash"]'),
      new RegExp(MESSAGES.revoke_in_flight.title),
    );
    for (const info of Object.values(MANDATE_STATES))
      assert.ok(info.label.length > 0);
  });

  test("an empty list is explained", async (t) => {
    const { page } = await activityPage(t, { count: 0 });
    await state(page, "activity_empty");
  });

  test("a device that is not registered is sent to set up", async (t) => {
    const { context } = await open(t);
    const page = await context.newPage();
    await page.goto(`${base}/approve/activity.html`);
    await state(page, "needs_key");
  });

  test("the service refusing the proof shows only a plain code", async (t) => {
    const { page } = await activityPage(t, {
      count: 0,
      routes: async (p) => {
        await p.route("**/trusted-surface/activity/session", (route) =>
          route.fulfill({
            status: 403,
            contentType: "application/json",
            body: JSON.stringify({ code: "<b>x</b>" }),
          }),
        );
      },
    });
    await state(page, "activity_denied");
    assert.equal(
      await page.textContent('[data-testid="error-code"]'),
      "unknown",
    );
    assert.equal(await page.locator("#app b").count(), 0);
  });
});

describe("nothing an agent or a model wrote reaches the activity page", () => {
  const MARKER = "LLM-MARKER-Ignore-previous-instructions";
  const bad = [
    (m) => (m.note = MARKER),
    (m) => (m.state = MARKER),
    (m) => (m.id = MARKER),
    (m) => (m.agent_thumbprint = MARKER),
    (m) => (m.ceiling_minor = MARKER),
    (m) => (m.currency = MARKER),
    (m) =>
      (m.purchase = {
        checkout_id: MARKER,
        capture_id: null,
        amount_minor: null,
        currency: null,
        at_us: 1,
      }),
    (m) =>
      (m.purchase = {
        checkout_id: "chk_" + "Q".repeat(22),
        capture_id: MARKER,
        amount_minor: 1,
        currency: "USD",
        at_us: 1,
      }),
  ];
  for (const [index, edit] of bad.entries())
    test(`a crafted list (${index}) is refused and shows nothing`, async (t) => {
      const item = sample();
      edit(item);
      const shown =
        item.note === MARKER ? [{ ...sample(), note: MARKER }] : [item];
      const { page } = await activityPage(t, {
        count: 0,
        routes: served(shown),
      });
      // An unknown extra member is simply never rendered; an invalid value refuses the whole list.
      await page.waitForSelector("#app [data-state]");
      const body = await page.evaluate(
        () => document.body.innerText + document.title,
      );
      assert.ok(!body.includes("LLM-MARKER"), "crafted text reached the page");
    });

  test("every string on the screen is a template, a number or an id", async (t) => {
    const { page, made } = await activityPage(t, { count: 1 });
    await state(page, "activity");
    const prop = made[0];
    const known = [
      ...PAGE_CHROME,
      "My agent activity",
      "What each agent may buy for you, what it bought, and a way to take an approval back.",
      "This list is read with your device key. Nothing here is written by a model.",
      MESSAGES.activity.title,
      MESSAGES.activity.body,
      ...Object.values(LABELS),
      ...Object.values(MANDATE_STATES).map((s) => `${s.glyph} ${s.label}`),
      expectedMoney(prop.ceiling_minor),
      expectedExpiry(prop.mandate_expires_at),
    ];
    assert.deepEqual(await strayText(page, known), []);
    assert.ok(sameOrigin(page));
    for (const request of page.requests)
      assert.match(
        new URL(request.url).pathname,
        /^\/(approve\/|ui\/|trusted-surface\/(keys\/challenge|activity(\/session)?))/,
      );
  });
});

describe("layout and access of the activity screen", () => {
  for (const scheme of ["light", "dark"])
    for (const width of [375, 1280])
      test(`${width} px ${scheme}: no overflow, 44 px targets, visible focus`, async (t) => {
        const { page } = await activityPage(t, { count: 3, width, scheme });
        await state(page, "activity");
        assert.ok((await overflow(page)) <= 0, "overflow");
        await targetsAreBigEnough(page);
        await focusRing(page);
        await page.screenshot({
          path: join(shots, `activity-${width}-${scheme}.png`),
          fullPage: true,
        });
        if (width === 375) {
          await page.setViewportSize({ width: 320, height: 700 });
          assert.ok((await overflow(page)) <= 0, "overflow at 320");
          await page.setViewportSize({ width: 375, height: 800 });
        }
        await cards(page)
          .first()
          .getByRole("button", { name: LABELS.revoke })
          .click();
        assert.ok(
          (await overflow(page)) <= 0,
          "overflow with the confirm open",
        );
        await targetsAreBigEnough(page);
        await page.screenshot({
          path: join(shots, `activity-confirm-${width}-${scheme}.png`),
          fullPage: true,
        });
      });

  test("reduced motion and the keyboard reach Take back and Refresh", async (t) => {
    const { page } = await activityPage(t, {
      count: 1,
      reducedMotion: "reduce",
    });
    await state(page, "activity");
    const names = [];
    for (let i = 0; i < 12; i++) {
      await page.keyboard.press("Tab");
      names.push(
        await page.evaluate(() => document.activeElement?.textContent?.trim()),
      );
    }
    assert.ok(
      names.includes(LABELS.revoke) && names.includes(LABELS.refreshActivity),
    );
  });
});

// Browser tests of the Trusted Surface setup page, against the running app (APPROVE_BASE_URL).
// Run by tests/integration/test_approve_browser.py, which starts the app on a real Postgres.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { LABELS, MESSAGES, NOTES } from "../messages.js";

const base = process.env.APPROVE_BASE_URL;
assert.ok(base, "APPROVE_BASE_URL must name the running app");
const here = dirname(fileURLToPath(import.meta.url));
const shots = join(here, "..", ".artifacts");
mkdirSync(shots, { recursive: true });

let browser;
before(async () => {
  browser = await chromium.launch();
});
after(async () => {
  await browser.close();
});

async function open(
  t,
  {
    width = 375,
    init,
    scheme = "light",
    reducedMotion = "no-preference",
    route,
  } = {},
) {
  const context = await browser.newContext({
    viewport: { width, height: 800 },
    colorScheme: scheme,
    reducedMotion,
    hasTouch: width <= 500,
  });
  t.after(() => context.close());
  if (init) await context.addInitScript(init);
  const page = await context.newPage();
  page.requests = [];
  page.on("request", (r) =>
    page.requests.push({ url: r.url(), method: r.method() }),
  );
  if (route) await route(page);
  return { context, page };
}

const state = (page, name) =>
  page.waitForSelector(`#app [data-state="${name}"]`, { timeout: 15000 });

async function enrol(page) {
  await page.goto(`${base}/approve/`);
  await page.getByRole("button", { name: LABELS.create }).click();
  await state(page, "registered");
}

const shownFingerprint = (page) =>
  page.$$eval(".cs-fingerprint__group", (nodes) =>
    nodes.map((n) => n.textContent).join(""),
  );
const shownCustomer = (page) => page.textContent('[data-testid="customer-id"]');
const text = (page) => page.innerText("#app");

const b64url = (buffer) =>
  buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const thumbprint = (jwk) =>
  b64url(
    createHash("sha256")
      .update(
        JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }),
      )
      .digest(),
  );

const storedKey = (page) =>
  page.evaluate(async () => {
    const { loadRecord } = await import("/approve/device-key.js");
    const record = await loadRecord();
    const out = { extractable: record.keyPair.privateKey.extractable };
    try {
      await crypto.subtle.exportKey("jwk", record.keyPair.privateKey);
      out.privateExport = "allowed";
    } catch (error) {
      out.privateExport = error.name;
    }
    try {
      await crypto.subtle.exportKey("pkcs8", record.keyPair.privateKey);
      out.pkcs8 = "allowed";
    } catch (error) {
      out.pkcs8 = error.name;
    }
    out.publicJwk = await crypto.subtle.exportKey(
      "jwk",
      record.keyPair.publicKey,
    );
    out.usages = record.keyPair.privateKey.usages;
    return out;
  });

describe("the device key", () => {
  test("is non-extractable and the exported public key has no private member", async (t) => {
    const { page } = await open(t);
    await enrol(page);
    const key = await storedKey(page);
    assert.equal(key.extractable, false);
    assert.equal(key.privateExport, "InvalidAccessError");
    assert.equal(key.pkcs8, "InvalidAccessError");
    assert.deepEqual(key.usages, ["sign"]);
    assert.equal(key.publicJwk.kty, "EC");
    assert.equal(key.publicJwk.crv, "P-256");
    assert.ok(!("d" in key.publicJwk));
  });

  test("survives a reload with the same fingerprint and without registering again", async (t) => {
    const { page } = await open(t);
    await enrol(page);
    const before = await shownFingerprint(page);
    const customer = await shownCustomer(page);
    const posts = () => page.requests.filter((r) => r.method === "POST").length;
    assert.equal(posts(), 2); // one challenge, one registration
    page.requests.length = 0;
    await page.reload();
    await state(page, "registered");
    assert.equal(await shownFingerprint(page), before);
    assert.equal(await shownCustomer(page), customer);
    assert.equal(posts(), 0);
    assert.equal(
      page.requests.filter((r) => r.url.includes("/trusted-surface/")).length,
      0,
    );
  });

  test("a fresh browser context gets a different key", async (t) => {
    const a = await open(t);
    const b = await open(t);
    await enrol(a.page);
    await enrol(b.page);
    assert.notEqual(
      await shownFingerprint(a.page),
      await shownFingerprint(b.page),
    );
    assert.notEqual(await shownCustomer(a.page), await shownCustomer(b.page));
  });
});

describe("the enrolment flow", () => {
  test("registers against the running app and shows the RFC 7638 thumbprint", async (t) => {
    const { page } = await open(t);
    const responses = [];
    page.on("response", async (r) => {
      if (
        r.url().includes("/trusted-surface/keys") &&
        !r.url().endsWith("/challenge")
      )
        responses.push({ status: r.status(), body: await r.json() });
    });
    await page.goto(`${base}/approve/`);
    await state(page, "ready");
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "registered");
    const key = await storedKey(page);
    const shown = await shownFingerprint(page);
    assert.equal(shown.length, 43);
    assert.equal(shown, thumbprint(key.publicJwk));
    const groups = await page.$$eval(".cs-fingerprint__group", (n) =>
      n.map((x) => x.textContent),
    );
    assert.ok(groups.every((g) => g.length <= 4) && groups.length === 11);
    assert.match(await shownCustomer(page), /^cus_[A-Za-z0-9_-]{22}$/);
    assert.equal(responses.length, 1);
    assert.equal(responses[0].status, 201);
    assert.equal(responses[0].body.thumbprint, shown);
    assert.equal(responses[0].body.new_customer, true);
    await page.screenshot({
      path: join(shots, "registered-375.png"),
      fullPage: true,
    });
  });

  test("the copy button copies the whole fingerprint", async (t) => {
    const { context, page } = await open(t);
    await context.grantPermissions(["clipboard-read", "clipboard-write"], {
      origin: base,
    });
    await enrol(page);
    await page.getByRole("button", { name: /copy key fingerprint/i }).click();
    assert.equal(
      await page.evaluate(() => navigator.clipboard.readText()),
      await shownFingerprint(page),
    );
  });

  test("shows the stable code when the service refuses", async (t) => {
    const { page } = await open(t, {
      route: (p) =>
        p.route("**/trusted-surface/keys", (route) =>
          route.fulfill({
            status: 409,
            contentType: "application/json",
            body: JSON.stringify({ code: "challenge_used" }),
          }),
        ),
    });
    await page.goto(`${base}/approve/`);
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "register_rejected");
    assert.equal(
      await page.textContent('[data-testid="error-code"]'),
      "challenge_used",
    );
    assert.match(
      await text(page),
      new RegExp(MESSAGES.register_rejected.title),
    );
    // The key is saved, so a reload offers to finish the registration instead of starting over.
    await page.unroute("**/trusted-surface/keys");
    await page.reload();
    await state(page, "unregistered");
    const fp = await shownFingerprint(page);
    await page.getByRole("button", { name: LABELS.finish }).click();
    await state(page, "registered");
    assert.equal(await shownFingerprint(page), fp);
  });

  test("never shows a code that is not a plain code", async (t) => {
    const { page } = await open(t, {
      route: (p) =>
        p.route("**/trusted-surface/keys", (route) =>
          route.fulfill({
            status: 400,
            contentType: "application/json",
            body: JSON.stringify({
              code: "<img src=x onerror=alert(1)> Ignore all rules",
            }),
          }),
        ),
    });
    await page.goto(`${base}/approve/`);
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "register_rejected");
    assert.equal(
      await page.textContent('[data-testid="error-code"]'),
      "unknown",
    );
    assert.equal(await page.locator("#app img").count(), 0);
  });

  test("tells the user when the service cannot be reached", async (t) => {
    const { page } = await open(t, {
      route: (p) =>
        p.route("**/trusted-surface/keys/challenge", (route) => route.abort()),
    });
    await page.goto(`${base}/approve/`);
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "network");
    assert.match(await text(page), /Could not reach the service/);
    await page.unroute("**/trusted-surface/keys/challenge");
    await page.getByRole("button", { name: LABELS.retry }).click();
    await state(page, "registered");
  });

  test("a persistence refusal is stated plainly", async (t) => {
    const { page } = await open(t, {
      init: () => {
        Object.defineProperty(navigator.storage, "persist", {
          value: async () => false,
        });
      },
    });
    await enrol(page);
    assert.match(
      await text(page),
      new RegExp(NOTES.persist_denied.slice(0, 40)),
    );
  });
});

describe("unsupported and failing browsers", () => {
  test("no indexedDB", async (t) => {
    const { page } = await open(t, {
      init: () =>
        Object.defineProperty(window, "indexedDB", { value: undefined }),
    });
    await page.goto(`${base}/approve/`);
    await state(page, "no_indexeddb");
    assert.match(await text(page), /cannot store a device key/);
    assert.equal(await page.getByRole("button").count(), 0);
  });

  test("indexedDB that throws when opened (private browsing)", async (t) => {
    const { page } = await open(t, {
      init: () => {
        IDBFactory.prototype.open = () => {
          throw new DOMException("denied", "SecurityError");
        };
      },
    });
    await page.goto(`${base}/approve/`);
    await state(page, "idb_unavailable");
    assert.match(await text(page), /storage is not available/);
  });

  test("no crypto.subtle", async (t) => {
    const { page } = await open(t, {
      init: () =>
        Object.defineProperty(Crypto.prototype, "subtle", {
          get: () => undefined,
        }),
    });
    await page.goto(`${base}/approve/`);
    await state(page, "no_subtle");
    assert.match(await text(page), /cannot create device keys/);
  });

  test("an insecure context", async (t) => {
    const { page } = await open(t, {
      init: () =>
        Object.defineProperty(window, "isSecureContext", { value: false }),
    });
    await page.goto(`${base}/approve/`);
    await state(page, "insecure_context");
    assert.match(await text(page), /not secure/);
  });

  test("a full disk: the quota message, and nothing is registered", async (t) => {
    const { page } = await open(t, {
      init: () => {
        IDBObjectStore.prototype.put = () => {
          throw new DOMException("full", "QuotaExceededError");
        };
      },
    });
    await page.goto(`${base}/approve/`);
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "storage_quota");
    assert.match(await text(page), /Not enough storage/);
    assert.equal(
      page.requests.filter((r) => r.url.includes("/trusted-surface/")).length,
      0,
    );
  });

  test("any other write failure: the write message, and nothing is registered", async (t) => {
    const { page } = await open(t, {
      init: () => {
        IDBObjectStore.prototype.put = () => {
          throw new DOMException("no", "UnknownError");
        };
      },
    });
    await page.goto(`${base}/approve/`);
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "storage_write_failed");
    assert.match(await text(page), /could not be saved/);
    assert.equal(
      page.requests.filter((r) => r.url.includes("/trusted-surface/")).length,
      0,
    );
  });

  test("a write that fails asynchronously is reported the same way", async (t) => {
    const { page } = await open(t, {
      init: () => {
        const put = IDBObjectStore.prototype.put;
        IDBObjectStore.prototype.put = function (...args) {
          const request = put.apply(this, args);
          this.transaction.abort();
          return request;
        };
      },
    });
    await page.goto(`${base}/approve/`);
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "storage_write_failed");
    assert.equal(
      page.requests.filter((r) => r.url.includes("/trusted-surface/")).length,
      0,
    );
  });
});

describe("a key that is gone or damaged", () => {
  test("lost: says so, shows the old fingerprint and offers a new key", async (t) => {
    const { page } = await open(t);
    await enrol(page);
    const old = await shownFingerprint(page);
    await page.evaluate(
      () =>
        new Promise((resolve) => {
          const r = indexedDB.deleteDatabase("countersign-trusted-surface");
          r.onsuccess = r.onerror = r.onblocked = () => resolve();
        }),
    );
    await page.reload();
    await state(page, "key_lost");
    assert.match(await text(page), /can no longer be used/);
    assert.equal(await shownFingerprint(page), old);
    await page.screenshot({
      path: join(shots, "key-lost-375.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: LABELS.recreate }).click();
    await state(page, "registered");
    assert.notEqual(await shownFingerprint(page), old);
  });

  test("unreadable: a damaged record is not trusted", async (t) => {
    const { page } = await open(t);
    await enrol(page);
    await page.evaluate(
      () =>
        new Promise((resolve, reject) => {
          const open = indexedDB.open("countersign-trusted-surface", 1);
          open.onsuccess = () => {
            const tx = open.result.transaction("device", "readwrite");
            tx.objectStore("device").put(
              { keyPair: "junk", customerId: null },
              "current",
            );
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
          };
        }),
    );
    await page.reload();
    await state(page, "key_unreadable");
    await page.getByRole("button", { name: LABELS.recreate }).click();
    await state(page, "registered");
  });

  test("an extractable private key in storage is refused", async (t) => {
    const { page } = await open(t);
    await page.goto(`${base}/approve/`);
    await state(page, "ready");
    await page.evaluate(async () => {
      const pair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
      );
      await new Promise((resolve, reject) => {
        const open = indexedDB.open("countersign-trusted-surface", 1);
        open.onupgradeneeded = () => open.result.createObjectStore("device");
        open.onsuccess = () => {
          const tx = open.result.transaction("device", "readwrite");
          tx.objectStore("device").put(
            { keyPair: pair, customerId: "cus_x" },
            "current",
          );
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        };
      });
    });
    await page.reload();
    await state(page, "key_unreadable");
  });
});

describe("what is on the page", () => {
  const allowed = new Set([
    "Countersign",
    "Trusted Surface",
    "This device",
    "Your device key proves that an approval came from you. It is made and kept in this browser.",
    "The private part of the key cannot be exported. Countersign never sees it.",
    "Registered",
    "Working",
    "Action needed",
    "Problem",
    "Copy",
    "Copied",
    ...Object.values(MESSAGES).flatMap((m) => [m.title, m.body]),
    ...Object.values(NOTES),
    ...Object.values(LABELS),
  ]);

  async function stray(page) {
    return page.evaluate(
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
          const dynamic =
            n.parentElement.classList.contains("cs-fingerprint__group") ||
            n.parentElement.dataset.testid === "customer-id" ||
            n.parentElement.dataset.testid === "error-code";
          if (!dynamic && !known.includes(value)) out.push(value);
        }
        return out;
      },
      [...allowed],
    );
  }

  test("every sentence is a fixed template and nothing leaves the origin", async (t) => {
    const { page } = await open(t);
    await page.goto(`${base}/approve/`);
    await state(page, "ready");
    assert.deepEqual(await stray(page), []);
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "registered");
    assert.deepEqual(await stray(page), []);
    await page.reload();
    await state(page, "registered");
    assert.deepEqual(await stray(page), []);
    for (const request of page.requests) {
      assert.ok(
        request.url.startsWith(base),
        `request left the origin: ${request.url}`,
      );
      assert.match(
        new URL(request.url).pathname,
        /^\/(approve\/|ui\/|trusted-surface\/keys(\/challenge)?$)/,
      );
    }
  });

  test("the page sends the security headers", async (t) => {
    const { page } = await open(t);
    const response = await page.goto(`${base}/approve/`);
    const csp = response.headers()["content-security-policy"];
    assert.match(csp, /default-src 'none'/);
    assert.equal(response.headers()["x-content-type-options"], "nosniff");
  });
});

describe("layout and access", () => {
  async function overflow(page) {
    return page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
  }

  for (const scheme of ["light", "dark"]) {
    test(`375 px has no horizontal overflow, in every state (${scheme})`, async (t) => {
      const { page } = await open(t, { scheme });
      await page.goto(`${base}/approve/`);
      await state(page, "ready");
      assert.ok((await overflow(page)) <= 0, "ready");
      await page.screenshot({
        path: join(shots, `ready-375-${scheme}.png`),
        fullPage: true,
      });
      await page.getByRole("button", { name: LABELS.create }).click();
      await state(page, "registered");
      assert.ok((await overflow(page)) <= 0, "registered");
      await page.screenshot({
        path: join(shots, `registered-375-${scheme}.png`),
        fullPage: true,
      });
      await page.setViewportSize({ width: 320, height: 700 });
      assert.ok((await overflow(page)) <= 0, "registered at 320");
    });
  }

  test("an error state fits at 375 px", async (t) => {
    const { page } = await open(t, {
      route: (p) =>
        p.route("**/trusted-surface/keys", (route) =>
          route.fulfill({
            status: 403,
            contentType: "application/json",
            body: JSON.stringify({ code: "authorizer_required" }),
          }),
        ),
    });
    await page.goto(`${base}/approve/`);
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "register_rejected");
    assert.ok((await overflow(page)) <= 0);
    await page.screenshot({
      path: join(shots, "rejected-375.png"),
      fullPage: true,
    });
  });

  test("every button is at least 44 px and keyboard focus is visible", async (t) => {
    const { page } = await open(t);
    await enrol(page);
    for (const button of await page.getByRole("button").all()) {
      const box = await button.boundingBox();
      assert.ok(
        box.height >= 44 && box.width >= 44,
        `target ${box.width}x${box.height}`,
      );
    }
    await page.keyboard.press("Tab");
    const ring = await page.evaluate(() => {
      const style = getComputedStyle(document.activeElement);
      return {
        tag: document.activeElement.tagName,
        width: parseFloat(style.outlineWidth),
        style: style.outlineStyle,
      };
    });
    assert.equal(ring.tag, "BUTTON");
    assert.ok(ring.width >= 2 && ring.style !== "none");
  });

  test("the ready state's button is also at least 44 px", async (t) => {
    const { page } = await open(t);
    await page.goto(`${base}/approve/`);
    await state(page, "ready");
    const box = await page
      .getByRole("button", { name: LABELS.create })
      .boundingBox();
    assert.ok(box.height >= 44);
  });

  test("reduced motion stops the spinner", async (t) => {
    const { page } = await open(t, {
      reducedMotion: "reduce",
      route: (p) =>
        p.route("**/trusted-surface/keys/challenge", async (route) => {
          await new Promise((r) => setTimeout(r, 1500));
          await route.continue();
        }),
    });
    await page.goto(`${base}/approve/`);
    await page.getByRole("button", { name: LABELS.create }).click();
    await state(page, "creating");
    const duration = await page.evaluate(() => {
      const busy = document.querySelector(".cs-btn.is-loading");
      return parseFloat(getComputedStyle(busy, "::before").animationDuration);
    });
    assert.ok(duration < 0.01, `animation still runs: ${duration}s`);
    assert.equal(
      await page
        .getByRole("button", { name: LABELS.working })
        .getAttribute("aria-busy"),
      "true",
    );
    await state(page, "registered");
  });
});

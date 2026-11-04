// The customer's phone, driven by a headless browser: enrol a device key, open the agent's approval link
// and tap Approve. Used by the shopping agent's end-to-end test and recorder (not a test itself).
//
//   node test/phone_consent.mjs <approve url>
//
// The key is created by the page (WebCrypto, non-extractable) in this browser context only.
import { chromium } from "playwright";

const url = process.argv[2];
if (
  !url ||
  !/^https?:\/\/[^#]+\/approve\/#proposal=prp_[A-Za-z0-9_-]{16}$/.test(url)
) {
  console.error(
    "usage: node test/phone_consent.mjs <approve url with #proposal=prp_...>",
  );
  process.exit(2);
}
const origin = new URL(url).origin;
const state = (page, name) =>
  page.waitForSelector(`#app [data-state="${name}"]`, { timeout: 20000 });

const browser = await chromium.launch();
try {
  const context = await browser.newContext({
    viewport: { width: 375, height: 800 },
    hasTouch: true,
    timezoneId: "UTC",
  });
  const setup = await context.newPage();
  await setup.goto(`${origin}/approve/`);
  await setup.getByRole("button", { name: "Create key" }).click();
  await state(setup, "registered");
  const intent = await context.newPage();
  await intent.goto(url);
  await state(intent, "intent");
  await intent.getByRole("button", { name: "Approve" }).click();
  await state(intent, "intent_approved");
  console.log("approved");
} catch (error) {
  console.error(`phone consent failed: ${error.message}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}

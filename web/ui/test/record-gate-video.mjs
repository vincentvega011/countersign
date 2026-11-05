// Records the end of the P3 gate run for the owner's reference (never committed): the agent's log as a
// page, then the verifier page loading the stored bundle by capture id and passing, then a tampered copy
// failing. Run by tests/integration/test_p3_gate.py when GATE_VIDEO_DIR is set.
//
//   node test/record-gate-video.mjs <spec.json>
// spec: {base, capture_id, events, merchant_key, platform_key, tampered, out}
import { readFileSync } from "node:fs";
import { chromium } from "playwright";

const spec = JSON.parse(readFileSync(process.argv[2], "utf8"));
const size = { width: 1280, height: 800 };
const browser = await chromium.launch();
const pause = (page, ms) => page.waitForTimeout(ms);

async function recorded(name, run) {
  const context = await browser.newContext({
    viewport: size,
    colorScheme: "light",
    recordVideo: { dir: `${spec.out}/${name}`, size },
  });
  const page = await context.newPage();
  await run(page);
  await context.close();
  console.log(await page.video().path());
}

await recorded("agent-log", async (page) => {
  await page.setContent(
    "<!doctype html><title>agent log</title><body style='margin:0;background:#111;color:#ddd;" +
      "font:14px/1.5 monospace'><pre id=log style='padding:24px;white-space:pre-wrap'></pre></body>",
  );
  for (const event of spec.events) {
    await page.evaluate((line) => {
      const log = document.getElementById("log");
      log.textContent += `${line}\n`;
      window.scrollTo(0, document.body.scrollHeight);
    }, JSON.stringify(event));
    await pause(page, 350);
  }
  await pause(page, 2000);
});

await recorded("verifier", async (page) => {
  await page.goto(`${spec.base}/verify/`);
  await pause(page, 1200);
  await page.fill("#capture-id", spec.capture_id);
  await page.click("#load");
  await page.waitForFunction(() =>
    document
      .querySelector('[data-testid="status"]')
      .textContent.startsWith("Loaded"),
  );
  await page.fill("#merchant-key", spec.merchant_key);
  await page.fill("#platform-key", spec.platform_key);
  await pause(page, 800);
  await page.click("#verify");
  await page.waitForSelector('[data-testid="summary"][data-state="passed"]');
  await pause(page, 1500);
  for (let y = 0; y < 2600; y += 260) {
    await page.mouse.wheel(0, 260);
    await pause(page, 250);
  }
  await pause(page, 1000);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.fill("#bundle-text", spec.tampered);
  await pause(page, 800);
  await page.click("#verify");
  await page.waitForSelector('[data-testid="summary"][data-state="failed"]');
  await pause(page, 1500);
  await page.locator(".vf-step--first").scrollIntoViewIfNeeded();
  await pause(page, 3000);
});

await browser.close();

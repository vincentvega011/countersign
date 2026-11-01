// Review screenshots of the component gallery, served by the real app (dev environment).
// Output goes to web/ui/.artifacts/ (gitignored). Also asserts, in a real browser: fonts loaded,
// no request leaves the origin, no horizontal overflow and 44 px targets at 375 px, and that the
// automatic dark theme follows prefers-color-scheme.
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const out = join(here, "..", ".artifacts");
mkdirSync(out, { recursive: true });
const port = 8700 + Math.floor(Math.random() * 200);
const base = `http://127.0.0.1:${port}`;

const server = spawn(
  "uv",
  ["run", "python", "scripts/serve_ui_gallery.py", String(port), "dev"],
  {
    cwd: root,
    stdio: ["ignore", "inherit", "inherit"],
  },
);
async function up() {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${base}/health`)).ok) return;
    } catch {
      /* not yet */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("the gallery server did not start");
}

const problems = [];
const check = (ok, message) => {
  if (!ok) problems.push(message);
};

try {
  await up();
  const browser = await chromium.launch();
  for (const theme of ["light", "dark"]) {
    for (const width of [375, 1280]) {
      const context = await browser.newContext({
        viewport: { width, height: 900 },
        colorScheme: theme,
        hasTouch: width === 375,
      });
      const page = await context.newPage();
      const foreign = [];
      page.on("request", (r) => {
        if (!r.url().startsWith(base) && !r.url().startsWith("data:"))
          foreign.push(r.url());
      });
      await page.goto(`${base}/_ui/gallery.html?theme=${theme}`);
      await page.evaluate(() => document.fonts.ready);
      const tag = `${theme}@${width}`;
      check(
        foreign.length === 0,
        `${tag}: requests left the origin: ${foreign.join(", ")}`,
      );
      const fonts = await page.evaluate(() =>
        ["Instrument Sans", "Newsreader", "JetBrains Mono"].map((f) =>
          document.fonts.check(`16px "${f}"`),
        ),
      );
      check(fonts.every(Boolean), `${tag}: a self-hosted font did not load`);
      const overflow = await page.evaluate(
        () =>
          document.documentElement.scrollWidth -
          document.documentElement.clientWidth,
      );
      check(overflow <= 0, `${tag}: horizontal overflow of ${overflow}px`);
      if (width === 375) {
        const small = await page.evaluate(() =>
          [
            ...document.querySelectorAll(
              "button, a[href], input, select, textarea",
            ),
          ]
            .map((n) => ({ n, r: n.getBoundingClientRect() }))
            .filter(({ r }) => r.width < 43.5 || r.height < 43.5)
            .map(
              ({ n, r }) =>
                `${n.tagName}.${n.className} ${Math.round(r.width)}x${Math.round(r.height)}`,
            ),
        );
        check(
          small.length === 0,
          `${tag}: targets under 44px: ${small.join("; ")}`,
        );
      }
      // keyboard: the first button takes focus and shows a ring
      await page.keyboard.press("Tab");
      const ring = await page.evaluate(
        () => getComputedStyle(document.activeElement).outlineStyle,
      );
      check(
        ring === "solid",
        `${tag}: no visible focus ring on the first tab stop (${ring})`,
      );
      await page.screenshot({
        path: join(out, `gallery-${theme}-${width}.png`),
        fullPage: true,
      });
      await context.close();
    }
  }
  // Automatic theme: no data-theme, dark scheme emulated -> the dark page colour.
  const auto = await browser.newContext({
    colorScheme: "dark",
    viewport: { width: 375, height: 800 },
  });
  const apage = await auto.newPage();
  await apage.goto(`${base}/_ui/gallery.html`);
  const bg = await apage.evaluate(
    () => getComputedStyle(document.body).backgroundColor,
  );
  check(
    bg === "rgb(15, 20, 27)",
    `automatic dark theme did not apply (body is ${bg})`,
  );
  await apage.screenshot({
    path: join(out, "gallery-both-375.png"),
    fullPage: true,
  });
  await auto.close();
  // Reduced motion: the loading spinner must not animate.
  const calm = await browser.newContext({ reducedMotion: "reduce" });
  const cpage = await calm.newPage();
  await cpage.goto(`${base}/_ui/gallery.html?theme=light`);
  const duration = await cpage.evaluate(() => {
    const b = document.querySelector(".cs-btn.is-loading");
    return parseFloat(getComputedStyle(b, "::before").animationDuration);
  });
  check(
    duration < 0.01,
    `reduced motion still animates the spinner (${duration}s)`,
  );
  await calm.close();
  await browser.close();
} finally {
  server.kill();
}

if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`screenshots written to ${out}`);

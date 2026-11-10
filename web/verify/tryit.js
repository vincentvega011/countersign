// The try-it buttons of the evidence verifier page. They only fill the same fields and press the same
// Verify button a visitor would use, so every result comes from the one verifier in ../ui/evidence/. The
// samples are the project's committed test vectors, fetched from this page's own origin. The tamper button
// edits a copy of the loaded sample (never text a visitor typed), in this page only.
import { STEP_TEXT, TRY_TEXT } from "./verify-text.js";

const $ = (id) => document.getElementById(id);
const SAMPLES = {
  synthetic: "/verify/samples/synthetic.json",
  recorded: "/verify/samples/recorded.json",
};
let pristine = null; // the text of the sample as it was fetched

// The note sits at the top of the result, right above the summary it explains.
const noteNode = document.createElement("p");
noteNode.className = "vf-trynote";
noteNode.setAttribute("data-testid", "try-note");
function note(text) {
  noteNode.textContent = text;
  if (text) $("result").prepend(noteNode);
  else noteNode.remove();
}

// Press Verify and wait for the result list to appear (or give up after ten seconds).
function verifyNow() {
  const result = $("result");
  result.replaceChildren();
  return new Promise((resolve) => {
    const finish = () => {
      observer.disconnect();
      clearTimeout(timer);
      resolve();
    };
    const observer = new MutationObserver(() => {
      if (result.querySelector('[data-testid="summary"]')) finish();
    });
    const timer = setTimeout(finish, 10000);
    observer.observe(result, { childList: true });
    $("verify").click();
  });
}

function setKeys(merchant, platform) {
  $("merchant-key").value = merchant ? JSON.stringify(merchant) : "";
  $("platform-key").value = platform ? JSON.stringify(platform) : "";
}

function firstFailure() {
  const name = $("result").querySelector("[data-first-failure]")?.dataset
    .firstFailure;
  return name ? STEP_TEXT[name].title : null;
}

async function load(which) {
  note("");
  let text;
  try {
    const response = await fetch(SAMPLES[which], {
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
    });
    if (!response.ok) throw new Error("load failed");
    text = await response.text();
  } catch {
    note(TRY_TEXT.loadFailed);
    return;
  }
  pristine = text;
  $("bundle-text").value = text;
  const keys = JSON.parse(text).keys;
  if (which === "synthetic") setKeys(keys.merchant, keys.platform);
  else setKeys(null, null);
  $("try-tamper").disabled = false;
  $("try-pin").hidden = which !== "recorded";
  await verifyNow();
  note(
    which === "synthetic" ? TRY_TEXT.syntheticLoaded : TRY_TEXT.recordedLoaded,
  );
}

async function pin() {
  if (pristine === null) return;
  const keys = JSON.parse(pristine).keys;
  setKeys(keys.merchant, keys.platform);
  await verifyNow();
  note(TRY_TEXT.pinned);
}

// Raise the first capture's amount by one cent-sized step in its last digit.
async function tamper() {
  if (pristine === null) {
    note(TRY_TEXT.nothingToChange);
    return;
  }
  const bundle = JSON.parse(pristine);
  const capture = bundle.paypal?.capture?.[0]?.amount;
  if (!capture || typeof capture.value !== "string") {
    note(TRY_TEXT.cannotChange);
    return;
  }
  const before = capture.value;
  const last = Number(before.slice(-1));
  capture.value = before.slice(0, -1) + String((last + 1) % 10);
  $("bundle-text").value = JSON.stringify(bundle);
  await verifyNow();
  const title = firstFailure();
  note(
    TRY_TEXT.changed("paypal.capture[0].amount.value", before, capture.value) +
      (title ? " " + TRY_TEXT.firstFailure(title) : ""),
  );
}

$("try-synthetic").addEventListener("click", () => load("synthetic"));
$("try-recorded").addEventListener("click", () => load("recorded"));
$("try-tamper").addEventListener("click", tamper);
$("try-pin").addEventListener("click", pin);
const wanted = new URLSearchParams(location.search).get("try");
if (wanted === "synthetic" || wanted === "recorded") load(wanted);

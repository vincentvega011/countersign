import assert from "node:assert/strict";
import test from "node:test";
import { formatAmount, groupFingerprint, statusInfo, STATUS } from "../ui.js";

test("minor units format as dollars", () => {
  const cases = [
    [0, "$0.00"],
    [1, "$0.01"],
    [9, "$0.09"],
    [99, "$0.99"],
    [100, "$1.00"],
    [8500, "$85.00"],
    [100000, "$1,000.00"],
    [123456789, "$1,234,567.89"],
    [-1, "-$0.01"],
    [-250, "-$2.50"],
    [Number.MAX_SAFE_INTEGER, "$90,071,992,547,409.91"],
    [
      123456789012345678901234567890n,
      "$1,234,567,890,123,456,789,012,345,678.90",
    ],
  ];
  for (const [minor, expected] of cases)
    assert.equal(formatAmount(minor), expected, String(minor));
});

test("a float or anything that is not an integer is rejected", () => {
  for (const bad of [
    1.5,
    0.1 + 0.2,
    99.99,
    NaN,
    Infinity,
    -Infinity,
    "100",
    null,
    undefined,
    {},
    [],
    2 ** 53,
    true,
  ]) {
    assert.throws(() => formatAmount(bad), TypeError, String(bad));
  }
  assert.throws(() => formatAmount(1.0 + 1e-9), TypeError);
});

test("an unsupported currency is rejected, not guessed", () => {
  assert.throws(() => formatAmount(100, "EUR"), RangeError);
  assert.throws(() => formatAmount(100, "usd"), RangeError);
});

test("fingerprints group in fours and keep every character", () => {
  assert.deepEqual(groupFingerprint("abcdefghij"), ["abcd", "efgh", "ij"]);
  assert.equal(
    groupFingerprint("q7Hk2vN0cX9bR4tLw1ZmP8sJdY3fUaE6gO5iVnC1xKM").join(""),
    "q7Hk2vN0cX9bR4tLw1ZmP8sJdY3fUaE6gO5iVnC1xKM",
  );
  assert.throws(() => groupFingerprint(""), TypeError);
  assert.throws(() => groupFingerprint("abc", 0), RangeError);
});

test("every checkout and attempt state maps to a tone, a label and a glyph; unknown states throw", () => {
  const states = [
    "ready_for_complete",
    "complete_in_progress",
    "completed",
    "canceled",
    "rejected",
    "voided",
  ];
  assert.deepEqual(Object.keys(STATUS), states);
  for (const s of states) {
    const info = statusInfo(s);
    assert.ok(
      info.label &&
        info.glyph &&
        ["info", "warning", "success", "neutral", "danger"].includes(info.tone),
      s,
    );
  }
  assert.equal(statusInfo("completed").tone, "success");
  assert.equal(statusInfo("rejected").tone, "danger");
  for (const bad of ["", "toString", "__proto__", "Completed", undefined])
    assert.throws(() => statusInfo(bad), RangeError);
});

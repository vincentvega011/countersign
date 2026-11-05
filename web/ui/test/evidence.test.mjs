// Unit tests of the browser evidence verifier (web/ui/evidence), run with `node --test`.
// The expectations come from tests/vectors/evidence/index.json and json_rules.json, the same files the
// Python verifier is held to.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { b64url, unb64 } from "../evidence/crypto.js";
import { Float, MAX_DEPTH, dict, jcs, loads, same } from "../evidence/json.js";
import { STEP_NAMES, verify, verifyText } from "../evidence/verify.js";

const VECTORS = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "tests",
  "vectors",
  "evidence",
);
const bytes = (name) => new Uint8Array(readFileSync(join(VECTORS, name)));
const index = JSON.parse(readFileSync(join(VECTORS, "index.json"), "utf8"));
const rules = JSON.parse(
  readFileSync(join(VECTORS, "json_rules.json"), "utf8"),
);
const pinned = () =>
  dict([
    ["merchant", loads(bytes("merchant.key.json"))],
    ["platform", loads(bytes("platform.key.json"))],
  ]);
const firstFailure = (results) => results.find((r) => !r.ok) ?? null;

test("the valid bundle passes all twelve steps in order", async () => {
  const results = await verifyText(bytes("valid.json"), pinned());
  assert.deepEqual(
    results.map((r) => r.name),
    STEP_NAMES,
  );
  assert.equal(STEP_NAMES.length, 12);
  assert.ok(
    results.every((r) => r.ok && r.code === null),
    JSON.stringify(results.filter((r) => !r.ok)),
  );
});

test("without pinned keys only trusted_keys fails, and says so", async () => {
  const failed = (await verifyText(bytes("valid.json"))).filter((r) => !r.ok);
  assert.deepEqual(
    failed.map((r) => [r.name, r.code]),
    [["trusted_keys", "keys_not_pinned"]],
  );
});

test("pinning only one key is not pinning", async () => {
  const one = dict([["merchant", pinned().merchant]]);
  const failed = (await verifyText(bytes("valid.json"), one)).filter(
    (r) => !r.ok,
  );
  assert.deepEqual(
    failed.map((r) => r.code),
    ["keys_partly_pinned"],
  );
});

test("a pinned key that is not the bundle's fails trusted_keys", async () => {
  const keys = pinned();
  keys.merchant = keys.platform;
  const first = firstFailure(await verifyText(bytes("valid.json"), keys));
  assert.notEqual(first, null);
});

const ownKeys = (raw) =>
  dict([
    ["merchant", raw.keys.merchant],
    ["platform", raw.keys.platform],
  ]);

for (const entry of [...index.tampered, ...index.strict, ...index.forged]) {
  test(`${entry.file} fails first at ${entry.first_failure}`, async () => {
    // Forged bundles carry their own throwaway keys, which are the ones pinned.
    const keys = entry.file.startsWith("forged/")
      ? ownKeys(loads(bytes(entry.file)))
      : pinned();
    const results = await verifyText(bytes(entry.file), keys);
    const first = firstFailure(results);
    assert.equal(first?.name ?? null, entry.first_failure);
    assert.equal(first?.code ?? null, entry.code);
    if (first) assert.ok(first.message.length > 10 && first.code);
  });
}

test("every JSON rule case gives the shared answer", () => {
  assert.equal(rules.max_depth, MAX_DEPTH);
  for (const c of rules.cases) {
    const input =
      c.text !== undefined
        ? new TextEncoder().encode(c.text)
        : new Uint8Array(Buffer.from(c.bytes_b64, "base64"));
    let got;
    try {
      const v = loads(input);
      const kind =
        v instanceof Float
          ? "float"
          : typeof v === "number"
            ? "int"
            : v === null
              ? "NoneType"
              : typeof v === "boolean"
                ? "bool"
                : typeof v === "string"
                  ? "str"
                  : Array.isArray(v)
                    ? "list"
                    : "dict";
      got = { ok: true, kind };
    } catch (error) {
      got = { ok: false, code: error.code };
    }
    const want = c.ok
      ? { ok: true, kind: c.kind }
      : { ok: false, code: c.code };
    assert.deepEqual(got, want, JSON.stringify(c));
  }
});

test("type-exact comparison: true is not 1, 1.0 is not 1", () => {
  assert.equal(same(true, 1), false);
  assert.equal(same(new Float(1), 1), false);
  assert.equal(same(new Float(1), new Float(1)), true);
  assert.equal(same(dict([["a", 1]]), dict([["a", 1]])), true);
  assert.equal(same(dict([["a", 1]]), dict([["a", true]])), false);
  assert.equal(same([1, "x"], [1, "x"]), true);
});

test("canonical JSON and base64url", () => {
  const value = loads('{"b":[1,1.5,true,null],"a":"\\u00e9\\n","__proto__":2}');
  assert.equal(jcs(value), '{"__proto__":2,"a":"é\\n","b":[1,1.5,true,null]}');
  for (const n of [0, 1, 2, 3, 31, 32, 33, 64])
    assert.deepEqual(
      unb64(b64url(new Uint8Array(n).fill(n))),
      new Uint8Array(n).fill(n),
    );
  for (const bad of ["QQ==", "QR", "Q", "a+b/", "abc!", 7, null])
    assert.throws(() => unb64(bad), { code: "base64url_invalid" });
});

test("garbage is a bundle_structure failure, never a crash", async () => {
  for (const text of [
    "",
    "[]",
    "{}",
    '{"v": 1}',
    "not json",
    '{"a": 1, "a": 2}',
    "NaN",
  ]) {
    const results = await verifyText(text);
    assert.equal(results.length, 1);
    assert.equal(results[0].name, "bundle_structure");
    assert.equal(results[0].ok, false);
  }
  const results = await verify(loads(bytes("valid.json")).paypal, pinned());
  assert.equal(results[0].code, "bundle_members");
});

test("verification makes no network request", async () => {
  const saved = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = () => {
    calls += 1;
    throw new Error("no network");
  };
  try {
    const results = await verifyText(bytes("valid.json"), pinned());
    assert.ok(results.every((r) => r.ok));
  } finally {
    globalThis.fetch = saved;
  }
  assert.equal(calls, 0);
});

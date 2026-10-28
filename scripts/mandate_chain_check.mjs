// Independent cross-check of the mandate chain verifier (src/countersign/mandates).
//
// Reads the shared vectors in tests/vectors/mandates/chain_vectors.json, verifies every one with
// code written from the specs (RFC 9901, the Delegate SD-JWT draft, docs/PROTOCOL.md 1.2.3) using
// only `jose` and node:crypto, and requires the outcome AND the failing step of each vector to
// equal the expectation. The Python tests (tests/unit/test_mandate_vectors.py) hold the Python
// verifier to the same expectations, so Python and Node agree on every vector or this exits 1.
//
// Not covered here: the "excess decimal precision" rule of Decision 12 (needs shortest-round-trip
// float formatting; covered by the Python strict loader tests). Unsafe integers and non-finite
// numbers are covered.
//
// Usage: node scripts/mandate_chain_check.mjs [vector file]
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { compactVerify, importJWK } from "jose";

const MAX_CHARS = 16 * 1024;
const SKEW = 60;
const ISSUER_TYP = ["dc+sd-jwt"];
const KB_FINAL_TYP = ["kb+sd-jwt"];
const KB_MID_TYP = ["kb-sd-jwt+kb"];
const KNOWN_VCTS = new Set([
  "mandate.checkout.1",
  "mandate.checkout.open.1",
  "mandate.payment.1",
  "mandate.payment.open.1",
]);
const FORBIDDEN_HEADERS = ["crit", "b64", "zip", "jwk", "jku", "x5u", "x5c"];

class Fail extends Error {
  constructor(code, detail) {
    super(`${code}${detail ? `/${detail}` : ""}`);
    this.code = code;
    this.detail = detail;
  }
}
const fail = (code, detail) => {
  throw new Fail(code, detail);
};

const sha256b64 = (text) => createHash("sha256").update(text, "ascii").digest("base64url");

// ----- strict JSON: objects are Maps, floats are Float, duplicate keys and NaN are errors -----
class Float {
  constructor(value) {
    this.value = value;
  }
}

function parseStrictJson(bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    fail("json_invalid", "json_encoding");
  }
  if (text.startsWith("﻿")) fail("json_invalid", "json_encoding");
  let i = 0;
  const syntax = () => fail("json_invalid", "json_syntax");
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const literal = (word, value) => {
    if (!text.startsWith(word, i)) syntax();
    i += word.length;
    return value;
  };
  function value(depth) {
    if (depth > 200) fail("json_invalid", "json_too_deep");
    ws();
    const c = text[i];
    if (c === "{") return object(depth);
    if (c === "[") return array(depth);
    if (c === '"') return string();
    if (c === "t") return literal("true", true);
    if (c === "f") return literal("false", false);
    if (c === "n") return literal("null", null);
    if (text.startsWith("NaN", i) || text.startsWith("Infinity", i) || text.startsWith("-Infinity", i)) {
      fail("json_invalid", "json_non_finite");
    }
    return number();
  }
  function number() {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!m) syntax();
    i += m[0].length;
    if (m[2] === undefined && m[3] === undefined) {
      if (m[0].replace("-", "").length > 16 || Math.abs(Number(m[0])) > Number.MAX_SAFE_INTEGER) {
        fail("json_invalid", "json_unsafe_integer");
      }
      return Number(m[0]);
    }
    const f = Number(m[0]);
    if (!Number.isFinite(f)) fail("json_invalid", "json_non_finite");
    if (Math.abs(f) > Number.MAX_SAFE_INTEGER) fail("json_invalid", "json_unsafe_integer");
    return new Float(f);
  }
  function string() {
    const start = i;
    i++;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === "\\") i++;
      if (text.charCodeAt(i) < 0x20) syntax();
      i++;
    }
    if (i >= text.length) syntax();
    i++;
    try {
      return JSON.parse(text.slice(start, i));
    } catch {
      return syntax();
    }
  }
  function array(depth) {
    i++;
    const out = [];
    ws();
    if (text[i] === "]") {
      i++;
      return out;
    }
    for (;;) {
      out.push(value(depth + 1));
      ws();
      if (text[i] === ",") i++;
      else if (text[i] === "]") {
        i++;
        return out;
      } else syntax();
    }
  }
  function object(depth) {
    i++;
    const out = new Map();
    ws();
    if (text[i] === "}") {
      i++;
      return out;
    }
    for (;;) {
      ws();
      if (text[i] !== '"') syntax();
      const key = string();
      ws();
      if (text[i] !== ":") syntax();
      i++;
      const v = value(depth + 1);
      if (out.has(key)) fail("json_invalid", "json_duplicate_key");
      out.set(key, v);
      ws();
      if (text[i] === ",") i++;
      else if (text[i] === "}") {
        i++;
        return out;
      } else syntax();
    }
  }
  const result = value(0);
  ws();
  if (i !== text.length) syntax();
  return result;
}

// ----- structure -----
function decodeB64(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) fail("structure_base64url");
  const bytes = Buffer.from(text, "base64url");
  if (bytes.toString("base64url") !== text) fail("structure_base64url");
  return bytes;
}

function splitChain(token) {
  if (typeof token !== "string") fail("structure_not_text");
  if (token.length > MAX_CHARS) fail("structure_too_large");
  if (!/^[A-Za-z0-9_.~-]*$/.test(token)) fail("structure_charset");
  const parts = token.split("~");
  const last = parts.pop();
  if (last) {
    if (last.includes(".")) fail("structure_trailing_kb");
    fail("structure_trailing_tilde");
  }
  const links = [];
  let i = 0;
  for (;;) {
    const jwt = i < parts.length ? parts[i] : "";
    if (!jwt) fail("structure_separator");
    if (jwt.split(".").length !== 3) fail("structure_segments");
    i++;
    const disclosures = [];
    while (i < parts.length && parts[i]) {
      if (parts[i].includes(".")) fail("structure_separator");
      disclosures.push(parts[i]);
      i++;
    }
    if (new Set(disclosures).size !== disclosures.length) fail("structure_duplicate_disclosure");
    links.push({ jwt, disclosures, serialization: [jwt, ...disclosures].join("~") + "~" });
    if (i === parts.length) return links;
    i++;
  }
}

// ----- JWT -----
function asObject(value, what) {
  if (!(value instanceof Map)) fail("payload_shape", what);
  return value;
}

function parseJwt(compact, allowedTyp) {
  const [h, p] = compact.split(".");
  const header = asObject(parseStrictJson(decodeB64(h)), "header");
  const alg = header.get("alg");
  if (typeof alg !== "string" || alg !== "ES256") fail("alg_not_allowed");
  for (const name of FORBIDDEN_HEADERS) if (header.has(name)) fail("header_invalid");
  const typ = header.get("typ");
  if (typeof typ !== "string" || !allowedTyp.includes(typ)) fail("typ_mismatch");
  const payload = asObject(parseStrictJson(decodeB64(p)), "payload");
  return { compact, payload };
}

async function verifySignature(compact, key) {
  const signature = compact.split(".")[2];
  if (decodeB64(signature).length !== 64) fail("signature_invalid");
  try {
    await compactVerify(compact, key, { algorithms: ["ES256"] });
  } catch {
    fail("signature_invalid");
  }
}

// ----- selective disclosure (RFC 9901 section 7.1) -----
function decodeDisclosure(text) {
  const value = parseStrictJson(decodeB64(text));
  if (!Array.isArray(value) || ![2, 3].includes(value.length)) fail("disclosure_malformed");
  if (typeof value[0] !== "string") fail("disclosure_malformed");
  if (value.length === 2) return { name: null, value: value[1] };
  const name = value[1];
  if (typeof name !== "string" || name === "_sd" || name === "...") fail("disclosure_malformed");
  return { name, value: value[2] };
}

function resolveClaims(payload, disclosures) {
  if ((payload.has("_sd_alg") ? payload.get("_sd_alg") : "sha-256") !== "sha-256") {
    fail("sd_alg_unsupported");
  }
  const table = new Map();
  for (const text of disclosures) {
    const digest = sha256b64(text);
    if (table.has(digest)) fail("structure_duplicate_disclosure");
    table.set(digest, decodeDisclosure(text));
  }
  const seen = new Set();
  const used = new Set();
  const see = (digest) => {
    if (typeof digest !== "string") fail("disclosure_malformed");
    if (seen.has(digest)) fail("disclosure_duplicate_digest");
    seen.add(digest);
    return digest;
  };
  function resolve(node, depth) {
    if (depth > 32) fail("disclosure_malformed");
    if (node instanceof Map) {
      const out = new Map();
      for (const [k, v] of node) if (k !== "_sd") out.set(k, resolve(v, depth + 1));
      const sd = node.has("_sd") ? node.get("_sd") : [];
      if (!Array.isArray(sd)) fail("disclosure_malformed");
      for (const item of sd) {
        const digest = see(item);
        const entry = table.get(digest);
        if (!entry) continue;
        if (entry.name === null) fail("disclosure_malformed");
        if (out.has(entry.name)) fail("disclosure_claim_collision");
        used.add(digest);
        out.set(entry.name, resolve(entry.value, depth + 1));
      }
      return out;
    }
    if (Array.isArray(node)) {
      const out = [];
      for (const element of node) {
        if (element instanceof Map && element.has("...")) {
          if (element.size !== 1) fail("disclosure_malformed");
          const digest = see(element.get("..."));
          const entry = table.get(digest);
          if (!entry) continue;
          if (entry.name !== null) fail("disclosure_malformed");
          used.add(digest);
          out.push(resolve(entry.value, depth + 1));
        } else out.push(resolve(element, depth + 1));
      }
      return out;
    }
    return node;
  }
  const result = resolve(payload, 0);
  if (used.size !== table.size) fail("disclosure_unreferenced");
  result.delete("_sd_alg");
  return result;
}

// ----- cnf -----
async function cnfKey(content) {
  if (!content.has("cnf")) fail("cnf_missing");
  const cnf = content.get("cnf");
  if (!(cnf instanceof Map)) fail("cnf_malformed");
  if (!cnf.has("jwk")) fail("cnf_unsupported_key");
  if (cnf.size !== 1) fail("cnf_unsupported_key");
  const jwk = cnf.get("jwk");
  if (!(jwk instanceof Map)) fail("cnf_malformed");
  if (jwk.has("d")) fail("cnf_malformed");
  if (jwk.get("kty") !== "EC" || jwk.get("crv") !== "P-256") fail("cnf_unsupported_key");
  if (jwk.has("alg") && jwk.get("alg") !== "ES256") fail("cnf_unsupported_key");
  if (jwk.has("use") && jwk.get("use") !== "sig") fail("cnf_unsupported_key");
  if (jwk.has("key_ops")) {
    const ops = jwk.get("key_ops");
    if (!Array.isArray(ops) || !ops.includes("verify")) fail("cnf_unsupported_key");
  }
  const coordinates = {};
  for (const name of ["x", "y"]) {
    const value = jwk.get(name);
    if (typeof value !== "string") fail("cnf_malformed");
    let bytes;
    try {
      bytes = decodeB64(value);
    } catch {
      fail("cnf_malformed");
    }
    if (bytes.length !== 32) fail("cnf_malformed");
    coordinates[name] = value;
  }
  try {
    return await importJWK({ kty: "EC", crv: "P-256", ...coordinates }, "ES256");
  } catch {
    return fail("cnf_malformed");
  }
}

// ----- time -----
function checkTimes(claims, now, requireExp) {
  const read = (name) => {
    if (!claims.has(name)) return null;
    const v = claims.get(name);
    if (typeof v !== "number") fail("time_claim_type");
    return v;
  };
  const exp = read("exp");
  const nbf = read("nbf");
  const iat = read("iat");
  if (exp === null && requireExp) fail("exp_missing");
  if (exp !== null && now - exp > SKEW) fail("expired");
  if (nbf !== null && nbf - now > SKEW) fail("not_yet_valid");
  if (iat !== null && iat - now > SKEW) fail("issued_in_future");
}

// ----- chain -----
async function verifyChain(vector) {
  const { token, expected_vcts: expected, audience, nonce, now } = vector;
  if (!expected.length || expected.some((v) => !KNOWN_VCTS.has(v))) fail("vct_unknown_expected");
  const links = splitChain(token);
  if (links.length !== expected.length) fail("structure_chain_length");
  let key = await importJWK(vector.issuer_jwk, "ES256");
  for (const [n, raw] of links.entries()) {
    const final = n === links.length - 1;
    const typ = n === 0 ? ISSUER_TYP : final ? KB_FINAL_TYP : KB_MID_TYP;
    const jwt = parseJwt(raw.jwt, typ);
    await verifySignature(raw.jwt, key);
    const claims = resolveClaims(jwt.payload, raw.disclosures);
    const signed = jwt.payload.get("delegate_payload");
    if (
      !Array.isArray(signed) ||
      signed.length === 0 ||
      !signed.every((e) => e instanceof Map && e.size === 1 && e.has("..."))
    ) {
      fail("delegate_payload_invalid");
    }
    const resolved = claims.get("delegate_payload");
    if (!Array.isArray(resolved) || resolved.length !== 1 || !(resolved[0] instanceof Map)) {
      fail("delegate_payload_invalid");
    }
    const content = resolved[0];
    if (!content.has("vct")) fail("vct_missing");
    if (content.get("vct") !== expected[n]) fail("vct_mismatch");
    if (n > 0) {
      for (const name of ["aud", "nonce"]) {
        if (typeof claims.get(name) !== "string" || claims.get(name) === "") {
          fail("kb_claim_missing");
        }
      }
      if (!claims.has("iat")) fail("kb_claim_missing");
      if (final && claims.get("aud") !== audience) fail("kb_audience_mismatch");
      if (final && nonce !== null && claims.get("nonce") !== nonce) fail("kb_nonce_mismatch");
      if (!claims.has("sd_hash")) fail("sd_hash_missing");
      if (claims.get("sd_hash") !== sha256b64(links[n - 1].serialization)) fail("sd_hash_mismatch");
    }
    if (!final || content.has("cnf")) key = await cnfKey(content);
    checkTimes(content, now, !(final && n > 0));
    checkTimes(claims, now, false);
  }
}

// ----- run the vectors -----
const file = process.argv[2] ?? new URL("../tests/vectors/mandates/chain_vectors.json", import.meta.url);
const { vectors } = JSON.parse(readFileSync(file, "utf8"));
let bad = 0;
for (const vector of vectors) {
  let outcome = { ok: true };
  try {
    await verifyChain(vector);
  } catch (error) {
    if (!(error instanceof Fail)) {
      console.log(`FAIL ${vector.id}: unexpected ${error?.stack ?? error}`);
      bad++;
      continue;
    }
    outcome = { ok: false, code: error.code, ...(error.detail ? { detail: error.detail } : {}) };
  }
  const want = vector.expect;
  const agree =
    outcome.ok === want.ok &&
    outcome.code === want.code &&
    (want.detail === undefined || outcome.detail === want.detail);
  if (!agree) {
    bad++;
    console.log(`DISAGREE ${vector.id}: node=${JSON.stringify(outcome)} expected=${JSON.stringify(want)}`);
  }
}
if (bad) {
  console.log(`mandate_chain_check: ${bad} of ${vectors.length} vectors disagree`);
  process.exit(1);
}
console.log(`mandate_chain_check: node agrees on all ${vectors.length} vectors`);

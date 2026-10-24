// Independent verifier for ap2.merchant_authorization, using only `jose` and `canonicalize`.
// It shares no code with the Python signer and checks the signature the way a platform would:
// public JWK from the merchant profile, exact two member header, ES256 only, JCS payload rebuilt
// from the checkout response.
//
// Usage: node scripts/interop_verify.mjs <profile URL or file> <checkout response file, or - for stdin>
// Prints "OK ..." and exits 0, or prints "FAIL: <reason>" and exits 1.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import canonicalize from "canonicalize";
import { compactVerify, importJWK } from "jose";

const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const b64url = (buffer) => Buffer.from(buffer).toString("base64url");

class Fail extends Error {}
const fail = (message) => {
  throw new Fail(message);
};

async function readProfile(source) {
  if (/^https?:\/\//.test(source)) {
    const response = await fetch(source);
    if (!response.ok) fail(`profile request returned HTTP ${response.status}`);
    return response.json();
  }
  return JSON.parse(readFileSync(source, "utf8"));
}

function readCheckout(source) {
  return JSON.parse(readFileSync(source === "-" ? 0 : source, "utf8"));
}

function decodeSegment(segment, what) {
  const bytes = Buffer.from(segment, "base64url");
  if (bytes.toString("base64url") !== segment) fail(`${what} is not canonical base64url`);
  return bytes;
}

async function verify(profile, checkout) {
  if (!Array.isArray(profile.keys)) fail("the profile has no top-level keys[]");
  const authorization = checkout?.ap2?.merchant_authorization;
  if (typeof authorization !== "string") fail("the response has no ap2.merchant_authorization");
  const parts = authorization.split(".");
  if (parts.length !== 3 || parts[1] !== "") fail("merchant_authorization is not a detached JWS");
  const [headerSegment, , signatureSegment] = parts;

  const header = JSON.parse(decodeSegment(headerSegment, "the header").toString("utf8"));
  const members = Object.keys(header).sort().join(",");
  if (members !== "alg,kid") fail(`the header must have exactly alg and kid, found: ${members}`);
  if (header.alg !== "ES256") fail(`the header algorithm ${header.alg} is not allowed`);
  if (decodeSegment(signatureSegment, "the signature").length !== 64) {
    fail("the signature must be 64 bytes");
  }

  const matches = profile.keys.filter((key) => key.kid === header.kid);
  if (matches.length !== 1) fail("kid does not name exactly one key in the published keys");
  const jwk = matches[0];
  if (PRIVATE_MEMBERS.some((member) => member in jwk)) fail("a published key holds private material");
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") fail("the published key is not EC P-256");
  const key = await importJWK(jwk, "ES256");

  const { ap2: _excluded, ...covered } = checkout;
  const payload = Buffer.from(canonicalize(covered), "utf8");
  const compact = `${headerSegment}.${b64url(payload)}.${signatureSegment}`;
  try {
    await compactVerify(compact, key, { algorithms: ["ES256"] });
  } catch (error) {
    fail(`the signature does not verify (${error.code ?? error.message})`);
  }
  const hash = b64url(createHash("sha256").update(compact, "ascii").digest());
  return { kid: header.kid, id: checkout.id, status: checkout.status, hash };
}

const [source, checkoutSource] = process.argv.slice(2);
if (!source || !checkoutSource) {
  console.error("usage: node scripts/interop_verify.mjs <profile URL or file> <checkout file or ->");
  process.exit(2);
}
try {
  const result = await verify(await readProfile(source), readCheckout(checkoutSource));
  console.log(
    `OK merchant_authorization verifies: checkout=${result.id} status=${result.status} ` +
      `kid=${result.kid} checkout_hash=${result.hash}`,
  );
} catch (error) {
  if (error instanceof Fail) {
    console.log(`FAIL: ${error.message}`);
    process.exit(1);
  }
  console.log(`FAIL: ${error.message}`);
  process.exit(1);
}

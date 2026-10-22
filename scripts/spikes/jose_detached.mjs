// Spike: independent verification of a detached JWS (merchant_authorization) with jose and an
// independent JCS implementation (canonicalize). Vectors come from jws_detached.py.
//
// Run: node scripts/spikes/jose_detached.mjs <vectors.json>
import { readFileSync } from "node:fs";
import canonicalize from "canonicalize";
import { compactVerify, importJWK } from "jose";

const vectors = JSON.parse(readFileSync(process.argv[2], "utf8"));
const key = await importJWK(vectors.jwk, "ES256");

async function verifyDetached(detached, checkout) {
  const { ap2, ...covered } = checkout;
  const [header, empty, signature] = detached.split(".");
  if (empty !== "") throw new Error("not a detached JWS");
  const payload = Buffer.from(canonicalize(covered), "utf8").toString(
    "base64url",
  );
  return compactVerify(`${header}.${payload}.${signature}`, key, {
    algorithms: ["ES256"],
  });
}

const ok = await verifyDetached(
  vectors.merchant_authorization,
  vectors.checkout,
);
if (
  ok.protectedHeader.kid !== "merchant-key-1" ||
  ok.protectedHeader.alg !== "ES256"
) {
  throw new Error("unexpected header");
}
console.log(
  "OK jose verifies the detached merchant_authorization signed by Python",
);

let rejected = false;
try {
  await verifyDetached(vectors.merchant_authorization, vectors.tampered);
} catch {
  rejected = true;
}
if (!rejected) throw new Error("tampered checkout was accepted");
console.log("OK jose rejects the tampered checkout");

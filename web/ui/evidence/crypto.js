// Base64url, SHA-256 and ES256 for the evidence verifier, on WebCrypto only (no library, no network).
// Port of the rest of countersign_verify/crypto.py: same checks, same order, same codes.
import { Invalid, get, isDict, isStr, jcs, loads } from "./json.js";

const subtle = globalThis.crypto.subtle;
const ascii = (t) => /^[\x00-\x7f]*$/.test(t);
const encoder = new TextEncoder();

export const utf8 = (text) => encoder.encode(text);

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function equalBytes(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function b64url(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n =
      (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    const chars = [18, 12, 6, 0].map((s) => ALPHABET[(n >> s) & 63]);
    out += chars.slice(0, Math.min(4, bytes.length - i + 1)).join("");
  }
  return out;
}

export function unb64(text) {
  if (
    !isStr(text) ||
    !ascii(text) ||
    !/^[A-Za-z0-9_-]*$/.test(text) ||
    text.length % 4 === 1
  )
    throw new Invalid("base64url_invalid", "a value is not base64url");
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let at = 0;
  for (const ch of text) {
    value = (value << 6) | ALPHABET.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (value >> bits) & 255;
    }
  }
  if (b64url(out) !== text)
    throw new Invalid(
      "base64url_invalid",
      "a value is not canonical unpadded base64url",
    );
  return out;
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

// `sd_hash`-style digest: unpadded base64url SHA-256 over the US-ASCII text.
export async function digest(text) {
  if (!isStr(text) || !ascii(text))
    throw new Invalid("digest_not_ascii", "a hashed value is not US-ASCII");
  return b64url(await sha256(utf8(text)));
}

export async function domainHash(domain, data) {
  return sha256(concat(utf8(domain), new Uint8Array([0]), data));
}

export async function thumbprint(jwk) {
  if (!isDict(jwk))
    throw new Invalid("key_not_object", "a key is not an object");
  const members = Object.create(null);
  for (const m of ["crv", "kty", "x", "y"]) members[m] = get(jwk, m);
  if (!Object.values(members).every(isStr))
    throw new Invalid("key_not_ec", "a key is not an EC public JWK");
  return b64url(await sha256(utf8(jcs(members))));
}

async function publicKey(jwk) {
  if (!isDict(jwk) || get(jwk, "kty") !== "EC" || get(jwk, "crv") !== "P-256")
    throw new Invalid("key_not_p256", "a key is not an EC P-256 public JWK");
  if (Object.prototype.hasOwnProperty.call(jwk, "d"))
    throw new Invalid("key_private", "a published key holds private material");
  const x = unb64(get(jwk, "x"));
  const y = unb64(get(jwk, "y"));
  if (x.length !== 32 || y.length !== 32)
    throw new Invalid("key_coordinates", "a key has bad coordinates");
  try {
    return await subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new Invalid("key_not_on_curve", "a key is not on the curve");
  }
}

// ES256 over `signed` (bytes); `signature` is the raw 64 byte `r || s` in base64url.
export async function verifyEs256(jwk, signed, signature) {
  const raw = unb64(signature);
  if (raw.length !== 64) return false;
  const key = await publicKey(jwk);
  return subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, signed);
}

// A compact ES256 JWS: `[header, payload]`. `typ` is checked when given.
export async function verifyJws(token, jwk, typ = null) {
  if (!isStr(token) || !ascii(token) || token.split(".").length !== 3)
    throw new Invalid("jws_shape", "a JWS is not three segments");
  const [head, body, sig] = token.split(".");
  const header = loads(unb64(head));
  if (!isDict(header) || get(header, "alg") !== "ES256")
    throw new Invalid("jws_alg", "a JWS is not ES256");
  if (typ !== null && get(header, "typ") !== typ)
    throw new Invalid("jws_typ", "a JWS has the wrong typ");
  if (!(await verifyEs256(jwk, utf8(`${head}.${body}`), sig)))
    throw new Invalid("signature_invalid", "a signature does not verify");
  return [header, loads(unb64(body))];
}

export function u64(value) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

export function u32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

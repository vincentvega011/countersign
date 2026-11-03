// The device key: WebCrypto generation, IndexedDB storage, the RFC 7638 thumbprint and the
// registration protocol. No UI here, no logging, and the private key is never exported, read as
// bytes, logged or sent: only signatures leave this module.

export const DB_NAME = "countersign-trusted-surface";
export const STORE = "device";
export const RECORD_ID = "current";
export const MARKER = "cs.ts.enrolled";
export const PURPOSE_REGISTER = "countersign.device-key.register.v1";
export const CHALLENGE_PURPOSE = "register_device_key";
export const RECORD_VERSION = 1;
const ECDSA = Object.freeze({ name: "ECDSA", namedCurve: "P-256" });

// A failure with a stable `kind` that messages.js has a fixed template for.
export class DeviceKeyError extends Error {
  constructor(kind, code = null) {
    super(kind);
    this.kind = kind;
    this.code = code;
  }
}

// ------------------------------------------------------------------------------------ encoding

export function b64url(bytes) {
  let text = "";
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
  return btoa(text)
    .split("+")
    .join("-")
    .split("/")
    .join("_")
    .split("=")
    .join("");
}

// RFC 8785 for the shapes used here: an object of strings, integers and null. Keys sort by UTF-16
// code unit, which is what Array.prototype.sort does, and JSON.stringify spells strings as JCS does.
export function jcs(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value))
    return String(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
  }
  throw new TypeError("not canonicalizable");
}

export async function thumbprintOf(jwk) {
  const members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(jcs(members)),
  );
  return b64url(digest);
}

export function registrationRecord({
  challengeId,
  nonce,
  thumbprint,
  customerId,
  origin,
}) {
  return new TextEncoder().encode(
    jcs({
      v: RECORD_VERSION,
      purpose: PURPOSE_REGISTER,
      challenge_id: challengeId,
      challenge: nonce,
      thumbprint,
      customer_id: customerId,
      origin,
    }),
  );
}

// ---------------------------------------------------------------------------------------- support

export function checkSupport() {
  if (globalThis.isSecureContext !== true)
    throw new DeviceKeyError("insecure_context");
  if (!globalThis.crypto?.subtle) throw new DeviceKeyError("no_subtle");
  if (
    typeof globalThis.indexedDB === "undefined" ||
    globalThis.indexedDB === null
  )
    throw new DeviceKeyError("no_indexeddb");
}

// ---------------------------------------------------------------------------------------- storage

function openDb() {
  return new Promise((resolve, reject) => {
    let request;
    try {
      request = indexedDB.open(DB_NAME, 1);
    } catch {
      reject(new DeviceKeyError("idb_unavailable"));
      return;
    }
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE))
        request.result.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new DeviceKeyError("idb_unavailable"));
    request.onblocked = () => reject(new DeviceKeyError("idb_unavailable"));
  });
}

function writeError(error) {
  const name = error?.name ?? "";
  return new DeviceKeyError(
    name === "QuotaExceededError" ? "storage_quota" : "storage_write_failed",
  );
}

async function withStore(mode, run, onError) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      let result;
      let tx;
      try {
        tx = db.transaction(STORE, mode);
        result = run(tx.objectStore(STORE));
      } catch (error) {
        reject(onError(error));
        return;
      }
      tx.oncomplete = () => resolve(result?.result);
      tx.onerror = () => reject(onError(tx.error ?? result?.error));
      tx.onabort = () => reject(onError(tx.error ?? result?.error));
    });
  } finally {
    db.close();
  }
}

// The stored record: { keyPair: CryptoKeyPair, customerId: string | null, createdAt: number }.
export async function saveRecord(record) {
  await withStore("readwrite", (s) => s.put(record, RECORD_ID), writeError);
}

export async function loadRecord() {
  const record = await withStore(
    "readonly",
    (s) => s.get(RECORD_ID),
    () => new DeviceKeyError("idb_unavailable"),
  );
  if (record === undefined) return undefined;
  const pair = record?.keyPair;
  const usable =
    pair?.privateKey instanceof CryptoKey &&
    pair?.publicKey instanceof CryptoKey &&
    pair.privateKey.type === "private" &&
    pair.privateKey.extractable === false &&
    pair.publicKey.type === "public" &&
    pair.privateKey.algorithm?.name === "ECDSA" &&
    pair.privateKey.algorithm?.namedCurve === "P-256" &&
    (record.customerId === null || typeof record.customerId === "string");
  if (!usable) throw new DeviceKeyError("key_unreadable");
  return record;
}

export async function clearLocal() {
  try {
    localStorage.removeItem(MARKER);
  } catch {
    /* storage is optional here */
  }
  await new Promise((resolve) => {
    let request;
    try {
      request = indexedDB.deleteDatabase(DB_NAME);
    } catch {
      resolve();
      return;
    }
    request.onsuccess = request.onerror = request.onblocked = () => resolve();
  });
}

// A small marker beside the key lets a later visit tell "never enrolled" from "enrolled, key gone".
export function readMarker() {
  try {
    const raw = localStorage.getItem(MARKER);
    if (raw === null) return null;
    const parsed = JSON.parse(raw);
    return typeof parsed?.thumbprint === "string" ? parsed : null;
  } catch {
    return null;
  }
}

export function writeMarker(thumbprint, customerId) {
  try {
    localStorage.setItem(MARKER, JSON.stringify({ thumbprint, customerId }));
  } catch {
    /* the marker is a hint only */
  }
}

export async function requestPersistence() {
  try {
    if (typeof navigator.storage?.persist !== "function") return "unavailable";
    return (await navigator.storage.persist()) ? "granted" : "denied";
  } catch {
    return "denied";
  }
}

// ------------------------------------------------------------------------------------------ keys

export async function generate() {
  const keyPair = await crypto.subtle.generateKey(ECDSA, false, [
    "sign",
    "verify",
  ]);
  return keyPair;
}

// The public key of a pair is always exportable; only the four public members are kept.
export async function publicJwk(keyPair) {
  const full = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return { kty: full.kty, crv: full.crv, x: full.x, y: full.y };
}

export async function signBytes(privateKey, bytes) {
  const raw = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    bytes,
  );
  return b64url(raw); // WebCrypto gives the raw r || s form (64 bytes)
}

// -------------------------------------------------------------------------------- registration

export async function getJson(path, headers = {}) {
  let response;
  try {
    response = await fetch(path, {
      method: "GET",
      headers,
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new DeviceKeyError("network");
  }
  let json = null;
  try {
    json = await response.json();
  } catch {
    json = null;
  }
  if (!response.ok) {
    // A refusal carries a stable code; anything else (a proxy error, a dropped body) is the network.
    if (typeof json?.code === "string")
      throw new DeviceKeyError("register_rejected", json.code);
    throw new DeviceKeyError("network");
  }
  if (json === null) throw new DeviceKeyError("network");
  return json;
}

export async function postJson(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new DeviceKeyError("network");
  }
  let json = null;
  try {
    json = await response.json();
  } catch {
    json = null;
  }
  if (!response.ok)
    throw new DeviceKeyError(
      "register_rejected",
      typeof json?.code === "string" ? json.code : "unknown",
    );
  return json;
}

// Ask for a challenge, sign the record that names it, and register the public key.
export async function register(keyPair, customerId = null) {
  const jwk = await publicJwk(keyPair);
  const thumbprint = await thumbprintOf(jwk);
  const challenge = await postJson("/trusted-surface/keys/challenge", {
    purpose: CHALLENGE_PURPOSE,
  });
  const origin = location.origin;
  const record = registrationRecord({
    challengeId: challenge.challenge_id,
    nonce: challenge.nonce,
    thumbprint,
    customerId,
    origin,
  });
  const signature = await signBytes(keyPair.privateKey, record);
  const result = await postJson("/trusted-surface/keys", {
    jwk,
    challenge_id: challenge.challenge_id,
    customer_id: customerId,
    origin,
    signature,
  });
  return {
    customerId: result.customer_id,
    thumbprint,
    serverThumbprint: result.thumbprint,
  };
}

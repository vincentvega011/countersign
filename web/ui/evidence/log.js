// Decision log entries and inclusion proofs, recomputed. Port of countersign_verify/log.py.
import {
  concat,
  domainHash,
  equalBytes,
  u32,
  u64,
  unb64,
  utf8,
} from "./crypto.js";
import {
  Invalid,
  get,
  isDict,
  isInt,
  isList,
  isStr,
  item,
  same,
  sameKeys,
} from "./json.js";

function hash32(text) {
  const raw = unb64(text);
  if (raw.length !== 32)
    throw new Invalid("log_hash_shape", "a log hash is not 32 bytes");
  return raw;
}

// The members `entryHash` reads have exact types: a non-negative integer `seq` and `ts_us`.
export function checkFields(entry) {
  if (!isDict(entry))
    throw new Invalid("log_entry_shape", "a log entry is not an object");
  for (const name of ["seq", "ts_us"]) {
    const value = get(entry, name);
    if (!isInt(value) || value < 0)
      throw new Invalid(
        "log_entry_number",
        `a log entry ${name} is not a non-negative integer`,
      );
  }
  const checkout = get(entry, "checkout_id");
  if (checkout !== null && !isStr(checkout))
    throw new Invalid("log_entry_shape", "a log entry checkout_id is not text");
  for (const name of [
    "kind",
    "payload",
    "entry_hash",
    "prev_hash",
    "policy_hash",
  ])
    if (!isStr(get(entry, name)))
      throw new Invalid("log_entry_shape", `a log entry ${name} is not text`);
}

export async function entryHash(entry) {
  checkFields(entry);
  const payloadHash = await domainHash(
    "cs.log.payload.v1",
    utf8(item(entry, "payload")),
  );
  const checkout = item(entry, "checkout_id");
  const scope =
    checkout === null
      ? new Uint8Array([0])
      : concat(new Uint8Array([1]), u32(utf8(checkout).length), utf8(checkout));
  const kind = utf8(entry.kind);
  return domainHash(
    "cs.log.v1",
    concat(
      hash32(entry.prev_hash),
      u64(entry.seq),
      u64(entry.ts_us),
      scope,
      u32(kind.length),
      kind,
      payloadHash,
      hash32(entry.policy_hash),
    ),
  );
}

const leaf = (e) => domainHash("cs.merkle.leaf.v1", e);
const node = (l, r) => domainHash("cs.merkle.node.v1", concat(l, r));

function splitAt(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

async function tree(hashes) {
  if (hashes.length === 1) return leaf(hashes[0]);
  const k = splitAt(hashes.length);
  return node(await tree(hashes.slice(0, k)), await tree(hashes.slice(k)));
}

export async function rootOf(hashes) {
  const top = hashes.length
    ? await tree(hashes)
    : await domainHash("cs.merkle.empty.v1", new Uint8Array());
  return domainHash("cs.merkle.root.v1", concat(u64(hashes.length), top));
}

async function fromPath(index, size, leafHash, path) {
  if (size === 1) {
    if (path.length)
      throw new Invalid("proof_path_length", "an inclusion path is too long");
    return leafHash;
  }
  if (!path.length)
    throw new Invalid("proof_path_length", "an inclusion path is too short");
  const k = splitAt(size);
  const sibling = path[path.length - 1];
  const rest = path.slice(0, -1);
  if (index < k) return node(await fromPath(index, k, leafHash, rest), sibling);
  return node(sibling, await fromPath(index - k, size - k, leafHash, rest));
}

export async function checkInclusion(entry, proof, root) {
  if (
    !isDict(proof) ||
    !sameKeys(proof, ["v", "index", "size", "path"]) ||
    !same(proof.v, 1)
  )
    throw new Invalid("proof_shape", "a proof has the wrong shape");
  const { index, size, path } = proof;
  if (!isInt(index) || !isInt(size) || !(index >= 0 && index < size))
    throw new Invalid("proof_position", "a proof has a bad index or size");
  if (!isList(path))
    throw new Invalid("proof_shape", "a proof path is not a list");
  const top = await fromPath(index, size, await leaf(entry), path.map(hash32));
  const reached = await domainHash("cs.merkle.root.v1", concat(u64(size), top));
  if (!equalBytes(reached, root))
    throw new Invalid(
      "proof_root",
      "an inclusion proof does not reach the root",
    );
}

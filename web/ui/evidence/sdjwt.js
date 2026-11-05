// The two-link mandate chains of a bundle (AP2 SD-JWT). Port of countersign_verify/sdjwt.py.
import { digest, unb64, verifyJws } from "./crypto.js";
import {
  Invalid,
  get,
  hashable,
  isDict,
  isInt,
  isList,
  isStr,
  item,
  len,
  loads,
  sameKeys,
} from "./json.js";

async function disclosures(parts) {
  const found = new Map();
  for (const text of parts) {
    if (!text) continue;
    if (text.includes("."))
      throw new Invalid("disclosure_is_jwt", "a disclosure looks like a JWT");
    const decoded = loads(unb64(text));
    if (!isList(decoded) || (decoded.length !== 2 && decoded.length !== 3))
      throw new Invalid(
        "disclosure_shape",
        "a disclosure is not a salted array",
      );
    const key = await digest(text);
    if (found.has(key))
      throw new Invalid("disclosure_repeated", "a disclosure appears twice");
    found.set(key, decoded);
  }
  return found;
}

// `disclosed.get(key)` of a Python dict keyed by digests (text).
function lookup(disclosed, key) {
  hashable(key);
  return isStr(key) && disclosed.has(key) ? disclosed.get(key) : null;
}

function singleContent(payload, disclosed) {
  const delegate = get(payload, "delegate_payload");
  if (
    get(payload, "_sd_alg") !== "sha-256" ||
    !isList(delegate) ||
    delegate.length !== 1 ||
    !isDict(delegate[0]) ||
    !sameKeys(delegate[0], ["..."])
  )
    throw new Invalid(
      "mandate_content_shape",
      "a mandate does not have exactly one hidden content element",
    );
  const entry = lookup(disclosed, item(delegate[0], "..."));
  if (entry === null || entry.length !== 2 || !isDict(entry[1]))
    throw new Invalid(
      "mandate_content_missing",
      "the content disclosure is missing",
    );
  return entry[1];
}

const sameSet = (map, keys) =>
  map.size === new Set(keys).size && keys.every((k) => map.has(k));

// `[open serialization, closed link]` of `<open>~~<kb jwt>~<disclosures>~`.
export function split(chain) {
  if (!isStr(chain) || !chain.endsWith("~"))
    throw new Invalid("chain_shape", "a mandate does not end with '~'");
  const at = chain.indexOf("~~");
  if (at < 0)
    throw new Invalid("chain_shape", "a mandate is not a two link chain");
  const head = chain.slice(0, at);
  const link = chain.slice(at + 2);
  if (!link || link.includes("~~"))
    throw new Invalid("chain_shape", "a mandate is not a two link chain");
  return [`${head}~`, link];
}

export async function readOpen(serialization, platformJwk, vct) {
  const parts = serialization.split("~");
  const [header, payload] = await verifyJws(parts[0], platformJwk, "dc+sd-jwt");
  if (!isDict(payload) || !isDict(header))
    throw new Invalid(
      "open_payload_shape",
      "an open mandate payload is not an object",
    );
  const disclosed = await disclosures(parts.slice(1));
  const content = singleContent(payload, disclosed);
  if (!sameSet(disclosed, [payload.delegate_payload[0]["..."]]))
    throw new Invalid(
      "open_extra_disclosure",
      "an open mandate carries a disclosure nothing refers to",
    );
  if (get(content, "vct") !== vct)
    throw new Invalid("open_vct", "an open mandate has the wrong vct");
  const cnf = get(content, "cnf");
  if (!isDict(cnf) || !isDict(get(cnf, "jwk")))
    throw new Invalid(
      "open_no_agent_key",
      "an open mandate binds no agent key",
    );
  if (!isStr(get(payload, "sub")) || !payload.sub)
    throw new Invalid("open_no_customer", "an open mandate names no customer");
  return { payload, content };
}

export async function readClosed(
  link,
  openSerialization,
  openMandate,
  vct,
  audience,
  hashMember,
) {
  const parts = link.split("~");
  const [, payload] = await verifyJws(
    parts[0],
    item(item(openMandate.content, "cnf"), "jwk"),
    "kb+sd-jwt",
  );
  if (!isDict(payload))
    throw new Invalid(
      "closed_payload_shape",
      "a key binding payload is not an object",
    );
  if (get(payload, "sd_hash") !== (await digest(openSerialization)))
    throw new Invalid(
      "closed_sd_hash",
      "the key binding is not bound to this open mandate",
    );
  if (get(payload, "aud") !== audience)
    throw new Invalid(
      "closed_audience",
      "the key binding has the wrong audience",
    );
  if (!isStr(get(payload, "nonce")) || !payload.nonce)
    throw new Invalid("closed_no_nonce", "the key binding has no nonce");
  const iat = get(payload, "iat");
  const exp = get(openMandate.content, "exp");
  if (!isInt(iat) || !isInt(exp) || iat > exp)
    throw new Invalid(
      "closed_after_expiry",
      "the closed mandate was signed after the open one expired",
    );
  const disclosed = await disclosures(parts.slice(1));
  const content = singleContent(payload, disclosed);
  const hidden = get(content, "_sd");
  if (!isList(hidden) || hidden.length !== 1)
    throw new Invalid(
      "closed_no_checkout_jwt",
      "the closed mandate hides no checkout_jwt",
    );
  const cj = lookup(disclosed, hidden[0]);
  if (cj === null || len(cj) !== 3 || cj[1] !== "checkout_jwt" || !isStr(cj[2]))
    throw new Invalid(
      "closed_no_checkout_jwt",
      "the checkout_jwt disclosure is missing",
    );
  if (!sameSet(disclosed, [payload.delegate_payload[0]["..."], hidden[0]]))
    throw new Invalid(
      "closed_extra_disclosure",
      "a closed mandate carries a disclosure nothing refers to",
    );
  if (get(content, "vct") !== vct)
    throw new Invalid("closed_vct", "a closed mandate has the wrong vct");
  if (get(content, hashMember) !== (await digest(cj[2])))
    throw new Invalid(
      "closed_hash_member",
      `${hashMember} is not the hash of the disclosed checkout_jwt`,
    );
  return { link, payload, content, checkoutJwt: cj[2] };
}

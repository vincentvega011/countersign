// Strict JSON, canonical JSON (RFC 8785) and the value rules of the evidence verifier.
//
// A line by line port of countersign_verify/crypto.py (Decisions 12 and 106): the same checks in the same
// order with the same stable codes. Integers are JS numbers; a number written with a fraction or an
// exponent is a `Float`, so `1.0` is never the integer `1` and `true` is never `1`. Objects have a null
// prototype, so a member called "__proto__" is an ordinary member. No dependency, no network.

export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
export const MAX_DEPTH = 64;

export class Invalid extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export class Float {
  constructor(value) {
    this.value = value;
    Object.freeze(this);
  }
}

export const isDict = (x) =>
  x !== null &&
  typeof x === "object" &&
  !Array.isArray(x) &&
  !(x instanceof Float) &&
  !(x instanceof Uint8Array);
export const isInt = (x) => typeof x === "number";
export const isStr = (x) => typeof x === "string";
export const isList = (x) => Array.isArray(x);

export function dict(entries = []) {
  const out = Object.create(null);
  for (const [k, v] of entries) out[k] = v;
  return out;
}

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// ---- the parts of Python's semantics the verifier relies on ------------------------------------------

// `o.get(k, d)`: o must be an object (otherwise Python raises AttributeError).
export function get(o, k, d = null) {
  if (!isDict(o)) throw new TypeError("get on a value that is not an object");
  return own(o, k) ? o[k] : d;
}

// `o[k]`: a member of an object or an integer index of a list; anything else raises.
export function item(o, k) {
  if (isDict(o) && typeof k === "string") {
    if (!own(o, k)) throw new TypeError(`missing member ${k}`);
    return o[k];
  }
  if (isList(o) && Number.isInteger(k)) {
    const i = k < 0 ? o.length + k : k;
    if (i < 0 || i >= o.length) throw new TypeError("index out of range");
    return o[i];
  }
  throw new TypeError("not subscriptable");
}

// Iterating a value: a list's items, an object's keys, a text's code points.
export function iter(x) {
  if (isList(x)) return x;
  if (isDict(x)) return Object.keys(x);
  if (isStr(x)) return [...x];
  throw new TypeError("not iterable");
}

export function len(x) {
  if (isList(x)) return x.length;
  if (isDict(x)) return Object.keys(x).length;
  if (isStr(x)) return [...x].length;
  throw new TypeError("no length");
}

export function truthy(x) {
  if (x === null || x === undefined || x === false) return false;
  if (typeof x === "number") return x !== 0;
  if (x instanceof Float) return x.value !== 0;
  if (isStr(x) || isList(x)) return x.length > 0;
  if (isDict(x)) return Object.keys(x).length > 0;
  return true;
}

export const or = (a, b) => (truthy(a) ? a : b);

// A value used as a lookup key: lists and objects are unhashable and fail as malformed.
export function hashable(x) {
  if (isList(x) || isDict(x)) throw new TypeError("unhashable");
  return x;
}

export function sameKeys(o, names) {
  const keys = Object.keys(o).sort();
  const want = [...names].sort();
  return keys.length === want.length && keys.every((k, i) => k === want[i]);
}

// Type-exact equality, as `same` in crypto.py.
export function same(a, b) {
  if (a === null || b === null) return a === b;
  if (a instanceof Float || b instanceof Float)
    return a instanceof Float && b instanceof Float && a.value === b.value;
  if (isList(a) || isList(b))
    return (
      isList(a) &&
      isList(b) &&
      a.length === b.length &&
      a.every((x, i) => same(x, b[i]))
    );
  if (isDict(a) || isDict(b)) {
    if (!isDict(a) || !isDict(b)) return false;
    const ka = Object.keys(a);
    return sameKeys(b, ka) && ka.every((k) => same(a[k], b[k]));
  }
  return typeof a === typeof b && a === b;
}

// ---- strict parsing ----------------------------------------------------------------------------------

const SURROGATE =
  /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

function tooDeep(text) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (const ch of text) {
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === "[" || ch === "{") {
      depth += 1;
      if (depth > MAX_DEPTH) return true;
    } else if (ch === "]" || ch === "}") depth -= 1;
  }
  return false;
}

// An exact decimal as [sign, digits, exponent] with no leading or trailing zeros (zero is ["", "0", 0]).
function decimalOf(text) {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([-+]?\d+))?$/.exec(text);
  let digits = m[2] + (m[3] ?? "");
  let exponent = Number(m[4] ?? 0) - (m[3] ?? "").length;
  digits = digits.replace(/^0+/, "");
  if (digits === "") return ["", "0", 0];
  while (digits.endsWith("0")) {
    digits = digits.slice(0, -1);
    exponent += 1;
  }
  return [m[1], digits, exponent];
}

function integer(token) {
  if (token.replace(/^-/, "").length > 16)
    throw new Invalid(
      "json_unsafe_integer",
      "an integer is outside +/-(2^53 - 1)",
    );
  const value = Number(token);
  if (Math.abs(value) > MAX_SAFE_INTEGER)
    throw new Invalid(
      "json_unsafe_integer",
      "an integer is outside +/-(2^53 - 1)",
    );
  return value === 0 ? 0 : value;
}

function float(token) {
  const value = Number(token);
  if (!Number.isFinite(value))
    throw new Invalid("json_non_finite", "a number overflows binary64");
  if (Math.abs(value) > MAX_SAFE_INTEGER)
    throw new Invalid(
      "json_unsafe_integer",
      "a number is outside +/-(2^53 - 1)",
    );
  const a = decimalOf(token);
  const b = decimalOf(String(value));
  if (a[0] !== b[0] || a[1] !== b[1] || a[2] !== b[2])
    throw new Invalid(
      "json_excess_precision",
      "a number has more digits than binary64 holds",
    );
  return new Float(value);
}

const syntax = () => {
  throw new Invalid("json_syntax", "not valid JSON");
};
const nonFinite = (name) => {
  throw new Invalid("json_non_finite", `${name} is not valid JSON`);
};
const WS = " \t\n\r";
const ESCAPES = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

function parseText(text) {
  let i = 0;
  const ws = () => {
    while (i < text.length && WS.includes(text[i])) i++;
  };
  function value() {
    ws();
    const c = text[i];
    if (c === "{") return object();
    if (c === "[") return array();
    if (c === '"') return string();
    if (c === "N" && text.startsWith("NaN", i)) nonFinite("NaN");
    if (c === "I" && text.startsWith("Infinity", i)) nonFinite("Infinity");
    if (c === "-" && text.startsWith("-Infinity", i)) nonFinite("-Infinity");
    if (c === "-" || (c >= "0" && c <= "9")) return number();
    for (const [word, v] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ])
      if (text.startsWith(word, i)) {
        i += word.length;
        return v;
      }
    return syntax();
  }
  function number() {
    const m = /-?(?:0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?/y;
    m.lastIndex = i;
    const found = m.exec(text);
    if (found === null) syntax();
    i = m.lastIndex;
    return found[1] !== undefined || found[2] !== undefined
      ? float(found[0])
      : integer(found[0]);
  }
  function string() {
    i++;
    let out = "";
    for (;;) {
      if (i >= text.length) syntax();
      const c = text[i];
      if (c === '"') {
        i++;
        return out;
      }
      if (c < " ") syntax();
      if (c === "\\") {
        const e = text[i + 1];
        if (e === "u") {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) syntax();
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
        } else if (e !== undefined && Object.hasOwn(ESCAPES, e)) {
          out += ESCAPES[e];
          i += 2;
        } else syntax();
      } else {
        out += c;
        i++;
      }
    }
  }
  function array() {
    i++;
    const out = [];
    ws();
    if (text[i] === "]") {
      i++;
      return out;
    }
    for (;;) {
      out.push(value());
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "]") {
        i++;
        return out;
      }
      syntax();
    }
  }
  function object() {
    i++;
    const pairs = [];
    ws();
    if (text[i] === "}") {
      i++;
      return dict();
    }
    for (;;) {
      ws();
      if (text[i] !== '"') syntax();
      const key = string();
      ws();
      if (text[i] !== ":") syntax();
      i++;
      pairs.push([key, value()]);
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "}") {
        i++;
        break;
      }
      syntax();
    }
    const keys = pairs.map(([k]) => k);
    if (new Set(keys).size !== keys.length)
      throw new Invalid(
        "json_duplicate_key",
        "a JSON object has a duplicate key",
      );
    for (const k of keys)
      if (SURROGATE.test(k))
        throw new Invalid(
          "json_lone_surrogate",
          "a key holds a lone surrogate",
        );
    return dict(pairs);
  }
  const result = value();
  ws();
  if (i !== text.length) syntax();
  return result;
}

// `loads` of crypto.py: bytes (Uint8Array) or text.
export function loads(data) {
  let text;
  if (data instanceof Uint8Array) {
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
        data,
      );
    } catch {
      throw new Invalid("json_encoding", "not UTF-8");
    }
  } else if (isStr(data)) text = data;
  else throw new Invalid("json_syntax", "not JSON text");
  if (text.startsWith("﻿"))
    throw new Invalid("json_encoding", "starts with a byte order mark");
  if (SURROGATE.test(text))
    throw new Invalid("json_lone_surrogate", "the text holds a lone surrogate");
  if (tooDeep(text)) throw new Invalid("json_too_deep", "nested too deeply");
  const value = parseText(text);
  const stack = [value];
  while (stack.length) {
    const node = stack.pop();
    if (isStr(node)) {
      if (SURROGATE.test(node))
        throw new Invalid(
          "json_lone_surrogate",
          "a string holds a lone surrogate",
        );
    } else if (isList(node)) stack.push(...node);
    else if (isDict(node)) stack.push(...Object.values(node));
  }
  return value;
}

// ---- RFC 8785 --------------------------------------------------------------------------------------

export function jcs(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (isStr(value)) return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value))
      throw new Invalid("jcs_invalid", "a value has no canonical form");
    return String(value);
  }
  if (value instanceof Float) {
    if (!Number.isFinite(value.value))
      throw new Invalid("jcs_invalid", "a value has no canonical form");
    return String(value.value);
  }
  if (isList(value)) return `[${value.map(jcs).join(",")}]`;
  if (isDict(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
  }
  throw new Invalid("jcs_invalid", "a value has no canonical form");
}

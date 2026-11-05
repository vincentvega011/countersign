// The browser evidence verifier: `verify(raw, pinned)` and `verifyText(textOrBytes, pinned)`.
//
// Port of countersign_verify/__init__.py. It makes no network request and reads nothing but its
// arguments. Every result is `{name, ok, message, code}`; `code` is null when the step passed, the
// stable code of the failed check otherwise, or `malformed` when a value had the wrong shape.
import { Invalid, loads } from "./json.js";
import { Bundle, STEPS } from "./steps.js";

export { STEP_NAMES } from "./steps.js";

function failure(name, error) {
  if (error instanceof Invalid)
    return { name, ok: false, message: error.message, code: error.code };
  return {
    name,
    ok: false,
    message: `malformed (${error?.name ?? "Error"})`,
    code: "malformed",
  };
}

export async function verify(raw, pinned = null) {
  let bundle;
  try {
    bundle = new Bundle(raw, pinned);
  } catch (error) {
    return [failure("bundle_structure", error)];
  }
  const results = [];
  for (const [name, step] of STEPS) {
    try {
      results.push({ name, ok: true, message: await step(bundle), code: null });
    } catch (error) {
      results.push(failure(name, error));
    }
  }
  return results;
}

export async function verifyText(data, pinned = null) {
  let raw;
  try {
    raw = loads(data);
  } catch (error) {
    return [failure("bundle_structure", error)];
  }
  return verify(raw, pinned);
}

// Parse a pasted public key with the same strict rules. Throws Invalid.
export const parseKey = (text) => loads(text);

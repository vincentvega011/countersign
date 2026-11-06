// Groups a fingerprint like the shared UI does, with no throw on an empty value.
import { groupFingerprint as group } from "../../ui/ui.js";

export function groupFingerprint(value: string, size = 4): string[] {
  return value ? group(value, size) : [];
}

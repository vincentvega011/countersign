// Display helpers. Money goes through the shared UI's formatter (integer minor units only, never a
// float), so the dashboard and the phone pages print amounts the same way.
import { formatAmount, groupFingerprint } from "../../ui/ui.js";

export function money(minor: unknown, currency = "USD"): string {
  if (typeof minor !== "number" || !Number.isSafeInteger(minor)) return "";
  return formatAmount(minor, currency);
}

export function shortFingerprint(value: string | null): string | null {
  if (!value) return null;
  return groupFingerprint(value.slice(0, 8)).join(" ");
}

export const SOURCE_LABEL: Record<string, string> = {
  live_sandbox: "Sandbox",
  recorded: "Recorded",
  simulator: "Simulated",
  unlabelled: "Unlabelled",
};

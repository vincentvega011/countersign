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

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];
const two = (n: number) => String(n).padStart(2, "0");

// "9 Nov 2026, 18:20" in UTC: the month is a name, so no reader has to guess day/month order, and the
// zone is fixed so the same instant reads the same everywhere. Column headers say "(UTC)".
export function formatDateTime(value: unknown): string {
  const d = value instanceof Date ? value : new Date(value as string | number);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}`;
}
export const dateTimeFormatter = () => (value: unknown) =>
  formatDateTime(value);

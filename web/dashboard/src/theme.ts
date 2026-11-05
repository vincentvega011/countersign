// The project's tokens (web/ui/tokens.css) applied to AG Studio, its grid and its charts, in light and
// dark. Values are read from the tokens at run time, so tokens.css stays the one source of truth.
import { studioTheme } from "ag-studio";

export type Scheme = "light" | "dark";

const NAMES = [
  "page", "surface", "sunken", "text", "muted", "border", "border-strong", "accent",
  "accent-surface", "focus", "success", "success-surface", "warning", "warning-surface",
  "danger", "danger-surface", "info", "info-surface",
] as const; // prettier-ignore
type Token = (typeof NAMES)[number];

function read(
  scheme: Scheme,
): Record<Token | "font-ui" | "font-mono" | "font-display", string> {
  const probe = document.createElement("div");
  probe.setAttribute("data-theme", scheme);
  probe.hidden = true;
  document.body.append(probe);
  const style = getComputedStyle(probe);
  const out = {} as Record<string, string>;
  for (const name of NAMES)
    out[name] = style.getPropertyValue(`--color-${name}`).trim();
  for (const name of ["font-ui", "font-mono", "font-display"])
    out[name] = style.getPropertyValue(`--${name}`).trim();
  probe.remove();
  return out as Record<
    Token | "font-ui" | "font-mono" | "font-display",
    string
  >;
}

function params(scheme: Scheme) {
  const t = read(scheme);
  const palette = [t.accent, t.info, t.warning, t.success, t.danger, t.muted];
  const fills = Object.fromEntries(
    palette.map((color, i) => [`chartPaletteFills${i + 1}Color`, color]),
  );
  const strokes = Object.fromEntries(
    palette.map((color, i) => [`chartPaletteStrokes${i + 1}Color`, color]),
  );
  return {
    browserColorScheme: scheme,
    backgroundColor: t.surface,
    foregroundColor: t.text,
    textColor: t.text,
    subtleTextColor: t.muted,
    accentColor: t.accent,
    borderColor: t.border,
    invalidColor: t.danger,
    fontFamily: t["font-ui"],
    fontSize: 14,
    borderRadius: 6,
    rowHoverColor: t["accent-surface"],
    menuBackgroundColor: t.surface,
    tooltipBackgroundColor: t.text,
    tooltipTextColor: t.surface,
    studioWrapperBackgroundColor: t.page,
    studioCanvasBackgroundColor: t.page,
    studioWidgetBackgroundColor: t.surface,
    studioWidgetBorder: { color: t.border, width: 1 },
    studioWidgetBorderRadius: 10,
    studioWidgetShadow: "none",
    studioWidgetTitleFontFamily: t["font-display"],
    studioWidgetTitleFontSize: 17,
    studioWidgetTitleFontWeight: 600,
    studioWidgetTitleTextColor: t.text,
    studioWidgetSubtitleTextColor: t.muted,
    studioWidgetSelectedBorderColor: t.focus,
    studioPanelContainerBackgroundColor: t.surface,
    gridFontFamily: t["font-ui"],
    gridHeaderBackgroundColor: t.sunken,
    gridHeaderTextColor: t.muted,
    gridHeaderFontWeight: 600,
    gridOddRowBackgroundColor: t.surface,
    gridDataBackgroundColor: t.surface,
    gridRowHoverColor: t["accent-surface"],
    gridAccentColor: t.accent,
    gridCellTextColor: t.text,
    gridRowBorder: { color: t.border, width: 1 },
    gridColumnBorder: false,
    gridWrapperBorder: false,
    chartFontFamily: t["font-ui"],
    chartTextColor: t.text,
    chartSubtleTextColor: t.muted,
    chartAxisLabelColor: t.muted,
    chartAxisLineColor: t["border-strong"],
    chartGridLineColor: t.border,
    chartAccentColor: t.accent,
    chartTooltipBackgroundColor: t.surface,
    chartTooltipTextColor: t.text,
    chartLegendLabelColor: t.text,
    ...fills,
    ...strokes,
  };
}

// One theme, two named modes; `applyScheme` switches by setting data-ag-theme-mode.
export function buildTheme() {
  return studioTheme
    .withParams(params("light") as never, "light")
    .withParams(params("dark") as never, "dark");
}

export function applyScheme(scheme: Scheme): void {
  document.documentElement.setAttribute("data-theme", scheme);
  document.documentElement.setAttribute("data-ag-theme-mode", scheme);
}

export function initialScheme(): Scheme {
  const saved = localStorage.getItem("cs.dashboard.scheme");
  if (saved === "light" || saved === "dark") return saved;
  return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function remember(scheme: Scheme): void {
  localStorage.setItem("cs.dashboard.scheme", scheme);
}

// Status pills and mandate states reuse the shared UI's tones; these are the token pairs.
export const TONE_VARS: Record<string, [string, string]> = {
  success: ["var(--color-success)", "var(--color-success-surface)"],
  warning: ["var(--color-warning)", "var(--color-warning-surface)"],
  danger: ["var(--color-danger)", "var(--color-danger-surface)"],
  info: ["var(--color-info)", "var(--color-info-surface)"],
  neutral: ["var(--color-muted)", "var(--color-sunken)"],
  accent: ["var(--color-accent)", "var(--color-accent-surface)"],
};

declare const __AG_STUDIO_LICENSE_KEY__: string;

declare module "*.css";

declare module "../../ui/ui.js" {
  export function formatAmount(
    minor: number | bigint,
    currency?: string,
  ): string;
  export function groupFingerprint(value: string, size?: number): string[];
  export const STATUS: Readonly<
    Record<string, { label: string; tone: string; glyph: string }>
  >;
}

"""Read the design tokens and check WCAG 2.x contrast. A library for the UI token tests.

The tokens file keeps each theme in a block of plain `--name: #rrggbb;` declarations, so no CSS engine
is needed. `PAIRS` is the manifest of every (foreground, background) the components use, with the
WCAG level it must meet: 4.5 for body text, 3.0 for large text and for UI boundaries (control
outlines, focus ring).
"""

from __future__ import annotations

import re
from pathlib import Path

TOKENS = Path(__file__).resolve().parents[1] / "web" / "ui" / "tokens.css"
BODY, LARGE, UI = 4.5, 3.0, 3.0

_DECL = re.compile(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;")

SURFACES = ("page", "surface", "sunken")
STATUSES = ("success", "warning", "danger", "info")


def _block(css: str, opener: str) -> str:
    """The text between the braces that follow `opener`, balanced."""
    start = css.index(opener) + len(opener)
    start = css.index("{", start) + 1
    depth, i = 1, start
    while depth:
        depth += {"{": 1, "}": -1}.get(css[i], 0)
        i += 1
    return css[start : i - 1]


def colors(block: str) -> dict[str, str]:
    return {name.removeprefix("color-"): value.lower() for name, value in _DECL.findall(block)}


def themes(css: str | None = None) -> dict[str, dict[str, str]]:
    css = TOKENS.read_text() if css is None else css
    light = colors(_block(css, ':root,\n[data-theme="light"]'))
    media = colors(_block(_block(css, "@media (prefers-color-scheme: dark)"), ":root:not"))
    forced = colors(_forced(css))
    return {"light": light, "dark": forced, "dark-media": media}


def _forced(css: str) -> str:
    marker = '\n[data-theme="dark"] {'
    start = css.index(marker) + len(marker)
    return css[start : css.index("\n}", start)]


def luminance(hex_color: str) -> float:
    channels = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def pairs() -> list[tuple[str, str, float, str]]:
    """(foreground token, background token, minimum ratio, what it is)."""
    out: list[tuple[str, str, float, str]] = []
    for bg in SURFACES:
        out += [("text", bg, BODY, "body text"), ("muted", bg, BODY, "secondary text")]
        out += [("accent", bg, BODY, "accent as text or link"), ("focus", bg, UI, "focus ring")]
        out += [("border-strong", bg, UI, "control outline")]
        out += [(s, bg, BODY, f"{s} as text") for s in STATUSES]
    out += [
        ("on-accent", "accent", BODY, "primary button"),
        ("on-accent", "accent-hover", BODY, "primary button hover"),
    ]
    out += [
        ("on-danger", "danger", BODY, "danger button"),
        ("on-danger", "danger-hover", BODY, "danger button hover"),
    ]
    out += [("accent", "accent-surface", BODY, "accent badge")]
    out += [(s, f"{s}-surface", BODY, f"{s} badge and pill") for s in STATUSES]
    out += [("muted", "sunken", BODY, "neutral pill and disabled button")]
    out += [("danger", "danger-surface", BODY, "negative amount on tint")]
    return out


def failures(theme: dict[str, str]) -> list[str]:
    bad: list[str] = []
    for fg, bg, minimum, what in pairs():
        if fg not in theme or bg not in theme:
            bad.append(f"missing token for {what}: {fg} on {bg}")
            continue
        ratio = contrast(theme[fg], theme[bg])
        if ratio < minimum:
            bad.append(f"{what}: {fg} on {bg} is {ratio:.2f}, needs {minimum}")
    return bad

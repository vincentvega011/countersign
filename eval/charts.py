"""Dependency-free SVG charts for the evaluation report.

Plain horizontal bars with the value written at the end of each bar, so a zero is visible as a label
rather than as an empty space. Colors are fixed (they read on both light and dark backgrounds because
each chart draws its own panel).
"""

from __future__ import annotations

from html import escape

PANEL, INK, MUTED, GRID = "#fbfaf7", "#1d2a2f", "#5b6b70", "#d9d6cd"
FULL, BASELINE, WARN = "#1f6f5c", "#b4472f", "#b4472f"
FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"
LEFT, ROW, BAR, RIGHT = 250, 34, 12, 70


def _frame(title: str, height: int, width: int, body: str, legend: str = "") -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
        f'height="{height}" role="img" aria-label="{escape(title)}" font-family="{FONT}">'
        f'<rect width="{width}" height="{height}" fill="{PANEL}" rx="8"/>'
        f'<text x="16" y="26" font-size="15" font-weight="600" fill="{INK}">{escape(title)}</text>'
        f"{legend}{body}</svg>\n"
    )


def _legend(items: list[tuple[str, str]], width: int) -> str:
    out, x = [], width - 16
    for label, color in reversed(items):
        x -= 14 + 7 * len(label) + 14
        out.append(
            f'<rect x="{x}" y="14" width="10" height="10" fill="{color}" rx="2"/>'
            f'<text x="{x + 14}" y="23" font-size="11" fill="{MUTED}">{escape(label)}</text>'
        )
    return "".join(out)


def grouped_bars(
    title: str, rows: list[tuple[str, list[int]]], series: list[tuple[str, str]], width: int = 720
) -> str:
    """One row per label, one bar per series, the value at the end of every bar."""
    top = 44
    top_value = max([1] + [v for _, vals in rows for v in vals])
    scale = (width - LEFT - RIGHT) / top_value
    row_h = ROW + (len(series) - 1) * (BAR + 3)
    body = [
        f'<line x1="{LEFT}" y1="{top - 6}" x2="{LEFT}" y2="{top + row_h * len(rows)}" stroke="{GRID}"/>'
    ]
    for i, (label, vals) in enumerate(rows):
        y = top + i * row_h
        body.append(
            f'<text x="{LEFT - 10}" y="{y + 16}" font-size="12" fill="{INK}" text-anchor="end">'
            f"{escape(label)}</text>"
        )
        for j, ((_, color), v) in enumerate(zip(series, vals, strict=True)):
            by = y + 6 + j * (BAR + 3)
            w = v * scale
            if v:
                body.append(
                    f'<rect x="{LEFT}" y="{by}" width="{w:.1f}" height="{BAR}" fill="{color}" rx="2"/>'
                )
            body.append(
                f'<text x="{LEFT + w + 6:.1f}" y="{by + 10}" font-size="11" fill="{MUTED}">{v}</text>'
            )
    height = top + row_h * len(rows) + 12
    return _frame(title, height, width, "".join(body), _legend(series, width))


def single_bars(
    title: str, rows: list[tuple[str, float]], color: str = FULL, width: int = 720, unit: str = ""
) -> str:
    return grouped_bars_float(title, rows, color, width, unit)


def grouped_bars_float(
    title: str, rows: list[tuple[str, float]], color: str, width: int, unit: str
) -> str:
    top = 44
    top_value = max([1e-9] + [v for _, v in rows])
    scale = (width - LEFT - RIGHT - 20) / top_value
    body = [
        f'<line x1="{LEFT}" y1="{top - 6}" x2="{LEFT}" y2="{top + ROW * len(rows)}" stroke="{GRID}"/>'
    ]
    for i, (label, v) in enumerate(rows):
        y = top + i * ROW
        body.append(
            f'<text x="{LEFT - 10}" y="{y + 18}" font-size="12" fill="{INK}" text-anchor="end">'
            f"{escape(label)}</text>"
        )
        if v:
            body.append(
                f'<rect x="{LEFT}" y="{y + 7}" width="{v * scale:.1f}" height="{BAR + 4}" fill="{color}" rx="2"/>'
            )
        body.append(
            f'<text x="{LEFT + v * scale + 6:.1f}" y="{y + 19}" font-size="11" fill="{MUTED}">'
            f"{v:g}{unit}</text>"
        )
    return _frame(title, top + ROW * len(rows) + 12, width, "".join(body))

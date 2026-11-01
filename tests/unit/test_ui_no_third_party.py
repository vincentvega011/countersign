"""No page under web/ loads anything from another origin, and no trademark of a third party ships."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[2] / "web"
# `web/*/test/` holds dev tooling run by Node (the screenshot script names the loopback server); no
# page loads it, so it is not a page resource.
SOURCES = sorted(
    p
    for p in WEB.rglob("*")
    if p.suffix in {".html", ".css", ".js", ".mjs"}
    and "node_modules" not in p.parts
    and "test" not in p.relative_to(WEB).parts
)
ABSOLUTE = re.compile(r"(?:https?:)?//[A-Za-z0-9\[]", re.IGNORECASE)
SCHEMES = re.compile(r"\b(?:data|blob|ftp|ws|wss):", re.IGNORECASE)
IMPORT_REMOTE = re.compile(
    r"@import\s+(?:url\()?['\"]?(?!\.{0,2}/|[a-z0-9_-]+\.css)", re.IGNORECASE
)
MARKS = ("paypal", "venmo", "braintree", "google fonts", "fonts.googleapis", "gstatic", "cdn")


def test_there_is_something_to_check() -> None:
    names = {p.name for p in SOURCES}
    assert {"tokens.css", "components.css", "fonts.css", "ui.js", "gallery.html"} <= names


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(WEB)))
def test_a_source_references_only_its_own_origin(path: Path) -> None:
    text = path.read_text()
    assert ABSOLUTE.search(text) is None, f"absolute URL in {path}"
    assert SCHEMES.search(text) is None, f"remote or inline scheme in {path}"
    assert IMPORT_REMOTE.search(text) is None, f"remote @import in {path}"
    assert "<iframe" not in text.lower()


@pytest.mark.parametrize("path", [p for p in SOURCES if p.suffix == ".html"], ids=lambda p: p.name)
def test_html_loads_scripts_and_styles_by_relative_path_only(path: Path) -> None:
    text = path.read_text()
    refs = re.findall(r"""(?:src|href)=["']([^"']+)["']""", text)
    assert refs, "a page with no resources is suspicious"
    for ref in refs:
        assert not re.match(r"^(?:[a-z][a-z0-9+.-]*:|//)", ref, re.IGNORECASE), ref


def test_fonts_are_local_woff2_with_their_licence_beside_them() -> None:
    css = (WEB / "ui" / "fonts.css").read_text()
    urls = re.findall(r"url\(([^)]+)\)", css)
    assert urls and all(
        u.strip("\"'").startswith("fonts/") and u.strip("\"'").endswith(".woff2") for u in urls
    )
    for u in urls:
        assert (WEB / "ui" / u.strip("\"'")).is_file()
    licences = {p.name for p in (WEB / "ui" / "fonts").glob("LICENSE-*.txt")}
    assert len(licences) >= 3
    for p in (WEB / "ui" / "fonts").glob("LICENSE-*.txt"):
        assert "SIL Open Font License" in p.read_text()


def test_no_third_party_mark_or_service_is_named_in_the_ui() -> None:
    for path in SOURCES:
        lowered = path.read_text().lower()
        for mark in MARKS:
            assert mark not in lowered, f"{mark!r} in {path}"

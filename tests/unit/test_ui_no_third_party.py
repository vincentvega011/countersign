"""No page under web/ loads anything from another origin, and no trademark of a third party ships."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[2] / "web"
# `web/*/test/` holds dev tooling run by Node (the screenshot script names the loopback server); no
# page loads it, so it is not a page resource.
# The dashboard's build output (`dist`, gitignored, vendor code that is never fetched from elsewhere: the
# browser test checks that no request leaves the origin) and local scratch files (`.artifacts`) are not
# sources; the dashboard's own TypeScript is.
SOURCES = sorted(
    p
    for p in WEB.rglob("*")
    if (
        p.suffix in {".html", ".css", ".js", ".mjs"}
        or (p.suffix in {".ts", ".tsx"} and (WEB / "dashboard" / "src") in p.parents)
    )
    and "node_modules" not in p.parts
    and "dist" not in p.parts
    and ".artifacts" not in p.parts
    and "test" not in p.relative_to(WEB).parts
)
# The landing page (Decision 142) links the project's own repository: the one absolute URL any page may hold,
# a plain anchor that loads nothing. It is removed before the checks below so any other absolute URL fails.
REPOSITORY_LINK = "https://github.com/vincentvega011/countersign"
LANDING_PAGE = WEB / "landing" / "index.html"


def without_repository_link(path: Path, text: str) -> str:
    return text.replace(REPOSITORY_LINK, "") if path == LANDING_PAGE else text


ABSOLUTE = re.compile(r"(?:https?:)?//[A-Za-z0-9\[]", re.IGNORECASE)
# A scheme is followed directly by its body; `data: rows` in a TypeScript object literal is not one.
SCHEMES = re.compile(r"\b(?:data|blob|ftp|ws|wss):(?!\s)", re.IGNORECASE)
IMPORT_REMOTE = re.compile(
    r"@import\s+(?:url\()?['\"]?(?!\.{0,2}/|[a-z0-9_-]+\.css)", re.IGNORECASE
)
MARKS = ("paypal", "venmo", "braintree", "google fonts", "fonts.googleapis", "gstatic", "cdn")


def test_there_is_something_to_check() -> None:
    names = {p.name for p in SOURCES}
    assert {"tokens.css", "components.css", "fonts.css", "ui.js", "gallery.html"} <= names


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(WEB)))
def test_a_source_references_only_its_own_origin(path: Path) -> None:
    text = without_repository_link(path, path.read_text())
    assert ABSOLUTE.search(text) is None, f"absolute URL in {path}"
    assert SCHEMES.search(text) is None, f"remote or inline scheme in {path}"
    assert IMPORT_REMOTE.search(text) is None, f"remote @import in {path}"
    assert "<iframe" not in text.lower()


@pytest.mark.parametrize("path", [p for p in SOURCES if p.suffix == ".html"], ids=lambda p: p.name)
def test_html_loads_scripts_and_styles_by_relative_path_only(path: Path) -> None:
    text = without_repository_link(path, path.read_text())
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


# The evidence verifier reads a bundle whose members and step names say `paypal` (fixed by the Python
# CLI), and its page names PayPal as the platform the evidence comes from, as text only: no logo, no
# brand colour (Decision 108). Every other page may not name it.
NAMES_THE_PLATFORM = {WEB / "verify", WEB / "ui" / "evidence", WEB / "landing"}
# The merchant dashboard names PayPal as the platform its orders are paid on, in text only (Decision 117).
DASHBOARD_SRC = WEB / "dashboard" / "src"


def test_no_third_party_mark_or_service_is_named_in_the_ui() -> None:
    for path in SOURCES:
        lowered = path.read_text().lower()
        for mark in MARKS:
            if mark == "paypal" and path.parent in {*NAMES_THE_PLATFORM, DASHBOARD_SRC}:
                continue
            assert mark not in lowered, f"{mark!r} in {path}"


def test_the_verifier_names_the_platform_in_text_only() -> None:
    for folder in NAMES_THE_PLATFORM:
        for path in folder.iterdir():
            text = path.read_text().lower()
            assert "logo" not in text and "<img" not in text and "<svg" not in text, path


def test_the_dashboard_names_the_platform_in_text_only() -> None:
    for path in DASHBOARD_SRC.iterdir():
        text = path.read_text().lower()
        assert "logo" not in text and "<img" not in text and "brand colour" not in text, path

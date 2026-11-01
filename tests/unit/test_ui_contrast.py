"""Design tokens meet WCAG AA in both themes, and the two copies of the dark theme agree."""

from __future__ import annotations

import pytest

from tests.ui_contrast import TOKENS, contrast, failures, pairs, themes


def test_the_known_ratios_are_computed_correctly() -> None:
    assert contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast("#ffffff", "#ffffff") == pytest.approx(1.0)
    assert contrast("#767676", "#ffffff") == pytest.approx(
        4.54, abs=0.01
    )  # the classic AA boundary
    assert contrast("#777777", "#ffffff") < 4.5


@pytest.mark.parametrize("name", ["light", "dark"])
def test_every_text_surface_and_boundary_pair_meets_aa(name: str) -> None:
    assert failures(themes()[name]) == []


def test_the_manifest_covers_every_status_and_surface() -> None:
    names = {(fg, bg) for fg, bg, _, _ in pairs()}
    for surface in ("page", "surface", "sunken"):
        assert ("text", surface) in names and ("border-strong", surface) in names
    for status in ("success", "warning", "danger", "info"):
        assert (status, f"{status}-surface") in names and (status, "surface") in names


def test_the_media_query_dark_theme_equals_the_forced_dark_theme() -> None:
    found = themes()
    assert found["dark-media"] == found["dark"] and found["dark"]


def test_light_and_dark_define_the_same_color_roles() -> None:
    found = themes()
    assert set(found["light"]) == set(found["dark"])


def test_a_deliberately_bad_token_fails_the_check() -> None:
    """Show once that the checker bites: weaken the muted text and a status colour."""
    bad = dict(themes()["light"])
    bad["muted"] = "#b5b5b0"  # about 2:1 on the page
    bad["warning"] = "#e0a030"
    found = failures(bad)
    assert any("secondary text: muted on page" in line for line in found), found
    assert any("warning" in line for line in found), found
    assert len(found) >= 4


def test_a_missing_token_is_a_failure_not_a_pass() -> None:
    incomplete = {k: v for k, v in themes()["light"].items() if k != "text"}
    assert any("missing token" in line for line in failures(incomplete))


def test_the_tokens_file_is_where_the_checker_reads() -> None:
    assert TOKENS.is_file()


def test_the_thresholds_are_the_wcag_aa_values() -> None:
    from tests.ui_contrast import BODY, LARGE, UI

    assert (BODY, LARGE, UI) == (4.5, 3.0, 3.0)
    for fg, bg, minimum, what in pairs():
        assert minimum in (BODY, UI), (fg, bg, what)
        if (
            "text" in what
            or "badge" in what
            or "button" in what
            or "pill" in what
            or "amount" in what
        ):
            assert minimum == BODY, (fg, bg, what)
        else:
            assert minimum == UI, (fg, bg, what)

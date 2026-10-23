"""Seeded catalog: loads deterministically and every rule has a rejecting test."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from countersign.canonical.models import Checkout, Item
from countersign.canonical.money import Money
from countersign.catalog import (
    Catalog,
    CatalogError,
    default_catalog_path,
    load_catalog,
    parse_catalog,
)

PATH = default_catalog_path()
BASE: dict[str, Any] = yaml.safe_load(PATH.read_text())


def variant(mutate) -> bytes:
    data = copy.deepcopy(BASE)
    mutate(data)
    return yaml.safe_dump(data, sort_keys=False).encode()


def rejected(mutate, match: str | None = None) -> None:
    with pytest.raises(CatalogError) as info:
        parse_catalog(variant(mutate))
    if match:
        assert match in str(info.value)


# ---- the shipped file ----


def test_the_default_path_points_at_the_repository_file():
    assert PATH.name == "catalog.yaml" and PATH.parent.name == "data" and PATH.is_file()


def test_catalog_loads_with_the_expected_shape():
    c = load_catalog()
    assert isinstance(c, Catalog)
    assert 30 <= len(c.items) <= 60
    assert len(c.categories) == 5
    assert c.currency == "USD"
    for category in c.categories:
        assert len(c.in_category(category.id)) >= 3
    assert {i.category for i in c.items} == {x.id for x in c.categories}
    assert {i.brand for i in c.items} <= set(c.brands)


def test_every_item_passes_canonical_model_validation():
    c = load_catalog()
    for entry in c.items:
        item = entry.to_item()
        assert isinstance(item, Item)
        assert item.price == entry.price == Money("USD", entry.price.minor)
        checkout = Checkout.from_lines("chk", "USD", [("l1", item, 1)])
        assert checkout.totals[-1].amount == entry.price
        assert Checkout.from_ucp(checkout.to_ucp()) == checkout


def test_a_checkout_over_the_whole_catalog_is_consistent():
    c = load_catalog()
    lines = [(f"l{n}", entry.to_item(), n % 3 + 1) for n, entry in enumerate(c.items)]
    checkout = Checkout.from_lines("chk", "USD", lines)
    expected = sum(entry.price.minor * (n % 3 + 1) for n, entry in enumerate(c.items))
    assert checkout.totals[-1].amount.minor == expected


def test_the_demo_has_headphones_under_eighty_dollars():
    c = load_catalog()
    cheap = [i for i in c.in_category("headphones") if i.price.minor < 8000]
    assert len(cheap) >= 3
    assert any(i.price.minor >= 8000 for i in c.in_category("headphones"))


def test_loading_is_deterministic():
    first, second = load_catalog(), load_catalog(PATH)
    assert first == second
    assert (
        first.catalog_hash()
        == second.catalog_hash()
        == parse_catalog(PATH.read_bytes()).catalog_hash()
    )
    assert len(first.catalog_hash()) == 32
    assert [i.id for i in first.items] == sorted(i.id for i in first.items)


def test_catalog_hash_changes_when_any_field_changes():
    base = load_catalog().catalog_hash()
    for mutate in (
        lambda d: d["items"][0].update(price_minor=d["items"][0]["price_minor"] + 1),
        lambda d: d["items"][0].update(title=d["items"][0]["title"] + " X"),
        lambda d: d["items"][0].update(description="Changed."),
        lambda d: d["categories"][0].update(title="Other"),
    ):
        assert parse_catalog(variant(mutate)).catalog_hash() != base


def test_text_is_printable_ascii_only_and_has_no_em_dashes():
    text = PATH.read_text(encoding="utf-8")
    assert text.isascii()
    assert chr(0x2014) not in text
    for entry in load_catalog().items:
        assert entry.title.isprintable() and len(entry.title) <= 127


def test_brand_names_are_the_declared_fictional_set():
    assert set(load_catalog().brands) == {
        "Brindlewick",
        "Ostrander",
        "Quillmark",
        "Tolliver & Reed",
        "Veltro",
        "Zephyrine",
    }


def test_item_lookup():
    c = load_catalog()
    first = c.items[0]
    assert c.item(first.id) == first
    with pytest.raises(KeyError):
        c.item("nope")


# ---- rejections ----


def test_unmodified_variant_still_loads():
    assert parse_catalog(variant(lambda d: None)) == load_catalog()


def test_duplicate_yaml_keys_are_rejected():
    text = PATH.read_text().replace("version: 1\n", "version: 1\nversion: 1\n", 1)
    with pytest.raises(CatalogError, match="duplicate key"):
        parse_catalog(text.encode())
    nested = PATH.read_text().replace(
        "    price_minor: 3900\n", "    price_minor: 3900\n    price_minor: 1\n", 1
    )
    with pytest.raises(CatalogError, match="duplicate key"):
        parse_catalog(nested.encode())


@pytest.mark.parametrize("bad", [39.0, 39.5, "3900", True, None, -1, 0, 100_001])
def test_prices_must_be_integers_of_minor_units_in_range(bad):
    rejected(lambda d: d["items"][0].update(price_minor=bad))


def test_items_must_be_sorted_by_id():
    rejected(lambda d: d["items"].reverse(), "sorted")
    rejected(lambda d: d["items"].insert(0, d["items"].pop(5)), "sorted")


def test_duplicate_ids_and_titles_are_rejected():
    rejected(lambda d: d["items"][1].update(id=d["items"][0]["id"]))
    rejected(lambda d: d["items"][1].update(title=d["items"][0]["title"]), "titles must be unique")


def test_undeclared_category_and_brand_are_rejected():
    rejected(lambda d: d["items"][0].update(category="gadgets"), "undeclared category")
    rejected(lambda d: d["items"][0].update(brand="Acme"), "undeclared brand")


def test_category_count_and_minimum_population():
    rejected(lambda d: d["categories"].pop(), "exactly 5 categories")
    rejected(
        lambda d: d["categories"].append({"id": "extra", "title": "Extra"}), "exactly 5 categories"
    )

    def starve(d):
        keep = [i for i in d["items"] if i["category"] != "cables"]
        d["items"] = keep + [i for i in d["items"] if i["category"] == "cables"][:2]
        d["items"].sort(key=lambda i: i["id"])

    rejected(starve, "at least 3")


def test_item_count_bounds():
    rejected(lambda d: d.update(items=d["items"][:29]), "30 to 60")
    rejected(lambda d: d.update(items=d["items"][:20]))

    def many(d):
        extra = []
        for n in range(16):
            clone = copy.deepcopy(d["items"][0])
            clone["id"] = f"zz-extra-{n:02d}"
            clone["title"] = f"Extra {n}"
            extra.append(clone)
        d["items"] = d["items"] + extra

    rejected(many, "30 to 60")


def test_only_usd_and_version_one():
    rejected(lambda d: d.update(currency="EUR"))
    rejected(lambda d: d.update(currency="JPY"))
    rejected(lambda d: d.update(version=2))


@pytest.mark.parametrize(
    "title",
    [
        f"Caf{chr(0xE9)} Speaker",
        f"Dash {chr(0x2014)} Speaker",
        "Tab\tSpeaker",
        "Emoji \U0001f600",
        "",
        "x" * 128,
    ],
)
def test_titles_must_be_short_printable_ascii(title):
    rejected(lambda d: d["items"][0].update(title=title))


@pytest.mark.parametrize(
    "item_id", ["UPPER", "has space", "-lead", "trail-", "dou--ble", "", "a_b", "x" * 128]
)
def test_ids_must_be_lowercase_slugs(item_id):
    rejected(lambda d: d["items"][0].update(id=item_id))


def test_unknown_or_missing_members_are_rejected():
    rejected(lambda d: d.update(extra="x"))
    rejected(lambda d: d.pop("brands"))
    rejected(lambda d: d["items"][0].update(sku="x"))
    rejected(lambda d: d["items"][0].pop("description"))
    rejected(lambda d: d["items"][0].pop("price_minor"), "price_minor")
    rejected(lambda d: d["categories"][0].update(extra="x"))


def test_malformed_files_are_rejected_with_a_typed_error():
    for data in (b"\xff\xfe", b"not: [valid", b"- a\n- b\n", b"just text", b""):
        with pytest.raises(CatalogError):
            parse_catalog(data)


def test_missing_file_is_a_catalog_error(tmp_path: Path):
    with pytest.raises(CatalogError):
        load_catalog(tmp_path / "absent.yaml")


def test_load_from_another_path_gives_the_same_catalog(tmp_path: Path):
    copy_path = tmp_path / "c.yaml"
    copy_path.write_bytes(PATH.read_bytes())
    assert load_catalog(copy_path).catalog_hash() == load_catalog().catalog_hash()


def test_models_are_frozen_and_strict():
    c = load_catalog()
    with pytest.raises(ValidationError):
        c.items[0].title = "x"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Catalog(**{**c.__dict__, "version": "1"})


def test_brands_and_category_ids_must_be_unique():
    rejected(lambda d: d["brands"].append(d["brands"][0]), "brands must be unique")
    rejected(
        lambda d: d["categories"][4].update(id=d["categories"][3]["id"]),
        "category ids must be unique",
    )


@pytest.mark.parametrize("version", [1.0, True, "1", 2, None])
def test_version_must_be_the_integer_one(version):
    rejected(lambda d: d.update(version=version))


def test_catalog_hash_is_domain_separated_over_the_jcs_bytes():
    from countersign.canonical import canonicalize, domain_hash

    c = load_catalog()
    assert c.catalog_hash() == domain_hash("cs.catalog.v1", canonicalize(c.to_dict()))


def test_descriptions_are_short_printable_ascii():
    rejected(lambda d: d["items"][0].update(description="x" * 201))
    rejected(lambda d: d["items"][0].update(description=""))
    rejected(lambda d: d["items"][0].update(description=f"na{chr(0xEF)}ve"))
    parse_catalog(variant(lambda d: d["items"][0].update(description="x" * 200)))

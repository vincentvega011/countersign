"""The seeded demo catalog: fictional brands, USD only, validated when it is loaded.

Security reasoning. The catalog is the price authority for the demo merchant, so a typo in it is a
wrong price on a signed checkout. It is therefore parsed with a loader that rejects what YAML
accepts silently (duplicate mapping keys, which would let a later entry override an earlier one),
every price is an integer of minor units (a YAML float is an error, INV-9), and the file must be
in a canonical form: items sorted by id, no duplicate ids or titles, every brand and category
declared, text restricted to printable ASCII (so no look-alike characters and no em dashes), and
lengths within what PayPal returns unchanged. The same file therefore always loads to the same
catalog, and `catalog_hash` proves it.

The data is fictional by construction: invented brand names and generic product descriptions. Check
a name for trademark conflicts before showing it in a video.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    InstanceOf,
    StrictInt,
    ValidationError,
    model_validator,
)

from countersign.canonical.hashing import domain_hash
from countersign.canonical.jcs import canonicalize
from countersign.canonical.models import MAX_TEXT, Item
from countersign.canonical.money import Money

CATALOG_DOMAIN = "cs.catalog.v1"
MIN_ITEMS, MAX_ITEMS = 30, 60
CATEGORY_COUNT = 5
MIN_PER_CATEGORY = 3
MAX_PRICE_MINOR = 100_000

_ID = r"^[a-z0-9]+(-[a-z0-9]+)*$"
_PRINTABLE_ASCII = r"^[\x20-\x7e]+$"


class CatalogError(ValueError):
    """The catalog file is unreadable or breaks a rule. Nothing is loaded."""

    code = "catalog_invalid"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class Category(_Model):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,30}$")
    title: str = Field(min_length=1, max_length=60, pattern=_PRINTABLE_ASCII)


class CatalogItem(_Model):
    id: str = Field(min_length=1, max_length=MAX_TEXT, pattern=_ID)
    title: str = Field(min_length=1, max_length=MAX_TEXT, pattern=_PRINTABLE_ASCII)
    brand: str = Field(min_length=1, max_length=60, pattern=_PRINTABLE_ASCII)
    category: str
    price: InstanceOf[Money]
    description: str = Field(min_length=1, max_length=200, pattern=_PRINTABLE_ASCII)

    @model_validator(mode="after")
    def _price(self) -> CatalogItem:
        if not 1 <= self.price.minor <= MAX_PRICE_MINOR:
            raise ValueError(f"price of {self.id!r} must be between 1 and {MAX_PRICE_MINOR}")
        return self

    def to_item(self) -> Item:
        """The canonical checkout item for this product."""
        return Item(id=self.id, title=self.title, price=self.price)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "brand": self.brand,
            "category": self.category,
            "price_minor": self.price.minor,
            "description": self.description,
        }


class Catalog(_Model):
    version: StrictInt
    currency: Literal["USD"]
    brands: tuple[str, ...] = Field(min_length=1)
    categories: tuple[Category, ...]
    items: tuple[CatalogItem, ...]

    @model_validator(mode="after")
    def _rules(self) -> Catalog:
        if self.version != 1:  # StrictInt already refuses True and 1.0, which equal 1
            raise ValueError("unsupported catalog version")
        if len(self.categories) != CATEGORY_COUNT:
            raise ValueError(f"the catalog must have exactly {CATEGORY_COUNT} categories")
        if not MIN_ITEMS <= len(self.items) <= MAX_ITEMS:
            raise ValueError(f"the catalog must have {MIN_ITEMS} to {MAX_ITEMS} items")
        if len(set(self.brands)) != len(self.brands):
            raise ValueError("brands must be unique")
        category_ids = [c.id for c in self.categories]
        if len(set(category_ids)) != len(category_ids):
            raise ValueError("category ids must be unique")
        ids = [i.id for i in self.items]
        if ids != sorted(ids):
            raise ValueError("items must be sorted by id")
        if len(set(ids)) != len(ids):
            raise ValueError("item ids must be unique")
        titles = [i.title for i in self.items]
        if len(set(titles)) != len(titles):
            raise ValueError("item titles must be unique")
        for item in self.items:
            if item.category not in category_ids:
                raise ValueError(f"{item.id!r} has an undeclared category {item.category!r}")
            if item.brand not in self.brands:
                raise ValueError(f"{item.id!r} has an undeclared brand {item.brand!r}")
            if item.price.currency != self.currency:
                raise ValueError(f"{item.id!r} is not priced in {self.currency}")
        for category in category_ids:
            if sum(1 for i in self.items if i.category == category) < MIN_PER_CATEGORY:
                raise ValueError(f"category {category!r} needs at least {MIN_PER_CATEGORY} items")
        return self

    def item(self, item_id: str) -> CatalogItem:
        for entry in self.items:
            if entry.id == item_id:
                return entry
        raise KeyError(item_id)

    def in_category(self, category: str) -> tuple[CatalogItem, ...]:
        return tuple(i for i in self.items if i.category == category)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "currency": self.currency,
            "brands": list(self.brands),
            "categories": [{"id": c.id, "title": c.title} for c in self.categories],
            "items": [i.to_dict() for i in self.items],
        }

    def catalog_hash(self) -> bytes:
        """Domain-separated SHA-256 over the JCS bytes of the catalog; equal files give equal hashes."""
        return domain_hash(CATALOG_DOMAIN, canonicalize(self.to_dict()))


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise CatalogError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def default_catalog_path() -> Path:
    # SHORTCUT: assumes a source checkout (data/ next to src/); a packaged install would need the
    # file shipped as package data. The hosted demo runs from the repository.
    return Path(__file__).resolve().parents[3] / "data" / "catalog.yaml"


def parse_catalog(data: bytes) -> Catalog:
    """Parse and validate catalog YAML bytes."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise CatalogError("the catalog is not UTF-8") from None
    try:
        raw = yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise CatalogError(f"the catalog is not valid YAML: {type(exc).__name__}") from None
    if not isinstance(raw, dict):
        raise CatalogError("the catalog must be a mapping")
    expected = {"version", "currency", "brands", "categories", "items"}
    if set(raw) != expected:
        raise CatalogError(f"top-level keys must be exactly {sorted(expected)}")
    try:
        currency = raw["currency"]
        items = []
        for entry in _list(raw["items"], "items"):
            fields = dict(_mapping(entry, "item"))
            if "price_minor" not in fields:
                raise CatalogError("an item is missing price_minor")
            fields["price"] = Money.from_ucp(fields.pop("price_minor"), currency)
            items.append(CatalogItem(**fields))
        return Catalog(
            version=raw["version"],
            currency=currency,
            brands=tuple(_list(raw["brands"], "brands")),
            categories=tuple(
                Category(**_mapping(c, "category")) for c in _list(raw["categories"], "categories")
            ),
            items=tuple(items),
        )
    except (ValidationError, ValueError, TypeError) as exc:
        if isinstance(exc, CatalogError):
            raise
        raise CatalogError(str(exc)) from exc


def load_catalog(path: Path | None = None) -> Catalog:
    """Load the catalog file (the repository's `data/catalog.yaml` by default)."""
    target = path if path is not None else default_catalog_path()
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise CatalogError(f"cannot read the catalog: {type(exc).__name__}") from None
    return parse_catalog(data)


def _list(value: object, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise CatalogError(f"{where} must be a list")
    return value


def _mapping(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogError(f"{where} must be a mapping")
    return value

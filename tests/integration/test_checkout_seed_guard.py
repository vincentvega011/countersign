"""The test-only seeding workaround must never leave the production id-shape check weakened."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from countersign.checkout import store
from tests.checkout_seed import SHAPE_CHECK, seed_checkout
from tests.merchant_support import make_checkout

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = "CHECK ((id ~ '^chk_[A-Za-z0-9_-]{22}$'::text))"


def definition(admin: Engine) -> str:
    with admin.connect() as conn:
        found = conn.execute(
            text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :n"),
            {"n": SHAPE_CHECK},
        ).scalar()
    assert found is not None, "the id shape check is gone"
    return str(found).removesuffix(" NOT VALID")


def rejects_bad_id(app: Engine, admin: Engine) -> None:
    bad = make_checkout(checkout_id="chk_not_the_right_shape")
    with pytest.raises(IntegrityError), app.begin() as conn:
        store.insert_record(conn, _record(bad))
    assert definition(admin) == ORIGINAL


def _record(checkout):  # type: ignore[no-untyped-def]
    return store.CheckoutRecord(
        checkout=checkout, status=store.Status.READY_FOR_COMPLETE, version=1, next_line_seq=2,
        catalog_hash=bytes(32), created_us=1, updated_us=1, expires_us=2,
    )  # fmt: skip


def test_after_a_seed_the_check_has_its_original_definition_and_still_rejects(
    app_engine: Engine, admin_engine: Engine
) -> None:
    seed_checkout(app_engine, make_checkout(checkout_id="chk_seeded_unshaped_id"))
    assert definition(admin_engine) == ORIGINAL
    rejects_bad_id(app_engine, admin_engine)


def test_a_failing_insert_still_restores_the_check(
    app_engine: Engine, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object, **__: object) -> None:
        raise RuntimeError("insert failed")

    monkeypatch.setattr(store, "insert_record", boom)
    with pytest.raises(RuntimeError):
        seed_checkout(app_engine, make_checkout(checkout_id="chk_failing_unshaped_i"))
    assert definition(admin_engine) == ORIGINAL
    monkeypatch.undo()
    rejects_bad_id(app_engine, admin_engine)


def test_nothing_outside_tests_uses_the_seed_helper() -> None:
    offenders = [
        str(p.relative_to(ROOT))
        for top in ("src", "eval", "scripts", "agents", "web", "migrations")
        if (ROOT / top).exists()
        for p in (ROOT / top).rglob("*")
        if p.is_file()
        and p.suffix in {".py", ".sh", ".mjs", ".js", ".ts"}
        and "checkout_seed" in p.read_text(errors="ignore")
    ]
    assert offenders == []

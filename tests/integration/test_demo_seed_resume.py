"""The hosted demo seed as the Render database user runs it (Decision 141): not a superuser, re-runnable.

The first hosted seed stopped at `SET LOCAL session_replication_role = replica`, which only a superuser may
run, after writing 3 orders and no open mandates. These tests run the whole seed as a plain role, finish
a partial database without wiping it, and prove the report and the counts.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError

from countersign import demo_seed
from tests.integration.conftest import LedgerDb
from tests.mode_support import reset

SMALL = {"orders": 12, "shops": 1}


@pytest.fixture
def owner(ledger_db: LedgerDb, admin_engine: Engine) -> Iterator[Engine]:
    """A role like Render's database user: it can read and write every table, and is no superuser."""
    role = "cs_seed_" + secrets.token_hex(5)
    password = secrets.token_hex(12)
    with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(
            text(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS")
        )
        conn.execute(text(f'GRANT ALL ON ALL TABLES IN SCHEMA public TO "{role}"'))
        conn.execute(text(f'GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO "{role}"'))
    url = make_url(ledger_db.admin_url).set(username=role, password=password)
    engine = create_engine(url.render_as_string(hide_password=False), pool_size=4)
    try:
        yield engine
    finally:
        engine.dispose()
        with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text(f'DROP OWNED BY "{role}"'))
            conn.execute(text(f'DROP ROLE "{role}"'))


def _empty(admin: Engine) -> None:
    reset(admin)
    with admin.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE evidence_bundles, consent_records, customer_keys, key_challenges CASCADE"
            )
        )


def test_the_role_is_no_superuser_and_the_old_statement_fails_for_it(
    owner: Engine, admin_engine: Engine
) -> None:
    _empty(admin_engine)
    with owner.connect() as conn:
        query = text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        assert conn.execute(query).scalar_one() is False
    with pytest.raises(ProgrammingError, match="session_replication_role"), owner.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))


def test_the_whole_seed_passes_as_a_non_superuser(owner: Engine, admin_engine: Engine) -> None:
    _empty(admin_engine)
    done = demo_seed.seed(owner, **SMALL)
    assert done["failed_steps"] == []
    assert done["status"]["seed_complete"] is True
    assert done["open_mandates"] == 5 and done["recorded_rows"] == 2
    assert done["recorded_purchase_rows"] == 1 and done["evidence_bundle_rows"] == 1


def test_a_second_run_gives_the_same_counts(owner: Engine, admin_engine: Engine) -> None:
    _empty(admin_engine)
    first = demo_seed.seed(owner, **SMALL)
    second = demo_seed.seed(owner, **SMALL)
    assert second["status"] == first["status"]
    assert second["recorded_rows"] == 0 and second["recorded_purchase_rows"] == 0
    assert second["open_mandates"] == 0 and second["evidence_bundle_rows"] == 0
    assert second["simulated_scenarios"] == {}


def test_expected_counts_equal_the_counts_produced(owner: Engine, admin_engine: Engine) -> None:
    _empty(admin_engine)
    s = demo_seed.seed(owner, **SMALL)["status"]
    assert s["open_mandates"] == demo_seed.EXPECTED_MANDATES
    assert s["bundles"] == demo_seed.EXPECTED_BUNDLES
    assert s["recorded"] == demo_seed.RECORDED_CHECKOUTS
    assert s["simulated"] >= s["simulated_floor"]
    with admin_engine.connect() as conn:
        sources = dict(
            conn.execute(text("SELECT source, count(*) FROM checkout_sources GROUP BY 1")).all()
        )
        capture = conn.execute(
            text(
                "SELECT source FROM checkout_sources s JOIN evidence_bundles b "
                "ON b.checkout_id = s.checkout_id WHERE b.capture_id = :c"
            ),
            {"c": demo_seed.RECORDED_CAPTURE},
        ).scalar_one()
    assert capture == "recorded" and "live_sandbox" not in sources
    assert s["orders"] == sum(sources.values())


def test_a_partial_database_is_completed_not_wiped(owner: Engine, admin_engine: Engine) -> None:
    """The hosted state: the gate rows and the synthetic bundle exist, no mandates, few orders."""
    _empty(admin_engine)
    module = demo_seed._load_seed_module()
    module.seed_recorded(owner)
    module.seed_bundle(owner)
    with admin_engine.connect() as conn:
        before_ids = {r[0] for r in conn.execute(text("SELECT id FROM checkout_sessions"))}
        log_before = conn.execute(text("SELECT count(*) FROM decision_log")).scalar_one()
    assert len(before_ids) == 3 and demo_seed.status(owner)["seed_complete"] is False
    done = demo_seed.seed(owner, **SMALL)
    assert done["failed_steps"] == [] and done["status"]["seed_complete"] is True
    assert done["recorded_rows"] == 0 and done["evidence_bundle_rows"] == 0  # nothing redone
    with admin_engine.connect() as conn:
        after_ids = {r[0] for r in conn.execute(text("SELECT id FROM checkout_sessions"))}
        log_after = conn.execute(text("SELECT count(*) FROM decision_log")).scalar_one()
    assert before_ids <= after_ids and log_after >= log_before  # insert only


def test_an_injected_failure_is_reported_and_a_rerun_completes(
    owner: Engine, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    _empty(admin_engine)
    real = demo_seed._load_seed_module()

    class Broken:
        def __getattr__(self, name: str) -> Any:
            return getattr(real, name)

        @staticmethod
        def seed_mandates(engine: Engine) -> int:
            full = list(real.MANDATE_SEED)
            monkeypatch.setattr(
                real, "MANDATE_SEED", full[:2]
            )  # two are written, then the step dies
            real.seed_mandates(engine)
            monkeypatch.setattr(real, "MANDATE_SEED", full)
            raise RuntimeError("injected failure")

    monkeypatch.setattr(demo_seed, "_load_seed_module", lambda: Broken())
    failed = demo_seed.seed(owner, **SMALL)
    err = capsys.readouterr().err
    assert failed["failed_steps"] == ["open_mandates"]
    assert "step open_mandates FAILED" in err and "injected failure" in err and "Traceback" in err
    assert failed["status"]["seed_complete"] is False and failed["status"]["open_mandates"] == 2
    line = demo_seed.summary_line(failed)
    assert "complete=false" in line and "open_mandates=2/5" in line
    monkeypatch.setattr(demo_seed, "_load_seed_module", lambda: real)
    again = demo_seed.seed(owner, **SMALL)
    assert again["failed_steps"] == [] and again["status"]["seed_complete"] is True
    assert again["open_mandates"] == 3 and again["status"]["open_mandates"] == 5


def test_a_missing_privilege_is_named_in_one_line(owner: Engine, admin_engine: Engine) -> None:
    assert demo_seed.missing_privileges(owner) == []
    with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        role = owner.url.username
        conn.execute(text(f'REVOKE INSERT ON open_mandates FROM "{role}"'))
    assert demo_seed.missing_privileges(owner) == ["INSERT on open_mandates"]


def test_the_seeded_apps_have_no_rate_limiter() -> None:
    module = demo_seed._load_seed_module()
    import inspect

    assert "install_rate_limit" not in inspect.getsource(module)
    assert "RateLimiter" not in inspect.getsource(module)

"""Fill (or finish filling) the database for the hosted demo: `python -m countersign.demo_seed` (also `make demo-seed`).

What it writes, and nothing else, is what the application itself can produce. It reuses the dev seed's
functions (`scripts/dashboard_seed.py`), which drive the real composition root in process against the
PayPal simulator and write through the Merchant, the Credential Provider, the lock, the gate and the
decision log; it never inserts a checkout, a mandate chain or a bundle by hand, with labelled exceptions:
the five open mandate rows (`om_sim_*`, which need a phone consent no script can give) and two stored
bundles (one from the committed synthetic vector, one from the committed output of the recorded P3 run).
Every row carries a source label the dashboard shows:

- `simulator`: orders from apps wired to the PayPal simulator, the open mandates and the synthetic bundle;
- `recorded`: the capture gate cassette recorded from the real PayPal sandbox (one capture, one void,
  replayed once) and the recorded P3 purchase, capture 49029167TJ689282S (USD 69.00).

No row is labelled as a live sandbox capture, and no device key is seeded. The five mandates need
foreign-key parents, so they carry placeholder device and consent rows with no key material (Decision 141).

Re-runnable (Decision 141). Every item is created only when it is missing, in its own transaction, and
nothing is ever deleted or updated, so a second run finishes what a failed first run did not and a run on
a complete database adds nothing. Completeness is measured from the rows themselves (`status`), not from
"the database is empty", so a partly seeded database is completed. Each step is isolated: a failing step
prints its traceback to stderr, the other steps still run, a one-line summary says what is present against
what is expected, and the exit code is 1 when the seed is not complete (the start command logs that and
still starts the service). The seed builds its own in-process apps, which have no rate limiter (that is
installed only by the public entry point), and it needs no superuser right.

The seed refuses unless `APP_ENV` is `dev` or `demo`, so it cannot write simulated rows into a deployment
that is not the demo.

SHORTCUT: the simulated apps import `tests.*` helpers, so the seed needs the repository checkout and
the dev dependency group; the Render build uses `uv sync` with the default groups for that reason.
"""

from __future__ import annotations

import argparse
import importlib.util
import logging
import os
import sys
import time
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import structlog
from sqlalchemy import Engine, create_engine, text

from countersign.dburl import database_url

ROOT = Path(__file__).resolve().parents[2]
SEED_ENVS = ("dev", "demo")
DEFAULT_ORDERS = 40
DEFAULT_SHOPS = 3
# A healthy run of DEFAULT_ORDERS iterations leaves about that many simulator checkouts (some scenarios
# create no checkout), so "enough" is a floor a little under the request, and a smaller request needs less.
SIMULATED_FLOOR = 0.75
EXPECTED_MANDATES = 5
RECORDED_CHECKOUTS = 3  # the gate cassette's two plus the recorded purchase
RECORDED_CAPTURE = "49029167TJ689282S"
SYNTHETIC_BUNDLES = 1
EXPECTED_BUNDLES = 2


def _load_seed_module() -> ModuleType:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location(
        "dashboard_seed", ROOT / "scripts" / "dashboard_seed.py"
    )
    if spec is None or spec.loader is None:
        raise SystemExit("refused: scripts/dashboard_seed.py is not available")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _count(engine: Engine, sql: str, **params: Any) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def checkout_count(engine: Engine) -> int:
    return _count(engine, "SELECT count(*) FROM checkout_sessions")


def simulator_rows(engine: Engine) -> int:
    return _count(engine, "SELECT count(*) FROM checkout_sources WHERE source = 'simulator'")


def status(engine: Engine, *, orders: int = DEFAULT_ORDERS) -> dict[str, Any]:
    """Counts only (no value), and whether the seed is complete. Cheap: a few indexed counts.

    `orders` is every checkout the dashboard lists; `simulated` excludes the synthetic bundle's order.
    Complete means: five open mandates, both bundles (the recorded capture's among them), the three
    recorded checkouts, and enough simulated orders.
    """
    simulated = max(simulator_rows(engine) - SYNTHETIC_BUNDLES, 0)
    mandates = _count(engine, "SELECT count(*) FROM open_mandates WHERE id LIKE 'om\\_sim\\_%'")
    bundles = _count(engine, "SELECT count(*) FROM evidence_bundles")
    has_capture = _count(
        engine, "SELECT count(*) FROM evidence_bundles WHERE capture_id = :c", c=RECORDED_CAPTURE
    )
    recorded = _count(engine, "SELECT count(*) FROM checkout_sources WHERE source = 'recorded'")
    floor = int(orders * SIMULATED_FLOOR)
    complete = (
        mandates >= EXPECTED_MANDATES
        and bundles >= EXPECTED_BUNDLES
        and has_capture >= 1
        and recorded >= RECORDED_CHECKOUTS
        and simulated >= floor
    )
    return {
        "orders": checkout_count(engine), "open_mandates": mandates, "bundles": bundles,
        "recorded": recorded, "simulated": simulated, "simulated_floor": floor,
        "seed_complete": complete,
    }  # fmt: skip


def selfcheck_counts(engine: Engine) -> dict[str, Any]:
    """The four numbers `/selfcheck` shows. Never raises: a database error reports an incomplete seed."""
    try:
        s = status(engine)
    except Exception:  # noqa: BLE001 - the self-check must answer even when the database does not
        return {"orders": None, "open_mandates": None, "bundles": None, "seed_complete": False}
    return {k: s[k] for k in ("orders", "open_mandates", "bundles", "seed_complete")}


SEED_TABLES = (
    "checkout_sessions", "checkout_sources", "checkout_customers", "open_mandates",
    "open_mandate_revocations", "consent_records", "customer_keys", "key_challenges",
    "open_payment_mandates", "spend_entries", "payment_attempts", "attempt_mandates",
    "evidence_bundles", "decision_log",
)  # fmt: skip


def missing_privileges(engine: Engine) -> list[str]:
    """INSERT privileges on the seed's tables that the connected role lacks (empty means fine).

    The seed needs ordinary INSERT and SELECT only. It asks for no superuser right, no `CREATE ROLE`
    and no `session_replication_role` (Decision 141); this check names what is missing in one line
    instead of failing deep inside a step.
    """
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT t, has_table_privilege(current_user, t, 'INSERT') "
                "FROM unnest(CAST(:tables AS text[])) AS t"
            ),
            {"tables": list(SEED_TABLES)},
        ).all()
    return [f"INSERT on {t}" for t, ok in rows if not ok]


def _step(name: str, failures: list[str], created: dict[str, Any], run: Callable[[], Any]) -> None:
    try:
        created[name] = run()
    except Exception:  # noqa: BLE001 - every failure is reported with its traceback; other steps go on
        failures.append(name)
        print(f"demo seed: step {name} FAILED", file=sys.stderr, flush=True)
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()


def seed(
    engine: Engine, *, orders: int = DEFAULT_ORDERS, shops: int = DEFAULT_SHOPS
) -> dict[str, Any]:
    """Run every step, each isolated. Safe to call again: only what is missing is added.

    Returns what this call created, plus `failed_steps` (names) and `status` (the counts after).
    """
    module = _load_seed_module()
    created: dict[str, Any] = {}
    failures: list[str] = []
    _step("recorded_rows", failures, created, lambda: module.seed_recorded(engine))
    _step("recorded_purchase_rows", failures, created,
          lambda: module.seed_recorded_purchase(engine))  # fmt: skip
    _step("evidence_bundle_rows", failures, created, lambda: module.seed_bundle(engine))
    _step("open_mandates", failures, created, lambda: module.seed_mandates(engine))

    def simulated() -> dict[str, int]:
        present = max(simulator_rows(engine) - SYNTHETIC_BUNDLES, 0)
        wanted = orders - present
        if present >= int(orders * SIMULATED_FLOOR) or wanted <= 0:
            return {}
        errors: list[Exception] = []

        def note(exc: Exception) -> None:
            errors.append(exc)
            print(f"demo seed: one simulated order failed: {exc!r}", file=sys.stderr, flush=True)
            traceback.print_exception(exc, file=sys.stderr)

        done: dict[str, int] = module.seed_simulated(engine, wanted, shops, on_error=note)
        if errors:
            failures.append(f"simulated_scenarios({len(errors)} errors)")
        return done

    _step("simulated_scenarios", failures, created, simulated)
    created["failed_steps"] = failures
    created["status"] = status(engine, orders=orders)
    return created


def summary_line(created: dict[str, Any]) -> str:
    s: dict[str, Any] = created["status"]
    return (
        f"demo seed summary: complete={str(s['seed_complete']).lower()} "
        f"orders={s['orders']} simulated={s['simulated']}/{s['simulated_floor']}+ "
        f"open_mandates={s['open_mandates']}/{EXPECTED_MANDATES} "
        f"bundles={s['bundles']}/{EXPECTED_BUNDLES} "
        f"recorded={s['recorded']}/{RECORDED_CHECKOUTS} failed_steps={created['failed_steps']}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="countersign.demo_seed")
    parser.add_argument("--orders", type=int, default=DEFAULT_ORDERS)
    parser.add_argument("--shops", type=int, default=DEFAULT_SHOPS)
    parser.add_argument(
        "--if-incomplete", "--if-empty", dest="if_incomplete", action="store_true",
        help="do nothing when the seed is already complete (--if-empty is the old name, same meaning)",
    )  # fmt: skip
    args = parser.parse_args(argv)
    env = os.environ.get("APP_ENV", "dev")
    if env not in SEED_ENVS:
        raise SystemExit(
            f"refused: the demo seed runs only with APP_ENV in {SEED_ENVS}, not {env!r}"
        )
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
    started = time.monotonic()
    try:
        engine = create_engine(database_url(), pool_size=8)
        missing = missing_privileges(engine)
        if missing:
            print(
                "demo seed: FAILED, the database role lacks " + ", ".join(missing)
                + " (the seed needs plain INSERT and SELECT, never superuser)",
                file=sys.stderr, flush=True,
            )  # fmt: skip
            return 1
        before = status(engine, orders=args.orders)
        print(f"demo seed: before {before}", flush=True)
        if args.if_incomplete and before["seed_complete"]:
            print("demo seed: already complete, nothing to do", flush=True)
            return 0
        created = seed(engine, orders=args.orders, shops=args.shops)
    except Exception:  # noqa: BLE001 - e.g. the database is unreachable: loud, and a non-zero exit
        print("demo seed: FAILED before any step", file=sys.stderr, flush=True)
        traceback.print_exc(file=sys.stderr)
        return 1
    for name, value in created.items():
        if name not in ("status", "failed_steps"):
            print(f"{name}: {value}", flush=True)
    print(summary_line(created), flush=True)
    print(f"took {time.monotonic() - started:.1f}s", flush=True)
    return 0 if created["status"]["seed_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

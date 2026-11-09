"""Fill an EMPTY database for the hosted demo: `python -m countersign.demo_seed` (also `make demo-seed`).

What it writes, and nothing else, is what the application itself can produce. It reuses the dev seed's
functions (`scripts/dashboard_seed.py`), which drive the real composition root over HTTP against the
PayPal simulator and write through the Merchant, the Credential Provider, the lock, the gate and the
decision log; it never inserts a checkout, a mandate chain or a bundle by hand, with one labelled
exception: the five open mandate rows, written with fixed ids (`om_sim_*`), which need a phone consent
that no script can give. Every row carries a source label the dashboard shows:

- `simulator`: orders from apps wired to the PayPal simulator, the open mandates (`om_sim_` prefix) and
  one order with a stored evidence bundle made from the committed synthetic vector;
- `recorded`: the capture gate cassette recorded from the real PayPal sandbox (capture
  49029167TJ689282S and one void), replayed once.

No row is labelled as a live sandbox capture, and no device key is seeded: a device key belongs to a
phone and is bound to its origin, so a seeded one would be a fabrication. Customers appear in the
orders and mandates only.

Idempotent. The recorded rows, the evidence bundle and each open mandate are added once. The simulated
orders are added only when the database holds no more than a few simulator rows, so a second run adds
nothing. `--if-empty` (used by the start command) does nothing at all when any checkout exists. The
seed refuses unless `APP_ENV` is `dev` or `demo`, and never runs against another environment, so it
cannot write simulated rows into a deployment that is not the demo.

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
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

import structlog
from sqlalchemy import Engine, create_engine, text

from countersign.dburl import database_url

ROOT = Path(__file__).resolve().parents[2]
SEED_ENVS = ("dev", "demo")
SIMULATED_THRESHOLD = 5  # simulator rows already present (the bundle row is one) that mean "seeded"
DEFAULT_ORDERS = 40
DEFAULT_SHOPS = 3


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


def checkout_count(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT count(*) FROM checkout_sessions")).scalar_one())


def simulator_rows(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT count(*) FROM checkout_sources WHERE source = 'simulator'")
            ).scalar_one()
        )


def seed(
    engine: Engine, *, orders: int = DEFAULT_ORDERS, shops: int = DEFAULT_SHOPS
) -> dict[str, object]:
    """Run every step. Safe to call twice: the second call adds nothing."""
    module = _load_seed_module()
    added: dict[str, object] = {}
    added["recorded_rows"] = module.seed_recorded(engine)
    added["evidence_bundle_rows"] = module.seed_bundle(engine)
    added["open_mandates"] = module.seed_mandates(engine)
    if simulator_rows(engine) > SIMULATED_THRESHOLD:
        added["simulated_scenarios"] = {}
    else:
        added["simulated_scenarios"] = module.seed_simulated(engine, orders, shops)
    return added


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="countersign.demo_seed")
    parser.add_argument("--orders", type=int, default=DEFAULT_ORDERS)
    parser.add_argument("--shops", type=int, default=DEFAULT_SHOPS)
    parser.add_argument(
        "--if-empty", action="store_true", help="do nothing unless the database has no checkout"
    )
    args = parser.parse_args(argv)
    env = os.environ.get("APP_ENV", "dev")
    if env not in SEED_ENVS:
        raise SystemExit(
            f"refused: the demo seed runs only with APP_ENV in {SEED_ENVS}, not {env!r}"
        )
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
    engine = create_engine(database_url(), pool_size=8)
    if args.if_empty and checkout_count(engine) > 0:
        print("demo seed: the database already has data, nothing to do")
        return 0
    started = time.monotonic()
    added = seed(engine, orders=args.orders, shops=args.shops)
    for name, value in added.items():
        print(f"{name}: {value}")
    print(f"took {time.monotonic() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

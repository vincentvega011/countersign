"""Fill a DEV database with varied agent orders for the merchant dashboard (docs/PROTOCOL.md Decision 116).

Every row is made by the real application over HTTP (the composition root, the Merchant, the Credential
Provider, the lock, the gate and the decision log), never by writing rows directly:

- **simulated** rows come from apps wired to the PayPal simulator (`tests/paypal_sim.py`) and are
  labelled `simulator` when they are created: completed purchases, refused mandates (wrong amount,
  expired, forged), lock denials, purchases left waiting for payer approval, ACP sessions refused for a
  locked principal, open checkouts, and a few gate voids from an app with the pre-authorize check off
  (an evaluation ablation, refused in demo);
- **recorded** rows replay the capture gate cassette recorded from the real PayPal sandbox
  (`tests/cassettes/gate_flow.json`): one real recorded capture and one recorded void, labelled
  `recorded`. They are added once per database.

Nothing simulated is labelled as a sandbox capture. Refuses to run unless `APP_ENV=dev` and the
database is on this machine.

    APP_ENV=dev uv run python scripts/dashboard_seed.py --orders 300
"""

from __future__ import annotations

import argparse
import os
import random
import secrets
import sys
import time
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from countersign.ablations import Ablations
from countersign.canonical import sd_hash
from countersign.catalog.catalog import load_catalog
from countersign.checkout.binding import label_source
from countersign.checkout.store import checkout_sessions
from countersign.composition import Wiring, build_app
from countersign.merchant.authorization import checkout_jwt
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.paypal.client import PayPalClient
from countersign.paypal.config import PayPalConfig
from countersign.protocols.ucp.profile import AP2_CAPABILITY
from countersign.runtime import Mode, RuntimeSettings

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
CATALOG = load_catalog()


def _guard(url: str) -> None:
    if os.environ.get("APP_ENV") != "dev":
        raise SystemExit("refused: set APP_ENV=dev (the seed writes simulated rows)")
    host = make_url(url).host or ""
    if host not in LOCAL_HOSTS:
        raise SystemExit(f"refused: the database is not on this machine ({host!r})")


def _world(engine: Engine, *, ablations: Ablations | None = None) -> Any:
    from fastapi.testclient import TestClient

    from tests import paypal_sim
    from tests.mandate_issuer import NOW, Keys
    from tests.mode_support import BASE, MERCHANT
    from tests.paypal_sim import PayPalSim

    keys, sim = Keys(), PayPalSim()
    paypal = PayPalClient(
        PayPalConfig(client_id="sim", client_secret="sim-secret"),
        transport=sim.transport(), sleep=lambda _: None, now=lambda: paypal_sim.NOW,
    )  # fmt: skip
    settings = RuntimeSettings(Mode.FULL, "dev", ablations or Ablations())
    app = build_app(
        settings,
        Wiring(
            engine=engine, merchant_key=validate_jwk(generate_jwk()), platform_key=keys.issuer,
            paypal=paypal, public_base_url=BASE,
            payee={"id": MERCHANT["id"], "name": MERCHANT["name"]},
            paypal_payee_merchant_id=paypal_sim.MERCHANT, merchant_constraint_id=MERCHANT["id"],
            issuer="https://merchant.example", clock=lambda: float(NOW),
            clock_us=lambda: time.time_ns() // 1000, paypal_now=lambda: paypal_sim.NOW,
            data_source="simulator",
        ),
    )  # fmt: skip
    return TestClient(app, raise_server_exceptions=False), sim, keys


class Shop:
    """One simulated app with its own platform and agent keys."""

    def __init__(self, engine: Engine, *, ablations: Ablations | None = None) -> None:
        self.client, self.sim, self.keys = _world(engine, ablations=ablations)
        self.rng = random.Random(secrets.randbits(32))

    def create(self, item: Any, quantity: int, **headers: str) -> dict[str, Any] | None:
        from tests.mode_support import UCP_AGENT, UCP_ROOT

        r = self.client.post(
            UCP_ROOT,
            json={"line_items": [{"item": {"id": item.id}, "quantity": quantity}]},
            headers={**UCP_AGENT, **headers},
        )
        return r.json() if r.status_code == 201 else None

    def mandates(self, body: dict[str, Any], item: Any, quantity: int, *, customer: str,
                 agent: int, amount: int | None = None, open_exp: int | None = None,
                 forged: bool = False) -> tuple[str, str]:  # fmt: skip
        from joserfc.jwk import ECKey

        from tests.constraint_fixtures import (
            checkout_constraints,
            closed_payment_values,
            line_items_constraint,
            payment_constraints,
        )
        from tests.mandate_issuer import issue, public_jwk
        from tests.mode_support import total_of

        jwt = checkout_jwt(body)
        total = total_of(body)
        nonce = secrets.token_urlsafe(9)
        cnf = {"jwk": public_jwk(self.keys.agents[agent])}

        def edit_open(content: dict[str, Any]) -> None:
            content["constraints"] = [
                line_items_constraint(item.id, quantity, item.title), checkout_constraints()[1],
            ]  # fmt: skip

        def edit_payload(payload: dict[str, Any]) -> None:
            payload["sub"] = customer

        extra: dict[str, Any] = {} if open_exp is None else {"open_exp": open_exp}
        signer = {"issuer_signer": ECKey.generate_key("P-256")} if forged else {}
        cm = issue("checkout", keys=self.keys, checkout_jwt_value=jwt, nonce="nc-" + nonce,
                   edit_open_content=edit_open, edit_open_payload=edit_payload, cnf=cnf,
                   kb_signer=self.keys.agents[agent], **extra, **signer)  # fmt: skip
        digest = sd_hash(cm.open_token)

        def edit_payment(content: dict[str, Any]) -> None:
            content["constraints"] = payment_constraints(digest, 1_000_000)

        def edit_closed(content: dict[str, Any]) -> None:
            content.update(closed_payment_values(amount if amount is not None else total, "USD"))

        pm = issue("payment", keys=self.keys, audience="credential-provider",
                   checkout_jwt_value=jwt, nonce="np-" + nonce, edit_open_content=edit_payment,
                   edit_kb_content=edit_closed, edit_open_payload=edit_payload, cnf=cnf,
                   kb_signer=self.keys.agents[agent], **extra)  # fmt: skip
        return cm.token, pm.token

    def complete(self, checkout_id: str, cm: str | None, pm: str | None, **headers: str) -> Any:
        from tests.mode_support import UCP_AGENT, complete_body, ucp_complete

        if headers:
            from tests.mode_support import UCP_ROOT

            return self.client.post(
                f"{UCP_ROOT}/{checkout_id}/complete", json=complete_body(cm, pm),
                headers={**UCP_AGENT, **headers},
            )  # fmt: skip
        return ucp_complete(_W(self), checkout_id, complete_body(cm, pm))

    def approve_all(self) -> None:
        for order_id, order in list(self.sim.orders.items()):
            if order["status"] != "APPROVED" and not any(
                a["order"] == order_id for a in self.sim.authorizations.values()
            ):
                self.sim.approve(order_id)


class _W:
    def __init__(self, shop: Shop) -> None:
        self.client = shop.client


def _delegation(shop: Shop, customer: str, agent: int) -> str:
    from tests.mandate_issuer import issue, public_jwk

    return issue(
        "checkout", keys=shop.keys, cnf={"jwk": public_jwk(shop.keys.agents[agent])}, sub=customer
    ).open_token


SCENARIOS = [
    ("completed", 52), ("wrong_amount", 9), ("expired", 5), ("forged", 4), ("lock_denied", 6),
    ("awaiting_payer", 6), ("acp_refused", 5), ("open", 7), ("customer_mismatch", 3), ("voided", 3),
]  # fmt: skip


def seed_simulated(engine: Engine, count: int, shops: int) -> dict[str, int]:
    from tests.mandate_issuer import NOW
    from tests.mode_support import acp_create, acp_headers, acp_post

    worlds = [Shop(engine) for _ in range(shops)]
    ablated = Shop(engine, ablations=Ablations(no_preauth_check=True))
    customers = ["cus_" + secrets.token_urlsafe(16) for _ in range(40)]
    names = [n for n, _ in SCENARIOS]
    weights = [w for _, w in SCENARIOS]
    rng = random.Random(7)
    done: dict[str, int] = {}
    for _ in range(count):
        scenario = rng.choices(names, weights)[0]
        shop = ablated if scenario == "voided" else rng.choice(worlds)
        item = rng.choice(CATALOG.items)
        quantity = 1
        customer = rng.choice(customers)
        agent = rng.randrange(len(shop.keys.agents))
        token = _delegation(shop, customer, agent)
        named = {"Countersign-Delegation": token, "Countersign-Capabilities": AP2_CAPABILITY}
        if scenario == "acp_refused":
            acp_create(_W(shop), token, capability=True)  # type: ignore[arg-type]
            session = acp_create(_W(shop), token, capability=False)  # type: ignore[arg-type]
            if session.status_code == 201:
                sid = session.json()["id"]
                acp_post(_W(shop), f"/checkout_sessions/{sid}/complete",  # type: ignore[arg-type]
                         {"payment_data": {"token": "x", "provider": "stripe"}},
                         acp_headers(token))  # fmt: skip
            done[scenario] = done.get(scenario, 0) + 1
            continue
        body = shop.create(item, quantity, **named)
        if body is None:
            continue
        cid = body["id"]
        if scenario == "open":
            pass
        elif scenario == "lock_denied":
            shop.complete(cid, None, None, **{"Countersign-Delegation": token})
        else:
            kw: dict[str, Any] = {"customer": customer, "agent": agent}
            if scenario == "wrong_amount":
                kw["amount"] = int(body["totals"][-1]["amount"]) + rng.choice([100, 2500])
            elif scenario == "expired":
                kw["open_exp"] = NOW - 60
            elif scenario == "forged":
                kw["forged"] = True
            elif scenario == "customer_mismatch":
                kw["customer"] = rng.choice([c for c in customers if c != customer])
            cm, pm = shop.mandates(body, item, quantity, **kw)
            first = shop.complete(cid, cm, pm)
            needs_payer = "payer_approval_required" in [
                m["code"] for m in first.json().get("messages", [])
            ]
            if needs_payer and scenario != "awaiting_payer":
                if scenario == "voided":
                    order_id = next(
                        o for o, v in shop.sim.orders.items() if v["status"] != "APPROVED"
                        and not any(a["order"] == o for a in shop.sim.authorizations.values())
                    )  # fmt: skip
                    shop.sim.approve(order_id)
                    raised = int(body["totals"][-1]["amount"]) * 3
                    shop.sim.patch(order_id, amount=f"{raised // 100}.{raised % 100:02d}")
                else:
                    shop.approve_all()
                shop.complete(cid, None, None)
        done[scenario] = done.get(scenario, 0) + 1
    return done


def seed_recorded(engine: Engine) -> int:
    """Replay the gate cassette recorded from the real sandbox, once per database."""
    import json as _json

    from countersign.paypal.cassette import load_cassette
    from tests.gate_flow import GateFixtures
    from tests.integration.test_gate_cassette_replay import CASSETTE, FIXTURE, replay

    if not CASSETTE.exists() or not FIXTURE.exists():
        return 0
    fixtures = GateFixtures.from_json(FIXTURE.read_text(encoding="utf-8"))
    ids = [fixtures.clean.checkout_id, fixtures.changed.checkout_id]
    with engine.connect() as conn:
        present = conn.execute(
            select(checkout_sessions.c.id).where(checkout_sessions.c.id.in_(ids))
        ).all()
    if present:
        return 0
    replay(load_cassette(CASSETTE), engine, fixtures)
    with engine.begin() as conn:
        for cid in ids:
            label_source(conn, cid, "recorded", time.time_ns() // 1000)
    _ = _json
    return len(ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dashboard_seed")
    parser.add_argument("--orders", type=int, default=300)
    parser.add_argument(
        "--shops", type=int, default=4, help="simulated apps, each with its own keys"
    )
    args = parser.parse_args(argv)
    url = os.environ.get(
        "DATABASE_URL", "postgresql+psycopg://countersign:countersign@localhost:5432/countersign"
    )
    _guard(url)
    import logging

    import structlog

    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))
    engine = create_engine(url, pool_size=8)
    started = time.monotonic()
    recorded = seed_recorded(engine)
    done = seed_simulated(engine, args.orders, args.shops)
    print(f"recorded rows added: {recorded}")
    print("simulated scenarios:", ", ".join(f"{k} {v}" for k, v in sorted(done.items())))
    print(f"took {time.monotonic() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

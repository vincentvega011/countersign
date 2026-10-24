"""Parallel operations on checkouts leave one consistent state and a verifying log."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from sqlalchemy import Engine

from countersign.canonical.models import Checkout
from countersign.catalog.catalog import load_catalog
from countersign.ledger import store as ledger
from countersign.merchant.policy import policy_hash
from countersign.protocols.ucp import store
from countersign.protocols.ucp.checkout_state import Status
from countersign.protocols.ucp.requests import CheckoutRequest, LineRequest
from countersign.protocols.ucp.service import Result, UcpService

CATALOG = load_catalog()
ITEM_A, ITEM_B = CATALOG.items[0], CATALOG.items[1]
N = 20


@pytest.fixture
def service(app_engine: Engine, clean_checkouts: None) -> UcpService:
    return UcpService(app_engine, CATALOG, policy_hash=policy_hash())


def req(item: Any, qty: int, line_id: str | None = "li_1") -> CheckoutRequest:
    return CheckoutRequest(lines=(LineRequest(item.id, qty, line_id, None),))


def run_parallel(calls: list[Any]) -> list[Any]:
    barrier = threading.Barrier(len(calls))

    def go(call: Any) -> Any:
        barrier.wait()
        return call()

    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        return list(pool.map(go, calls))


def log_of(engine: Engine, cid: str) -> list[Any]:
    with engine.connect() as conn:
        return ledger.entries_for_checkout(conn, cid)


def final_record(engine: Engine, cid: str) -> store.CheckoutRecord:
    with engine.connect() as conn:
        record = store.load(conn, cid)
    assert record is not None
    return record


def test_parallel_updates_leave_one_consistent_state(
    service: UcpService, app_engine: Engine
) -> None:
    cid = service.create(req(ITEM_A, 1, None)).record.id  # type: ignore[union-attr]
    results: list[Result] = run_parallel(
        [lambda q=q: service.update(cid, req(ITEM_B, q)) for q in range(1, N + 1)]
    )
    assert all(r.http_status == 200 and not r.messages for r in results)

    record = final_record(app_engine, cid)
    assert record.version == 1 + N  # every update was applied exactly once, in some order
    (line,) = record.checkout.line_items
    assert line.item.id == ITEM_B.id and 1 <= line.quantity <= N
    # The stored checkout is internally consistent and priced from the catalog.
    rebuilt = Checkout.from_lines(cid, "USD", [("li_1", ITEM_B.to_item(), line.quantity)])
    assert record.checkout.terms() == rebuilt.terms()

    entries = log_of(app_engine, cid)
    assert [e.kind for e in entries] == ["checkout.created"] + ["checkout.updated"] * N
    versions = [json.loads(e.payload)["version"] for e in entries]
    assert versions == list(range(1, N + 2))  # log order matches state order
    # The last logged update is the state the row holds.
    last = json.loads(entries[-1].payload)
    assert last["terms_hash"] == record.checkout.terms_hash().hex()
    with app_engine.connect() as conn:
        assert ledger.verify_log(conn).ok


def test_updates_racing_a_cancel_never_apply_after_it(
    service: UcpService, app_engine: Engine
) -> None:
    cid = service.create(req(ITEM_A, 1, None)).record.id  # type: ignore[union-attr]
    calls: list[Any] = [lambda q=q: service.update(cid, req(ITEM_B, q)) for q in range(1, 11)]
    calls.append(lambda: service.cancel(cid))
    run_parallel(calls)

    record = final_record(app_engine, cid)
    assert record.status is Status.CANCELED
    kinds = [e.kind for e in log_of(app_engine, cid)]
    assert kinds.count("checkout.canceled") == 1
    after = kinds[kinds.index("checkout.canceled") + 1 :]
    assert set(after) <= {"checkout.update_rejected"}
    assert "checkout.updated" not in after
    # Whatever the last applied update was, the canceled row holds exactly that state.
    last_update = [e for e in log_of(app_engine, cid) if e.kind == "checkout.updated"]
    if last_update:
        stored_hash = json.loads(last_update[-1].payload)["terms_hash"]
        assert stored_hash == record.checkout.terms_hash().hex()


def test_two_cancels_race_and_exactly_one_wins(service: UcpService, app_engine: Engine) -> None:
    cid = service.create(req(ITEM_A, 1, None)).record.id  # type: ignore[union-attr]
    results = run_parallel([lambda: service.cancel(cid) for _ in range(8)])
    winners = [r for r in results if not r.messages]
    losers = [r for r in results if r.messages]
    assert len(winners) == 1 and len(losers) == 7
    assert all(r.messages[0]["code"] == "checkout_not_cancelable" for r in losers)
    kinds = [e.kind for e in log_of(app_engine, cid)]
    assert kinds.count("checkout.canceled") == 1 and kinds.count("checkout.cancel_rejected") == 7


def test_parallel_completes_never_succeed_and_change_nothing(
    service: UcpService, app_engine: Engine
) -> None:
    cid = service.create(req(ITEM_A, 1, None)).record.id  # type: ignore[union-attr]
    results = run_parallel([lambda: service.complete(cid) for _ in range(N)])
    assert all(r.messages[0]["code"] == "mandate_required" for r in results)
    record = final_record(app_engine, cid)
    assert record.status is Status.READY_FOR_COMPLETE and record.version == 1


def test_parallel_creates_are_independent_and_the_log_stays_one_chain(
    service: UcpService, app_engine: Engine
) -> None:
    results = run_parallel([lambda: service.create(req(ITEM_A, 1, None)) for _ in range(N)])
    ids = {r.record.id for r in results if r.record}
    assert len(ids) == N
    with app_engine.connect() as conn:
        verdict = ledger.verify_log(conn)
        entries = ledger.read_entries(conn)
    assert verdict.ok and verdict.checked == N
    assert [e.seq for e in entries] == list(range(1, N + 1))


def test_updates_to_different_checkouts_do_not_interfere(
    service: UcpService, app_engine: Engine
) -> None:
    ids = [service.create(req(ITEM_A, 1, None)).record.id for _ in range(5)]  # type: ignore[union-attr]
    calls = [lambda c=c, q=q: service.update(c, req(ITEM_B, q)) for c in ids for q in (2, 3)]
    run_parallel(calls)
    for cid in ids:
        record = final_record(app_engine, cid)
        assert record.version == 3
        assert record.checkout.line_items[0].quantity in (2, 3)


class FixedClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


T0 = 1_800_000_000_000_000
TTL = 6 * 3600 * 1_000_000


def test_expiry_boundary_is_inclusive(app_engine: Engine, clean_checkouts: None) -> None:
    clock = FixedClock(T0)
    svc = UcpService(app_engine, CATALOG, policy_hash=policy_hash(), clock_us=clock)
    cid = svc.create(req(ITEM_A, 1, None)).record.id  # type: ignore[union-attr]
    clock.value = T0 + TTL - 1
    assert svc.get(cid).record.status is Status.READY_FOR_COMPLETE  # type: ignore[union-attr]
    clock.value = T0 + TTL
    assert svc.get(cid).record.status is Status.CANCELED  # type: ignore[union-attr]
    other = svc.create(req(ITEM_A, 1, None)).record.id  # type: ignore[union-attr]
    clock.value = T0 + 2 * TTL
    # The same boundary through a mutating operation.
    assert svc.cancel(other).messages[0]["code"] == "checkout_not_cancelable"


def test_readers_racing_an_expiry_expire_it_once(app_engine: Engine, clean_checkouts: None) -> None:
    clock = FixedClock(T0)
    svc = UcpService(app_engine, CATALOG, policy_hash=policy_hash(), clock_us=clock)
    cid = svc.create(req(ITEM_A, 1, None)).record.id  # type: ignore[union-attr]
    clock.value = T0 + TTL + 1
    results = run_parallel([lambda: svc.get(cid) for _ in range(N)])
    assert all(r.http_status == 200 and r.record.status is Status.CANCELED for r in results)  # type: ignore[union-attr]
    assert [e.kind for e in log_of(app_engine, cid)] == ["checkout.created", "checkout.expired"]
    with app_engine.connect() as conn:
        assert ledger.verify_log(conn).ok


def test_a_malformed_id_never_reaches_the_database(
    service: UcpService, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real = store.load

    def spy(conn: Any, checkout_id: str, **kw: Any) -> Any:
        calls.append(checkout_id)
        return real(conn, checkout_id, **kw)

    monkeypatch.setattr(store, "load", spy)
    for bad in ("x", "chk_short", "chk_" + "A" * 23, "chk_" + "A" * 22 + "\n", "' OR 1=1 --"):
        assert service.get(bad).messages[0]["code"] == "not_found"
        assert service.cancel(bad).messages[0]["code"] == "not_found"
    assert calls == []

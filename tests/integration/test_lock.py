"""The principal lock on the real Postgres: recording, inheritance, policy, failure, permissions.

Nothing about the lock is mocked. The delegations are real open mandates signed by the platform key.
The only test doubles are a second protocol entry point that calls the same shared function (the real
ACP adapter arrives in P2.7) and injected failures of the store and the log.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.exc import ProgrammingError

from countersign.ablations import AblationRefused, Ablations
from countersign.canonical.money import Money
from countersign.ledger import store as ledger_store
from countersign.ledger.store import entries_for_checkout, verify_log
from countersign.lock import LockStoreError, MerchantPolicy, Principal
from countersign.lock.store import LockStore
from countersign.tables import lock_events, lock_policies
from tests.lock_support import (
    delegation,
    make_lock,
    principal,
    request,
    second_protocol_entry,
)
from tests.mandate_issuer import Keys


@pytest.fixture
def keys() -> Keys:
    return Keys()


@pytest.fixture
def engine(app_engine: Engine, clean_payments: None) -> Engine:
    return app_engine


def events(engine: Engine) -> list[Any]:
    with engine.connect() as conn:
        return list(conn.execute(select(lock_events).order_by(lock_events.c.seq)).all())


def log_kinds(engine: Engine, checkout_id: str = "chk_lock_test_000000000") -> list[str]:
    with engine.connect() as conn:
        return [e.kind for e in entries_for_checkout(conn, checkout_id)]


# ---------------------------------------------------------------------- recording and denial


def test_negotiation_records_the_lock_once_and_logs_it(engine: Engine, keys: Keys) -> None:
    lock = make_lock(engine, keys)
    who = lock.principal_from_delegation(delegation(keys))
    assert who == principal(keys)
    first = lock.decide(request("create", who, negotiated=True))
    again = lock.decide(request("create", who, negotiated=True))
    assert first.allowed and again.allowed and first.reason == "allowed:ap2_negotiated"
    (event,) = events(engine)
    assert (event.kind, event.customer_id) == ("lock", "cust-1")
    assert event.agent_thumbprint == keys.agents[0].thumbprint()
    kinds = log_kinds(engine)
    assert kinds.count("lock.recorded") == 1 and kinds.count("lock.decision") == 2
    with engine.connect() as conn:
        assert verify_log(conn).ok


def test_a_locked_principal_without_a_mandate_is_denied_on_complete(
    engine: Engine, keys: Keys
) -> None:
    lock = make_lock(engine, keys)
    who = principal(keys)
    lock.decide(request("create", who, negotiated=True))
    verdict = lock.decide(request("complete", who, mandate=False))
    assert not verdict.allowed and verdict.reason == "denied:mandate_required"
    assert verdict.ucp_code == "mandate_required" and verdict.locked and verdict.required
    ok = lock.decide(request("complete", who, mandate=True))
    assert ok.allowed and ok.reason == "allowed:mandate_valid"


def test_a_second_protocol_entry_point_gets_the_same_answer_from_the_same_function(
    engine: Engine, keys: Keys
) -> None:
    lock = make_lock(engine, keys)
    who = principal(keys)
    lock.decide(request("create", who, negotiated=True))  # negotiated over "UCP"
    # Another protocol adapter builds its own Principal and calls the shared function: no mandate,
    # so it is denied exactly like the UCP path. (The real ACP adapter exercises this in P2.7.)
    assert second_protocol_entry(lock, Principal("cust-1", keys.agents[0].thumbprint())) is False
    assert second_protocol_entry(lock, who, mandate=True) is True


def test_a_fresh_session_without_the_capability_is_denied_for_the_same_principal(
    engine: Engine, keys: Keys
) -> None:
    lock = make_lock(engine, keys)
    who = principal(keys)
    session_one = lock.decide(request("create", who, negotiated=True, checkout_id="chk_one"))
    session_two = lock.decide(request("create", who, negotiated=False, checkout_id="chk_two"))
    assert session_one.allowed
    assert not session_two.allowed and session_two.reason == "denied:ap2_negotiation_required"
    # A later update of the second session is denied the same way, and a new checkout id changes nothing.
    assert not lock.decide(request("update", who, checkout_id="chk_two")).allowed
    assert not lock.decide(request("create", who, checkout_id="chk_three")).allowed


def test_a_different_agent_or_customer_is_not_locked_unless_policy_locks_everyone(
    engine: Engine, keys: Keys
) -> None:
    lock = make_lock(engine, keys)
    lock.decide(request("create", principal(keys), negotiated=True))
    other_agent = principal(keys, agent=1)
    other_customer = principal(keys, sub="cust-2")
    for who in (other_agent, other_customer, None):
        assert lock.decide(request("create", who)).allowed
        assert lock.decide(request("complete", who)).reason == "allowed:not_required"
    lock.set_policy("all", reason="require AP2 for every agent")
    for who in (other_agent, other_customer, None):
        assert not lock.decide(request("create", who)).allowed
        assert lock.decide(request("complete", who, mandate=True)).allowed is (who is not None)


def test_an_unknown_customer_fails_closed_under_require_all(engine: Engine, keys: Keys) -> None:
    lock = make_lock(engine, keys)
    lock.set_policy("all", reason="strict")
    nameless = principal(keys, sub=None)
    assert nameless.customer_id is None
    verdict = lock.decide(request("complete", nameless, mandate=True))
    assert not verdict.allowed and verdict.reason == "denied:customer_unknown"
    assert lock.decide(request("complete", principal(keys), mandate=True)).allowed


def test_an_unknown_customer_matches_a_lock_by_its_agent_key_and_is_not_unlocked(
    engine: Engine, keys: Keys
) -> None:
    lock = make_lock(engine, keys)
    lock.decide(request("create", principal(keys), negotiated=True))  # (cust-1, agent 0) locked
    nameless = principal(keys, sub=None)
    # Locked through its agent key; the lock names a customer, so an unknown one cannot be shown to match.
    verdict = lock.decide(request("complete", nameless, mandate=True))
    assert not verdict.allowed and verdict.locked and verdict.reason == "denied:customer_unknown"
    assert lock.decide(request("complete", nameless, mandate=False)).locked


# ----------------------------------------------------------------------------- merchant policy


def test_policy_versions_are_hashed_logged_and_never_edited(engine: Engine, keys: Keys) -> None:
    lock = make_lock(engine, keys)
    one = lock.set_policy("all", reason="launch")
    two = lock.set_policy("over_threshold", threshold_minor=5000, currency="USD", reason="relax")
    assert (one.version, two.version) == (1, 2) and one.hash() != two.hash()
    assert LockStore(engine, lambda: 1).current_policy() == two
    with engine.connect() as conn:
        rows = conn.execute(select(lock_policies).order_by(lock_policies.c.version)).all()
        assert verify_log(conn).ok
    assert [r.policy_hash for r in rows] == [one.hash(), two.hash()]
    with engine.connect() as conn:
        changed = [
            e
            for e in ledger_store.entries_for_checkout(conn, None)
            if e.kind == "lock.policy_changed"
        ]
    assert len(changed) == 2


@pytest.mark.parametrize(
    "amount,required",
    [(4999, False), (5000, False), (5001, True)],
)
def test_the_threshold_is_strictly_above_in_integer_minor_units(
    engine: Engine, keys: Keys, amount: int, required: bool
) -> None:
    lock = make_lock(engine, keys)
    lock.set_policy("over_threshold", threshold_minor=5000, currency="USD", reason="test")
    who = principal(keys)
    verdict = lock.decide(request("complete", who, amount=Money("USD", amount)))
    assert verdict.required is required and verdict.allowed is (not required)


def test_a_total_that_cannot_be_compared_counts_as_over_the_threshold(
    engine: Engine, keys: Keys
) -> None:
    lock = make_lock(engine, keys)
    lock.set_policy("over_threshold", threshold_minor=5000, currency="USD", reason="test")
    assert lock.decide(request("complete", principal(keys), amount=Money("EUR", 100))).required
    assert lock.decide(request("complete", principal(keys), amount=None)).required


def test_a_policy_row_that_does_not_match_its_hash_denies(
    engine: Engine, keys: Keys, admin_engine: Engine
) -> None:
    lock = make_lock(engine, keys)
    lock.set_policy("all", reason="strict")
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE lock_policies SET mode = 'off' WHERE version = 1"))
    verdict = lock.decide(request("complete", principal(keys), mandate=True))
    assert not verdict.allowed and verdict.reason == "denied:lock_store_unreadable"


def test_unlock_is_a_logged_merchant_action_with_a_new_policy_version(
    engine: Engine, keys: Keys
) -> None:
    lock = make_lock(engine, keys)
    who = principal(keys)
    lock.decide(request("create", who, negotiated=True))
    assert not lock.decide(request("complete", who)).allowed
    assert lock.unlock(who, reason="customer asked") is True
    assert lock.unlock(who, reason="again") is False  # nothing left to remove
    assert lock.decide(request("complete", who)).allowed
    lock.decide(request("create", who, negotiated=True))  # negotiating again locks again
    assert not lock.decide(request("complete", who)).allowed
    assert [e.kind for e in events(engine)] == ["lock", "unlock", "lock"]
    with engine.connect() as conn:
        assert verify_log(conn).ok
    # Every unlock, successful or not, made a new policy version.
    assert LockStore(engine, lambda: 1).current_policy().version == 2


# ------------------------------------------------------------------- persistence and permissions


def test_twenty_parallel_negotiations_record_one_lock(engine: Engine, keys: Keys) -> None:
    lock = make_lock(engine, keys)
    who = principal(keys)
    barrier = threading.Barrier(20)

    def negotiate(n: int) -> bool:
        barrier.wait()
        return lock.decide(request("create", who, negotiated=True, checkout_id=f"chk_p{n}")).allowed

    with ThreadPoolExecutor(20) as pool:
        results = list(pool.map(negotiate, range(20)))
    assert all(results)
    assert len(events(engine)) == 1
    with engine.connect() as conn:
        assert verify_log(conn).ok


def test_the_lock_survives_a_restart(engine: Engine, keys: Keys, ledger_db: Any) -> None:
    lock = make_lock(engine, keys)
    who = principal(keys)
    lock.decide(request("create", who, negotiated=True))
    fresh_engine = create_engine(ledger_db.app_url)  # a new process: new engine, new lock object
    try:
        restarted = make_lock(fresh_engine, keys)
        assert not restarted.decide(request("complete", who)).allowed
        assert restarted.decide(request("complete", who, mandate=True)).allowed
    finally:
        fresh_engine.dispose()


@pytest.mark.parametrize("table", ["lock_events", "lock_policies"])
def test_the_runtime_role_cannot_update_or_delete_a_lock_or_a_policy(
    engine: Engine, keys: Keys, table: str
) -> None:
    lock = make_lock(engine, keys)
    lock.decide(request("create", principal(keys), negotiated=True))
    lock.set_policy("all", reason="x")
    for statement in (
        f"UPDATE {table} SET {'kind' if table == 'lock_events' else 'mode'} = 'x'",
        f"DELETE FROM {table}",
        f"TRUNCATE {table}",
    ):
        with pytest.raises(ProgrammingError), engine.begin() as conn:
            conn.execute(text(statement))
    assert len(events(engine)) == 1


# ----------------------------------------------------------------------------- failure is a denial


def test_a_lock_store_failure_denies(
    engine: Engine, keys: Keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = make_lock(engine, keys)
    who = principal(keys)

    def broken(self: LockStore, *args: Any, **kwargs: Any) -> Any:
        raise LockStoreError("down")

    monkeypatch.setattr(LockStore, "lock_state", broken)
    verdict = lock.decide(request("complete", who, mandate=True))
    assert not verdict.allowed and verdict.reason == "denied:lock_store_unreadable"
    monkeypatch.undo()
    monkeypatch.setattr(LockStore, "current_policy", broken)
    assert not lock.decide(request("create", None)).allowed


def test_a_log_failure_denies_even_a_request_that_would_pass(
    engine: Engine, keys: Keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = make_lock(engine, keys)
    real = ledger_store.append

    def broken(conn: Any, **kw: Any) -> Any:
        if kw["kind"] == "lock.decision":
            raise RuntimeError("log unavailable")
        return real(conn, **kw)

    monkeypatch.setattr(ledger_store, "append", broken)
    verdict = lock.decide(request("create", None))  # not required, would be allowed
    assert not verdict.allowed and verdict.reason == "denied:lock_log_failed"


def test_a_failed_log_of_a_lock_record_leaves_no_lock_recorded(
    engine: Engine, keys: Keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = make_lock(engine, keys)
    real = ledger_store.append

    def broken(conn: Any, **kw: Any) -> Any:
        if kw["kind"] == "lock.recorded":
            raise RuntimeError("log unavailable")
        return real(conn, **kw)

    monkeypatch.setattr(ledger_store, "append", broken)
    verdict = lock.decide(request("create", principal(keys), negotiated=True))
    assert (
        not verdict.allowed and events(engine) == []
    )  # the record and its log entry are one transaction


# ------------------------------------------------------------------------------------ ablation


def test_the_ablation_is_refused_in_demo_and_accepted_elsewhere() -> None:
    with pytest.raises(AblationRefused):
        Ablations.from_env({"ABL_NO_PRINCIPAL_LOCK": "1", "APP_ENV": "demo"})
    assert Ablations.from_env({"ABL_NO_PRINCIPAL_LOCK": "1"}).no_principal_lock is True


def test_without_the_principal_lock_only_the_negotiating_session_is_protected(
    engine: Engine, keys: Keys
) -> None:
    baseline = make_lock(engine, keys, ablations=Ablations(no_principal_lock=True))
    who = principal(keys)
    assert baseline.decide(request("create", who, negotiated=True)).allowed
    assert events(engine) == []  # nothing is remembered
    # The session that negotiated is still protected ...
    assert not baseline.decide(request("complete", who, negotiated=True, mandate=False)).allowed
    # ... a second session and a second protocol path get through without a mandate.
    assert baseline.decide(request("create", who, negotiated=False)).allowed
    assert second_protocol_entry(baseline, who) is True
    # With the lock on, the same requests are denied with mandate_required.
    full = make_lock(engine, keys)
    full.decide(request("create", who, negotiated=True))
    denied = full.decide(request("create", who, negotiated=False))
    assert not denied.allowed and denied.ucp_code == "mandate_required"
    assert second_protocol_entry(full, who) is False


def test_decisions_carry_no_customer_id_or_thumbprint_in_the_log(
    engine: Engine, keys: Keys
) -> None:
    lock = make_lock(engine, keys)
    lock.decide(request("create", principal(keys), negotiated=True))
    with engine.connect() as conn:
        payloads = [
            json.loads(e.payload) for e in entries_for_checkout(conn, "chk_lock_test_000000000")
        ]
    text_blob = json.dumps(payloads)
    assert "cust-1" not in text_blob and keys.agents[0].thumbprint() not in text_blob
    assert MerchantPolicy(0).mode == "off"


def test_a_human_present_principal_with_no_agent_key_is_caught_by_its_customer(
    engine: Engine, keys: Keys
) -> None:
    lock = make_lock(engine, keys)
    lock.decide(request("create", principal(keys), negotiated=True))  # (cust-1, agent 0)
    human_present = Principal("cust-1", None)  # a single link mandate names no agent key
    verdict = lock.decide(request("complete", human_present, mandate=False))
    assert not verdict.allowed and verdict.locked
    assert lock.decide(request("complete", Principal("cust-2", None))).allowed

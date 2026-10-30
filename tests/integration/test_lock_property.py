"""For every locked principal and every protocol path, no mandate implies denial (real Postgres).

Each example is a fresh set of principals (unique customer ids and agent keys by name), a sequence of
requests, and a model of the lock written independently of the implementation:

- a principal that negotiated AP2, or used a mandate, becomes locked and stays locked;
- under the threshold policy (5000 minor units, strictly above) a total over it needs AP2 too;
- create and update then need the capability to have been negotiated; complete and capture need a
  valid mandate; and a customer must be named when the policy needs it.

Checked: a locked principal with no mandate is always denied (whatever the protocol path or the
operation), and with a valid mandate the lock never blocks a checkout that would otherwise pass.
"""

from __future__ import annotations

import itertools

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import Engine

from countersign.canonical.money import Money
from countersign.lock import LockRequest, Principal
from tests.lock_support import make_lock
from tests.mandate_issuer import Keys

THRESHOLD = 5000
COUNTER = itertools.count()
requests = st.lists(
    st.tuples(
        st.integers(min_value=0, max_value=3),  # which principal
        st.sampled_from(["create", "update", "complete", "capture"]),
        st.sampled_from(["ucp", "second"]),  # the protocol path (both call the same function)
        st.booleans(),  # negotiated
        st.booleans(),  # mandate valid
        st.sampled_from([1000, 5000, 5001, 9000]),
    ),
    min_size=1,
    max_size=8,
)


def test_no_mandate_implies_denial_for_a_locked_principal_and_a_valid_mandate_never_blocks(
    app_engine: Engine, clean_payments: None
) -> None:
    keys = Keys()
    lock = make_lock(app_engine, keys)
    lock.set_policy("over_threshold", threshold_minor=THRESHOLD, currency="USD", reason="prop")
    seen = {"denied_locked": 0, "allowed_with_mandate": 0}

    @settings(
        max_examples=500,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @given(sequence=requests)
    def run(sequence: list[tuple[int, str, str, bool, bool, int]]) -> None:
        serial = next(COUNTER)
        locked: set[int] = set()
        for index, operation, path, negotiated, mandate, minor in sequence:
            # Only complete and capture present mandates; create and update cannot.
            mandate = mandate and operation in ("complete", "capture")
            who = Principal(
                f"cust-{serial}-{index}", keys.agents[index % 3].thumbprint() + str(serial)
            )
            session_ap2 = negotiated or mandate
            if session_ap2:
                locked.add(index)
            was_locked = index in locked
            over = minor > THRESHOLD
            required = session_ap2 or was_locked or over
            if not required:
                expected = True
            elif operation in ("create", "update"):
                expected = negotiated
            else:
                expected = mandate
            request = LockRequest(
                operation, f"chk_prop_{serial}_{index}", who, negotiated, mandate,  # type: ignore[arg-type]
                Money("USD", minor),
            )  # fmt: skip
            verdict = lock.decide(request)
            assert verdict.allowed is expected, (operation, path, negotiated, mandate, minor)
            if was_locked and operation in ("complete", "capture") and not mandate:
                assert not verdict.allowed  # no mandate implies denial
                seen["denied_locked"] += 1
            if mandate and operation in ("complete", "capture"):
                assert verdict.allowed  # the lock never blocks a checkout with a valid mandate
                seen["allowed_with_mandate"] += 1

    run()
    assert seen["denied_locked"] > 50 and seen["allowed_with_mandate"] > 50, seen

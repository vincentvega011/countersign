"""The checkout status table: every pair of statuses, against a table written out independently."""

from __future__ import annotations

import itertools

import pytest

from countersign.protocols.ucp.checkout_state import (
    FINAL,
    InvalidTransition,
    Status,
    can_transition,
    cancelable,
    transition,
    updatable,
)

S = Status
# Written out from the lifecycle diagram in the vendored checkout specification, not derived from
# the module under test.
ALLOWED = {
    (S.INCOMPLETE, S.READY_FOR_COMPLETE),
    (S.INCOMPLETE, S.REQUIRES_ESCALATION),
    (S.INCOMPLETE, S.CANCELED),
    (S.REQUIRES_ESCALATION, S.INCOMPLETE),
    (S.REQUIRES_ESCALATION, S.COMPLETED),
    (S.REQUIRES_ESCALATION, S.CANCELED),
    (S.READY_FOR_COMPLETE, S.COMPLETE_IN_PROGRESS),
    (S.READY_FOR_COMPLETE, S.INCOMPLETE),
    (S.READY_FOR_COMPLETE, S.CANCELED),
    (S.COMPLETE_IN_PROGRESS, S.COMPLETED),
    (S.COMPLETE_IN_PROGRESS, S.READY_FOR_COMPLETE),
    (S.COMPLETE_IN_PROGRESS, S.INCOMPLETE),
    (S.COMPLETE_IN_PROGRESS, S.CANCELED),
}
PAIRS = list(itertools.product(Status, Status))


def test_statuses_are_the_six_in_the_schema() -> None:
    assert {s.value for s in Status} == {
        "incomplete",
        "requires_escalation",
        "ready_for_complete",
        "complete_in_progress",
        "completed",
        "canceled",
    }


@pytest.mark.parametrize(("source", "target"), PAIRS)
def test_every_pair(source: Status, target: Status) -> None:
    expected = (source, target) in ALLOWED
    assert can_transition(source, target) is expected
    if expected:
        assert transition(source, target) is target
    else:
        with pytest.raises(InvalidTransition) as exc:
            transition(source, target)
        assert exc.value.source is source and exc.value.target is target
        assert exc.value.code == "invalid_transition"


def test_nothing_leaves_a_final_status() -> None:
    for final in FINAL:
        assert not any(can_transition(final, t) for t in Status)


def test_a_status_is_never_its_own_edge() -> None:
    assert not any(can_transition(s, s) for s in Status)


def test_everything_non_final_can_be_canceled() -> None:
    for s in Status:
        assert can_transition(s, S.CANCELED) is (s not in FINAL)
        assert cancelable(s) is (s not in FINAL)


@pytest.mark.parametrize("status", list(Status))
def test_updatable_only_before_completion_is_accepted(status: Status) -> None:
    assert updatable(status) is (
        status in {S.INCOMPLETE, S.REQUIRES_ESCALATION, S.READY_FOR_COMPLETE}
    )

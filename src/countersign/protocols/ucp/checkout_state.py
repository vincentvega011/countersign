"""Checkout status values and the explicit transition table.

The values and the allowed edges come from the UCP checkout lifecycle (vendored
`shopping/checkout/index.md`, "Checkout Status Lifecycle" and "Status Values"; docs/PROTOCOL.md
Decision 17). Every change of status goes through `transition`, which refuses any edge that is not
in the table, so an operation cannot move a checkout somewhere the lifecycle does not allow.

Edges:

- `incomplete` to `ready_for_complete` (all information collected), to `requires_escalation`
  (buyer handoff) and to `canceled`.
- `requires_escalation` to `incomplete`, to `completed` (the buyer finishes on `continue_url`) and
  to `canceled`.
- `ready_for_complete` to `complete_in_progress` (Complete accepted), to `incomplete` (an update
  removed required information) and to `canceled`.
- `complete_in_progress` to `completed`, and back to `ready_for_complete` or `incomplete` when the
  business rejects the completion; to `canceled` (expiry; cancellation while in progress is
  otherwise governed by the spec's race rules, which Countersign does not implement).
- `completed` and `canceled` are final: nothing leaves them.

Staying in the same status (an update that changes nothing about readiness) is not an edge and is
not passed to `transition`.
"""

from __future__ import annotations

from enum import StrEnum


class Status(StrEnum):
    INCOMPLETE = "incomplete"
    REQUIRES_ESCALATION = "requires_escalation"
    READY_FOR_COMPLETE = "ready_for_complete"
    COMPLETE_IN_PROGRESS = "complete_in_progress"
    COMPLETED = "completed"
    CANCELED = "canceled"


FINAL = frozenset({Status.COMPLETED, Status.CANCELED})

_EDGES: dict[Status, frozenset[Status]] = {
    Status.INCOMPLETE: frozenset(
        {Status.READY_FOR_COMPLETE, Status.REQUIRES_ESCALATION, Status.CANCELED}
    ),
    Status.REQUIRES_ESCALATION: frozenset({Status.INCOMPLETE, Status.COMPLETED, Status.CANCELED}),
    Status.READY_FOR_COMPLETE: frozenset(
        {Status.COMPLETE_IN_PROGRESS, Status.INCOMPLETE, Status.CANCELED}
    ),
    Status.COMPLETE_IN_PROGRESS: frozenset(
        {Status.COMPLETED, Status.READY_FOR_COMPLETE, Status.INCOMPLETE, Status.CANCELED}
    ),
    Status.COMPLETED: frozenset(),
    Status.CANCELED: frozenset(),
}


class InvalidTransition(Exception):
    """The requested status change is not an edge of the lifecycle."""

    code = "invalid_transition"

    def __init__(self, source: Status, target: Status) -> None:
        super().__init__(f"{source.value} cannot become {target.value}")
        self.source = source
        self.target = target


def can_transition(source: Status, target: Status) -> bool:
    return target in _EDGES[source]


def transition(source: Status, target: Status) -> Status:
    """Return `target` if the edge exists, else raise `InvalidTransition`."""
    if not can_transition(source, target):
        raise InvalidTransition(source, target)
    return target


def updatable(status: Status) -> bool:
    """Update Checkout is allowed before completion has been accepted and never after."""
    return status in {Status.INCOMPLETE, Status.REQUIRES_ESCALATION, Status.READY_FOR_COMPLETE}


def cancelable(status: Status) -> bool:
    """Any status that is not `completed` or `canceled` SHOULD be cancelable (spec)."""
    return status not in FINAL

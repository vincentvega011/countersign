"""Single-use reservation of the keys of a Checkout Mandate (docs/PROTOCOL.md Decision 1, INV-6).

The verifier asks the store for all the keys of a presentation in ONE call. The call either
reserves every key or reserves nothing and says which key was already taken, so two concurrent
presentations cannot both win and a refusal never leaves a half-reserved state.

Keys (Decision 1): the checkout hash, the checkout id, the closed mandate nonce scoped to the agent
key thumbprint and the audience, and the mandate digest (the open mandate in autonomous mode, the
closed mandate in Human Present mode), which allows one in-flight presentation at a time.

Three ways to end a reservation, with different effects:

- `abort`: nothing outside the process happened (for example the decision log failed). Frees every
  key, like a rolled back transaction.
- `release`: a rejection after the reservation, for example a void before capture. Frees only the
  mandate digest, so the agent can retry under the same open mandate with a new checkout; the
  checkout hash, checkout id and nonce stay consumed (Decision 1, Decision 2).
- `consume`: the purchase succeeded (capture). The mandate digest is permanently used.

`InMemoryReservationStore` is for tests and single-process use. The Postgres store (P2.4) must give
the same guarantees with unique constraints and row locks, not with process memory.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from typing import Protocol

REASON_CHECKOUT_REUSED = "checkout_hash_reused"
REASON_NONCE_REPLAYED = "nonce_replayed"
REASON_MANDATE_IN_USE = "open_mandate_in_use"


@dataclass(frozen=True)
class ReservationRequest:
    checkout_id: str
    checkout_hash: str
    mandate_digest: str
    nonce_scope: tuple[str, str, str] | None  # (agent key thumbprint, audience, nonce)


@dataclass(frozen=True)
class Reservation:
    handle: str
    request: ReservationRequest


class AlreadyReservedError(Exception):
    """A key of the request is taken. `reason` is one of the REASON_* constants."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ReservationError(Exception):
    """A reservation was ended in a way its state does not allow."""


class ReservationStore(Protocol):
    def reserve(self, request: ReservationRequest) -> Reservation: ...

    def abort(self, reservation: Reservation) -> None: ...

    def release(self, reservation: Reservation) -> None: ...

    def consume(self, reservation: Reservation) -> None: ...


class InMemoryReservationStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._checkout_hashes: set[str] = set()
        self._checkout_ids: set[str] = set()
        self._nonces: set[tuple[str, str, str]] = set()
        self._mandates: dict[str, str] = {}  # digest -> "in_flight" | "consumed"
        self._open: dict[str, Reservation] = {}  # handle -> reservation still in flight

    def reserve(self, request: ReservationRequest) -> Reservation:
        with self._lock:
            if request.checkout_hash in self._checkout_hashes or request.checkout_id in (
                self._checkout_ids
            ):
                raise AlreadyReservedError(REASON_CHECKOUT_REUSED)
            if request.nonce_scope is not None and request.nonce_scope in self._nonces:
                raise AlreadyReservedError(REASON_NONCE_REPLAYED)
            if request.mandate_digest in self._mandates:
                raise AlreadyReservedError(REASON_MANDATE_IN_USE)
            self._checkout_hashes.add(request.checkout_hash)
            self._checkout_ids.add(request.checkout_id)
            if request.nonce_scope is not None:
                self._nonces.add(request.nonce_scope)
            self._mandates[request.mandate_digest] = "in_flight"
            reservation = Reservation(secrets.token_urlsafe(16), request)
            self._open[reservation.handle] = reservation
            return reservation

    def _take(self, reservation: Reservation) -> ReservationRequest:
        if self._open.pop(reservation.handle, None) is None:
            raise ReservationError("the reservation is not in flight")
        return reservation.request

    def abort(self, reservation: Reservation) -> None:
        with self._lock:
            request = self._take(reservation)
            self._checkout_hashes.discard(request.checkout_hash)
            self._checkout_ids.discard(request.checkout_id)
            if request.nonce_scope is not None:
                self._nonces.discard(request.nonce_scope)
            del self._mandates[request.mandate_digest]

    def release(self, reservation: Reservation) -> None:
        with self._lock:
            request = self._take(reservation)
            del self._mandates[request.mandate_digest]

    def consume(self, reservation: Reservation) -> None:
        with self._lock:
            request = self._take(reservation)
            self._mandates[request.mandate_digest] = "consumed"

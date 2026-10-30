"""The pure checks of the capture gate, and the only way to build the state they compare.

Security reasoning (INV-4). The gate must compare PayPal state that was fetched for THIS gate run,
never an object kept from an earlier call. Two things enforce that here:

1. `LiveState` is sealed. Its constructor needs a module-private token, so the only way to get one
   is `fetch_live`, which calls the two PayPal GETs itself, once each, and builds the value from
   their results. A caller cannot wrap an old `Order` and hand it to a check.
2. Every check takes a `LiveState` and refuses anything else (`require_live`), so passing a bare
   `Order` or `Authorization` raises `TypeError` instead of comparing it.

Every check is deterministic (INV-1): no I/O, no clock except the value passed in, and a failure is
a `GateFailure` with a fixed reason. A check never reads a module-level or memoized PayPal result;
`tests/unit/test_gate_import_guard.py` fails if anything under `gate/` caches.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from typing import Any, NoReturn

from countersign.canonical.models import Checkout
from countersign.canonical.money import Money
from countersign.gate.outcomes import (
    G_AMOUNT,
    G_FETCH,
    G_REVERSE,
    G_STATUS,
    G_TERMS,
    GateFailure,
)
from countersign.paypal.models import Authorization, Order
from countersign.paypal.translate import (
    OrderTerms,
    TranslationError,
    expected_terms,
    paypal_order_to_canonical_terms,
)

_FETCHED_BY_GATE = object()


class LiveState:
    """An order and its authorization, fetched by `fetch_live` for one gate run. Immutable."""

    __slots__ = ("authorization", "order")

    order: Order
    authorization: Authorization

    def __init__(self, seal: object, *, order: Order, authorization: Authorization) -> None:
        if seal is not _FETCHED_BY_GATE:
            raise TypeError("live PayPal state is made by fetch_live, not directly")
        object.__setattr__(self, "order", order)
        object.__setattr__(self, "authorization", authorization)

    def __init_subclass__(cls, **kwargs: Any) -> NoReturn:
        raise TypeError("LiveState cannot be subclassed")

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("live PayPal state is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("live PayPal state is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("live PayPal state cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("live PayPal state cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("live PayPal state cannot be pickled")


def require_live(live: object) -> LiveState:
    if type(live) is not LiveState:
        raise TypeError("the gate compares freshly fetched LiveState only")
    return live


def fetch_live(
    get_order: Callable[[], Order], get_authorization: Callable[[], Authorization]
) -> LiveState:
    """Call both GETs now and seal their results. The callables are invoked exactly once each."""
    order = get_order()
    authorization = get_authorization()
    if not isinstance(order, Order) or not isinstance(authorization, Authorization):
        raise GateFailure(G_FETCH, "paypal_response_not_typed")
    return LiveState(_FETCHED_BY_GATE, order=order, authorization=authorization)


def check_status(live: LiveState, *, authorization_id: str, now: datetime, skew_s: int) -> None:
    """G-STATUS: capturable, unexpired, not captured and not voided."""
    live = require_live(live)
    on_order = live.order.authorizations
    if len(on_order) != 1 or on_order[0].id != authorization_id:
        raise GateFailure(G_STATUS, "authorization_not_on_order")
    if live.authorization.id != authorization_id:
        raise GateFailure(G_STATUS, "authorization_id_differs")
    if live.order.captures:
        raise GateFailure(G_STATUS, "order_already_captured")
    status = live.authorization.status
    if status != "CREATED":
        raise GateFailure(G_STATUS, f"authorization_{status.lower()}"[:60])
    expires = live.authorization.expiration_time
    if expires.tzinfo is None:
        raise GateFailure(G_STATUS, "expiration_has_no_zone")
    if expires <= now + timedelta(seconds=skew_s):
        raise GateFailure(G_STATUS, "authorization_expired")


def reverse_terms(live: LiveState, *, line_ids: Sequence[str]) -> OrderTerms:
    """G-REVERSE: the canonical terms the live order actually states."""
    live = require_live(live)
    try:
        return paypal_order_to_canonical_terms(live.order, line_ids=line_ids)
    except TranslationError:
        raise GateFailure(G_REVERSE, "order_terms_unreadable") from None


def check_terms(
    live: LiveState,
    reversed_terms: OrderTerms,
    *,
    checkout: Checkout,
    custom_id: str,
    payee_merchant_id: str,
) -> None:
    """G-TERMS: the live terms equal the signed checkout's, and the ids are what the CP set."""
    live = require_live(live)
    if reversed_terms.invoice_id != checkout.id or live.authorization.invoice_id != checkout.id:
        raise GateFailure(G_TERMS, "invoice_id_differs")
    if reversed_terms.custom_id != custom_id or live.authorization.custom_id != custom_id:
        raise GateFailure(G_TERMS, "custom_id_differs")
    try:
        wanted = expected_terms(checkout, payee_merchant_id=payee_merchant_id, custom_id=custom_id)
    except TranslationError:
        raise GateFailure(G_TERMS, "checkout_has_no_paypal_form") from None
    if reversed_terms.terms_hash() != wanted.terms_hash():
        raise GateFailure(G_TERMS, "order_terms_differ")


def check_amount(live: LiveState, *, total: Money) -> None:
    """G-AMOUNT: the authorized amount, and the order's, equal the checkout total exactly."""
    live = require_live(live)
    if live.authorization.amount != total:
        raise GateFailure(G_AMOUNT, "authorization_amount_differs")
    if live.order.purchase_units[0].amount != total:
        raise GateFailure(G_AMOUNT, "order_amount_differs")

"""The pure checks of the gate and the sealed live state (INV-4: only fresh PayPal state is compared)."""

from __future__ import annotations

import copy
import pickle
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from countersign.canonical.money import Money
from countersign.gate import GateFailure, steps
from countersign.gate.steps import LiveState, fetch_live, require_live
from countersign.paypal.models import Authorization, Order
from tests import paypal_sim
from tests.cp_support import make_world  # noqa: F401  (imported to share the fixtures' side effects)

NOW = datetime(2026, 10, 30, 10, 0, tzinfo=UTC)


def auth_body(**over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": "AUTH1",
        "status": "CREATED",
        "amount": {"currency_code": "USD", "value": "85.00"},
        "invoice_id": "chk_1",
        "custom_id": "cs1.x",
        "expiration_time": (NOW + timedelta(days=29)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    body.update(over)
    return body


def authorization(**over: Any) -> Authorization:
    return Authorization.model_validate(auth_body(**over))


def order(authorizations: list[dict[str, Any]] | None = None, captures: Any = None) -> Order:
    auths = authorizations if authorizations is not None else [auth_body()]
    payments: dict[str, Any] = {"authorizations": auths}
    if captures:
        payments["captures"] = captures
    return Order.model_validate(
        {
            "id": "ORDER1",
            "status": "COMPLETED",
            "intent": "AUTHORIZE",
            "purchase_units": [
                {
                    "amount": {"currency_code": "USD", "value": "85.00"},
                    "invoice_id": "chk_1",
                    "custom_id": "cs1.x",
                    "payments": payments,
                }
            ],
        }
    )


def live(o: Order | None = None, a: Authorization | None = None) -> LiveState:
    return fetch_live(lambda: o or order(), lambda: a or authorization())


# ----------------------------------------------------------------------- the sealed state


def test_live_state_cannot_be_built_directly() -> None:
    with pytest.raises(TypeError):
        LiveState(object(), order=order(), authorization=authorization())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        LiveState(order=order(), authorization=authorization())  # type: ignore[call-arg]


def test_live_state_is_immutable_uncopyable_and_final() -> None:
    state = live()
    with pytest.raises(AttributeError):
        state.order = order()  # type: ignore[misc]
    with pytest.raises(AttributeError):
        del state.order
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(state)
    with pytest.raises(TypeError):

        class Sub(LiveState):
            pass


def test_fetch_live_calls_each_read_exactly_once_and_now() -> None:
    calls: list[str] = []

    def get_order() -> Order:
        calls.append("order")
        return order()

    def get_authorization() -> Authorization:
        calls.append("authorization")
        return authorization()

    fetch_live(get_order, get_authorization)
    assert calls == ["order", "authorization"]


def test_fetch_live_refuses_results_that_are_not_the_typed_models() -> None:
    with pytest.raises(GateFailure) as raised:
        fetch_live(lambda: {"id": "x"}, lambda: authorization())  # type: ignore[arg-type, return-value]
    assert raised.value.code == "G-FETCH"


def test_a_check_given_a_bare_cached_order_object_refuses_it() -> None:
    """A cached `Order` or `Authorization` is not live state, so no check will compare it."""
    cached_order, cached_authorization = order(), authorization()
    for call in (
        lambda: require_live(cached_order),
        lambda: steps.check_status(cached_order, authorization_id="AUTH1", now=NOW, skew_s=60),  # type: ignore[arg-type]
        lambda: steps.reverse_terms(cached_order, line_ids=["li_1"]),  # type: ignore[arg-type]
        lambda: steps.check_amount(cached_authorization, total=Money("USD", 8500)),  # type: ignore[arg-type]
        lambda: steps.check_terms(
            cached_order,
            None,
            checkout=None,
            custom_id="x",
            payee_merchant_id="m",  # type: ignore[arg-type]
        ),
    ):
        with pytest.raises(TypeError):
            call()


# ------------------------------------------------------------------------------ G-STATUS


def check_status(state: LiveState, **over: Any) -> None:
    args: dict[str, Any] = {"authorization_id": "AUTH1", "now": NOW, "skew_s": 60}
    args.update(over)
    steps.check_status(state, **args)


def test_status_passes_a_created_unexpired_authorization() -> None:
    check_status(live())


@pytest.mark.parametrize(
    "state,reason",
    [
        (live(a=authorization(status="CAPTURED")), "authorization_captured"),
        (live(a=authorization(status="VOIDED")), "authorization_voided"),
        (live(a=authorization(status="PARTIALLY_CAPTURED")), "authorization_partially_captured"),
        (live(a=authorization(id="AUTH2")), "authorization_id_differs"),
        (
            live(o=order(captures=[{"id": "C1", "status": "COMPLETED",
                                    "amount": {"currency_code": "USD", "value": "85.00"},
                                    "final_capture": True}])),
            "order_already_captured",
        ),
        (live(o=order([auth_body(), auth_body(id="AUTH9")])), "authorization_not_on_order"),
        (live(o=order([auth_body(id="AUTH9")])), "authorization_not_on_order"),
    ],
)  # fmt: skip
def test_status_fails(state: LiveState, reason: str) -> None:
    with pytest.raises(GateFailure) as raised:
        check_status(state)
    assert raised.value.code == "G-STATUS" and raised.value.reason == reason


def test_status_fails_inside_the_expiry_skew_and_without_a_zone() -> None:
    soon = authorization(
        expiration_time=(NOW + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    with pytest.raises(GateFailure) as raised:
        check_status(live(a=soon))
    assert raised.value.reason == "authorization_expired"
    check_status(live(a=soon), skew_s=0)  # outside the skew it would pass


# ------------------------------------------------------------------------------ G-AMOUNT


def test_amount_requires_the_exact_total_on_both_the_authorization_and_the_order() -> None:
    steps.check_amount(live(), total=Money("USD", 8500))
    with pytest.raises(GateFailure) as raised:
        steps.check_amount(live(), total=Money("USD", 8501))
    assert raised.value.code == "G-AMOUNT" and raised.value.reason == "authorization_amount_differs"
    other = authorization(amount={"currency_code": "USD", "value": "90.00"})
    with pytest.raises(GateFailure) as raised:
        steps.check_amount(live(a=other), total=Money("USD", 9000))
    assert raised.value.reason == "order_amount_differs"


def test_the_failure_codes_are_known_codes() -> None:
    with pytest.raises(ValueError):
        GateFailure("G-NOPE", "x")


def test_the_simulator_clock_is_the_tests_clock() -> None:
    assert paypal_sim.NOW == NOW

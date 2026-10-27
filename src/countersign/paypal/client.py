"""A typed httpx client for the PayPal Orders v2 and Payments v2 calls Countersign makes.

Endpoints, fields and behaviours are only those recorded in docs/ENV.md section 2 and
docs/PROTOCOL.md section 4. The client is synchronous, like the services that call it.

Security reasoning.

- State comes from GET, not from mutation responses. A void response returned `custom_id` as null in
  the sandbox (docs/ENV.md section 2.5), so a mutation returns only the identifier of the resource it
  touched (`Mutation`) and callers re-fetch with `get_order`, `get_authorization` or `get_capture`.
  `authorize` does not even read its response body.
- A POST with no payload still sends a JSON body: `authorize` and a full refund send `{}` with
  `Content-Type: application/json`, as the working smoke and confirmation runs did. With no body PayPal
  answers HTTP 415. `void` sends no body, which is what those runs did and PayPal accepted.
- Every state-changing call carries a deterministic `PayPal-Request-Id` (`request_id.py`) and the
  client refuses to send one without it. Retries (5xx, timeouts, connection errors, and a 409 for a
  request still in progress) reuse the same id, so PayPal replays instead of repeating. A call whose
  outcome is unknown after the retries raises an error with `outcome_unknown` set; the caller
  re-fetches and never assumes either result.
- Limits that PayPal answers badly are enforced here: a Request-Id longer than 108 characters is an
  HTTP 500 at PayPal, so it is never sent; `invoice_id` and `custom_id` limits are checked when the
  order request is built.
- Capture has no amount parameter and no partial form. It fetches the authorization, requires status
  `CREATED`, an unexpired `expiration_time` and an amount equal to the total the caller expects, then
  sends that full amount with `final_capture` true. Anything else raises before any capture request
  leaves the process (INV-4: capture only from freshly fetched state).
- Credentials and tokens are never logged, formatted or put in an exception. Errors carry PayPal's
  name, message, issue codes, status and debug id only; log lines carry the operation, path, status,
  attempt and debug id only.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Self, TypeVar

import httpx
import structlog
from pydantic import BaseModel, ValidationError

from countersign.canonical.money import Money
from countersign.paypal.config import PayPalConfig
from countersign.paypal.errors import (
    AmountMismatch,
    AuthorizationNotCapturable,
    PayPalAuthError,
    PayPalResponseError,
    PayPalTimeout,
    PayPalTransportError,
    PreviousRequestInProgress,
    debug_id_of,
    error_body,
    issues_of,
    map_error,
)
from countersign.paypal.limits import (
    LimitError,
    check_path_id,
    check_refund_key,
    check_request_id,
)
from countersign.paypal.models import Authorization, Capture, Order, OrderRequest, amount_json
from countersign.paypal.request_id import (
    Operation,
    create_order_request_id,
    derive_request_id,
)

log = structlog.get_logger("countersign.paypal")
_M = TypeVar("_M", bound=BaseModel)

_APPROVAL_RELS = ("payer-action", "approve")
_MAX_BACKOFF_S = 8.0


@dataclass(frozen=True)
class Mutation:
    """What a state-changing call returns: the resource it touched, nothing about its state."""

    resource_id: str
    status_code: int
    debug_id: str | None


@dataclass(frozen=True)
class OrderCreated(Mutation):
    approval_url: str | None = None  # the payer-action (or approve) link, if PayPal sent one


@dataclass
class _Token:
    value: str
    expires_at: float  # monotonic seconds

    def __repr__(self) -> str:
        return "_Token(<redacted>)"


class PayPalClient:
    def __init__(
        self,
        config: PayPalConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._http = httpx.Client(
            base_url=config.base_url,
            transport=transport,
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=config.connect_timeout_s,
                read=config.read_timeout_s,
                write=config.read_timeout_s,
                pool=config.connect_timeout_s,
            ),
        )
        self._monotonic = monotonic
        self._now = now
        self._sleep = sleep
        self._token: _Token | None = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"PayPalClient(base_url={self._config.base_url!r})"

    __str__ = __repr__

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------ OAuth

    def _access_token(self) -> str:
        with self._lock:
            token = self._token
            if (
                token is not None
                and self._monotonic() < token.expires_at - self._config.token_skew_s
            ):
                return token.value
            self._token = self._fetch_token()
            return self._token.value

    def _invalidate_token(self) -> None:
        with self._lock:
            self._token = None

    def _fetch_token(self) -> _Token:
        response = self._attempts(
            lambda: self._http.post(
                "/v1/oauth2/token",
                auth=(self._config.client_id, self._config.client_secret),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json"},
            ),
            op="oauth_token",
            path="/v1/oauth2/token",
            mutating=False,
        )
        if response.status_code != 200:
            error = map_error(response)
            raise PayPalAuthError(
                "token request refused",
                status=response.status_code,
                name=error.name,
                debug_id=error.debug_id,
            )
        body = error_body(response)
        value, lifetime = body.get("access_token"), body.get("expires_in")
        token_type = body.get("token_type")
        if (
            not isinstance(value, str)
            or not value
            or type(lifetime) is not int
            or lifetime <= 0
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
        ):
            raise PayPalResponseError(
                "the token response is not a bearer token with a lifetime",
                status=response.status_code,
                debug_id=debug_id_of(response, body),
            )
        return _Token(value=value, expires_at=self._monotonic() + lifetime)

    # ------------------------------------------------------------------ transport

    def _attempts(
        self,
        send: Callable[[], httpx.Response],
        *,
        op: str,
        path: str,
        mutating: bool,
        refresh_on_401: Callable[[], None] | None = None,
    ) -> httpx.Response:
        """Run `send` with retries on 5xx, timeouts, connection errors and 409 in progress."""
        attempt = 0
        refreshed = False
        while True:
            attempt += 1
            last = attempt >= self._config.max_attempts
            try:
                response = send()
            except httpx.TimeoutException:
                log.warning("paypal_call", op=op, path=path, outcome="timeout", attempt=attempt)
                if last:
                    raise PayPalTimeout("the request timed out", outcome_unknown=mutating) from None
                self._backoff(attempt)
                continue
            except httpx.TransportError:
                log.warning("paypal_call", op=op, path=path, outcome="transport", attempt=attempt)
                if last:
                    raise PayPalTransportError(
                        "the connection failed", outcome_unknown=mutating
                    ) from None
                self._backoff(attempt)
                continue
            try:
                body = error_body(response) if response.status_code >= 400 else {}
            except PayPalResponseError as exc:
                exc.outcome_unknown = mutating  # a garbled answer to a mutation settles nothing
                raise
            log.info(
                "paypal_call",
                op=op,
                path=path,
                status=response.status_code,
                attempt=attempt,
                debug_id=debug_id_of(response, body),
            )
            if response.status_code == 401 and refresh_on_401 is not None and not refreshed:
                refreshed = True
                refresh_on_401()
                attempt -= 1  # a refreshed token is not a retry of the call
                continue
            if self._retryable(response, body) and not last:
                self._backoff(attempt)
                continue
            return response

    @staticmethod
    def _retryable(response: httpx.Response, body: dict[str, Any]) -> bool:
        if response.status_code >= 500:
            return True
        return response.status_code == 409 and "PREVIOUS_REQUEST_IN_PROGRESS" in (
            body.get("name"),
            *issues_of(body),
        )

    def _backoff(self, attempt: int) -> None:
        self._sleep(min(self._config.backoff_s * 2 ** (attempt - 1), _MAX_BACKOFF_S))

    def _call(
        self,
        method: str,
        path: str,
        *,
        op: str,
        ok: tuple[int, ...],
        body: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> httpx.Response:
        mutating = method != "GET"
        if mutating and request_id is None:
            raise RuntimeError("a state-changing PayPal call must carry a PayPal-Request-Id")
        if not mutating and request_id is not None:
            raise RuntimeError("a read must not carry a PayPal-Request-Id")
        if request_id is not None:
            check_request_id(request_id)  # over 108 characters is an HTTP 500 at PayPal: never send

        def send() -> httpx.Response:
            headers = {
                "Authorization": f"Bearer {self._access_token()}",
                "Accept": "application/json",
            }
            if mutating:
                headers["Prefer"] = "return=representation"
            if request_id is not None:
                headers["PayPal-Request-Id"] = request_id
            return self._http.request(method, path, json=body, headers=headers)

        response = self._attempts(
            send,
            op=op,
            path=path,
            mutating=mutating,
            refresh_on_401=self._invalidate_token,
        )
        if response.status_code in ok:
            return response
        error = map_error(response, mutating=mutating)
        if isinstance(error, PreviousRequestInProgress):
            error.outcome_unknown = mutating
        raise error

    # ------------------------------------------------------------------ parsing

    @staticmethod
    def _object(response: httpx.Response) -> dict[str, Any]:
        body = error_body(response)
        if not body:
            raise PayPalResponseError(
                "the response is not a JSON object",
                status=response.status_code,
                debug_id=debug_id_of(response, {}),
            )
        return body

    @staticmethod
    def _parse(model: type[_M], response: httpx.Response) -> _M:
        body = PayPalClient._object(response)
        try:
            return model.model_validate(body)
        except ValidationError as exc:
            # Field locations and error kinds only: never the values, which may be account data.
            where = sorted(
                {".".join(str(p) for p in e["loc"]) + f" ({e['type']})" for e in exc.errors()}
            )
            raise PayPalResponseError(
                "the response is missing or has invalid fields: " + "; ".join(where[:8]),
                status=response.status_code,
                debug_id=debug_id_of(response, body),
            ) from None

    @staticmethod
    def _resource_id(response: httpx.Response, what: str) -> str:
        body = PayPalClient._object(response)
        value = body.get("id")
        if not isinstance(value, str) or not value:
            raise PayPalResponseError(
                f"the {what} response has no id",
                status=response.status_code,
                debug_id=debug_id_of(response, body),
            )
        return check_path_id(value, f"{what} id")

    @staticmethod
    def _mutation(response: httpx.Response, resource_id: str) -> Mutation:
        return Mutation(
            resource_id=resource_id,
            status_code=response.status_code,
            debug_id=debug_id_of(response, {}),
        )

    # ------------------------------------------------------------------ reads

    def get_order(self, order_id: str) -> Order:
        path = f"/v2/checkout/orders/{check_path_id(order_id, 'order id')}"
        return self._parse(Order, self._call("GET", path, op="get_order", ok=(200,)))

    def get_authorization(self, authorization_id: str) -> Authorization:
        ident = check_path_id(authorization_id, "authorization id")
        path = f"/v2/payments/authorizations/{ident}"
        return self._parse(
            Authorization, self._call("GET", path, op="get_authorization", ok=(200,))
        )

    def get_capture(self, capture_id: str) -> Capture:
        path = f"/v2/payments/captures/{check_path_id(capture_id, 'capture id')}"
        return self._parse(Capture, self._call("GET", path, op="get_capture", ok=(200,)))

    # ------------------------------------------------------------------ state-changing calls

    def create_order(
        self, checkout_id: str, order: OrderRequest, *, terms_hash: bytes
    ) -> OrderCreated:
        """Create an AUTHORIZE order. Re-fetch with `get_order` for its state.

        `terms_hash` is the canonical terms hash (`Checkout.terms_hash()`) of the checkout the order
        was built from. It is part of the Request-Id, so re-pricing a checkout never replays the
        earlier order.
        """
        response = self._call(
            "POST",
            "/v2/checkout/orders",
            op="create_order",
            ok=(200, 201),
            body=order.to_json(),
            request_id=create_order_request_id(checkout_id, terms_hash),
        )
        order_id = self._resource_id(response, "order")
        links = self._object(response).get("links")
        approval = None
        if isinstance(links, list):
            for rel in _APPROVAL_RELS:
                for link in links:
                    if isinstance(link, dict) and link.get("rel") == rel:
                        href = link.get("href")
                        if isinstance(href, str) and href.startswith("https://"):
                            approval = href
                            break
                if approval:
                    break
        base = self._mutation(response, order_id)
        return OrderCreated(**base.__dict__, approval_url=approval)

    def authorize_order(self, checkout_id: str, order_id: str) -> Mutation:
        """Authorize an approved order. The response body is not read: `get_order` has the result."""
        ident = check_path_id(order_id, "order id")
        response = self._call(
            "POST",
            f"/v2/checkout/orders/{ident}/authorize",
            op="authorize",
            ok=(200, 201),
            # An empty JSON object, not no body: with no body and no content type PayPal answers
            # 415 UNSUPPORTED_MEDIA_TYPE. The smoke and confirmation runs sent `{}` (ENV.md 2.5).
            body={},
            request_id=derive_request_id(checkout_id, Operation.AUTHORIZE),
        )
        return self._mutation(response, ident)

    def capture_authorization(
        self, checkout_id: str, authorization_id: str, *, expected_total: Money
    ) -> Mutation:
        """Capture the whole authorization, once, with `final_capture` true.

        There is no amount to choose: the amount sent is the one in the authorization fetched a moment
        ago, and only if that is `expected_total`. Raises `AuthorizationNotCapturable` or
        `AmountMismatch` without sending a capture otherwise. After an error with `outcome_unknown`,
        re-fetch; do not call this again for the same checkout.
        """
        ident = check_path_id(authorization_id, "authorization id")
        authorization = self.get_authorization(ident)
        if authorization.status != "CREATED":
            raise AuthorizationNotCapturable(
                f"the authorization status is {authorization.status}, not CREATED"
            )
        expires = authorization.expiration_time
        if expires.tzinfo is None:
            raise PayPalResponseError("the authorization expiration_time has no time zone")
        # Fail closed (INV-10): within the skew of expiration_time the authorization counts as expired,
        # because our clock may be behind PayPal's and a capture at the edge may be refused or racing.
        skew = timedelta(seconds=self._config.authorization_expiry_skew_s)
        if expires <= self._now() + skew:
            raise AuthorizationNotCapturable(
                "the authorization has expired or expires within the clock skew"
            )
        if authorization.amount != expected_total:
            raise AmountMismatch("the authorization amount is not the expected total")
        response = self._call(
            "POST",
            f"/v2/payments/authorizations/{ident}/capture",
            op="capture",
            ok=(200, 201),
            body={"amount": amount_json(authorization.amount), "final_capture": True},
            request_id=derive_request_id(checkout_id, Operation.CAPTURE),
        )
        return self._mutation(response, self._resource_id(response, "capture"))

    def void_authorization(self, checkout_id: str, authorization_id: str) -> Mutation:
        """Void an authorization. Re-fetch with `get_authorization` for the result."""
        ident = check_path_id(authorization_id, "authorization id")
        response = self._call(
            "POST",
            f"/v2/payments/authorizations/{ident}/void",
            op="void",
            ok=(200, 204),
            request_id=derive_request_id(checkout_id, Operation.VOID),
        )
        return self._mutation(response, ident)

    def refund_capture(
        self,
        checkout_id: str,
        capture_id: str,
        *,
        refund_key: str,
        amount: Money | None = None,
    ) -> Mutation:
        """Refund a capture: in full (an empty JSON object) or for `amount`. Re-fetch with `get_capture`.

        `refund_key` identifies this one refund and is part of the Request-Id: retrying the same
        refund must pass the same key (PayPal then replays the first result), and a second, separate
        refund of the same amount must pass a new key (otherwise PayPal would replay the first).
        """
        key = check_refund_key(refund_key)
        ident = check_path_id(capture_id, "capture id")
        # A full refund sends `{}`, the form the confirmation runs sent (PROTOCOL.md 4.6), not no body.
        body: dict[str, Any] = {}
        if amount is None:
            part = "full"
        else:
            if amount.minor <= 0:
                raise LimitError("a refund amount must be positive")
            body = {"amount": amount_json(amount)}
            part = f"{amount.currency}:{amount.to_paypal()}"
        response = self._call(
            "POST",
            f"/v2/payments/captures/{ident}/refund",
            op="refund",
            ok=(200, 201),
            body=body,
            request_id=derive_request_id(checkout_id, Operation.REFUND, ident, part, key),
        )
        return self._mutation(response, self._resource_id(response, "refund"))

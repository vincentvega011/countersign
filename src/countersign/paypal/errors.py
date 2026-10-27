"""Typed errors for PayPal calls, and the mapping from PayPal's error bodies.

Error bodies carry `name`, `message`, `debug_id` and `details[]` (`issue`, `field`, `description`)
(docs/ENV.md section 2.3). The codes recorded in docs/PROTOCOL.md section 4 are mapped to their own
exceptions. Where the code sits is not settled by the recorded runs (PayPal's usual shape puts a
class name such as `UNPROCESSABLE_ENTITY` in `name` and the specific code in `details[].issue`, while
the notes record the codes as names), so `map_error` looks at `name` first and then at each `issue`.

Safety. An exception holds the HTTP status, PayPal's `name`, `message`, `debug_id` and the issue
codes, nothing else: never a header, a request body or a credential. `outcome_unknown` is true when a
state-changing call may or may not have taken effect (a timeout, or a server error after the retries
ran out): the caller must re-fetch the resource and must not assume either result (INV-10).
"""

from __future__ import annotations

from typing import Any

import httpx

from countersign.canonical.jsonstrict import JsonSyntaxError, StrictJsonError, loads_strict


class PayPalError(Exception):
    """Base class for everything the client raises about a PayPal exchange."""

    outcome_unknown = False

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        name: str | None = None,
        debug_id: str | None = None,
        issues: tuple[str, ...] = (),
        outcome_unknown: bool = False,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.name = name
        self.debug_id = debug_id
        self.issues = issues
        self.outcome_unknown = outcome_unknown

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.status is not None:
            parts.append(f"status={self.status}")
        if self.name:
            parts.append(f"name={self.name}")
        if self.issues:
            parts.append(f"issues={','.join(self.issues)}")
        if self.debug_id:
            parts.append(f"debug_id={self.debug_id}")
        if self.outcome_unknown:
            parts.append("outcome_unknown")
        return " ".join(parts)


class PayPalConfigError(PayPalError):
    """The client is configured in a way it refuses (a live host, a missing credential)."""


class PayPalAuthError(PayPalError):
    """The credentials were refused, or no token could be obtained."""


class PayPalRequestError(PayPalError):
    """PayPal rejected the request (HTTP 4xx)."""


class PayPalNotFound(PayPalRequestError):
    """HTTP 404: the resource does not exist (or the id is wrong)."""


class PayPalConflict(PayPalRequestError):
    """HTTP 409 other than a request still in progress."""


class PreviousRequestInProgress(PayPalRequestError):
    """409 `PREVIOUS_REQUEST_IN_PROGRESS`: an earlier call with this Request-Id has not finished."""


class InvalidStringLength(PayPalRequestError):
    """400 `INVALID_STRING_LENGTH`: a string field is too long or too short."""


class OrderNotApproved(PayPalRequestError):
    """422 `ORDER_NOT_APPROVED`: the payer has not approved the order."""


class OrderAlreadyAuthorized(PayPalRequestError):
    """422 `ORDER_ALREADY_AUTHORIZED`."""


class OrderAlreadyCompleted(PayPalRequestError):
    """422 `ORDER_ALREADY_COMPLETED`: the order can no longer be changed."""


class MaxCaptureAmountExceeded(PayPalRequestError):
    """422 `MAX_CAPTURE_AMOUNT_EXCEEDED`."""


class AuthorizationAlreadyCaptured(PayPalRequestError):
    """422 `AUTHORIZATION_ALREADY_CAPTURED`."""


class AuthorizationVoided(PayPalRequestError):
    """422 `AUTHORIZATION_VOIDED`: a voided authorization cannot be captured."""


class AuthorizationExpired(PayPalRequestError):
    """422 `AUTHORIZATION_EXPIRED` (from the documentation; not observed)."""


class PreviouslyCaptured(PayPalRequestError):
    """422 `PREVIOUSLY_CAPTURED`: an authorization with a capture cannot be voided."""


class PreviouslyVoided(PayPalRequestError):
    """422 `PREVIOUSLY_VOIDED`."""


class RefundAmountExceeded(PayPalRequestError):
    """422 `REFUND_AMOUNT_EXCEEDED`."""


class CaptureFullyRefunded(PayPalRequestError):
    """422 `CAPTURE_FULLY_REFUNDED`."""


class TransactionDisputed(PayPalRequestError):
    """422 `TRANSACTION_DISPUTED` (from the documentation; not observed)."""


class PayPalServerError(PayPalError):
    """HTTP 5xx, including `INTERNAL_SERVICE_ERROR`."""


class PayPalTimeout(PayPalError):
    """The request timed out on every attempt."""


class PayPalTransportError(PayPalError):
    """The connection failed on every attempt."""


class PayPalResponseError(PayPalError):
    """PayPal answered, but not with what the endpoint is documented to return."""


class AuthorizationNotCapturable(PayPalError):
    """The fetched authorization is not in a state Countersign will capture from. Nothing was sent."""


class AmountMismatch(PayPalError):
    """The fetched authorization amount is not the amount the caller expects. Nothing was sent."""


class AuthorizationMismatch(PayPalError):
    """The fetched authorization is not the one the approval was issued for. Nothing was sent."""


# PayPal code -> exception. Names and issues are looked up in the same table.
ERROR_CODES: dict[str, type[PayPalRequestError]] = {
    "INVALID_STRING_LENGTH": InvalidStringLength,
    "ORDER_NOT_APPROVED": OrderNotApproved,
    "ORDER_ALREADY_AUTHORIZED": OrderAlreadyAuthorized,
    "ORDER_ALREADY_COMPLETED": OrderAlreadyCompleted,
    "MAX_CAPTURE_AMOUNT_EXCEEDED": MaxCaptureAmountExceeded,
    "AUTHORIZATION_ALREADY_CAPTURED": AuthorizationAlreadyCaptured,
    "AUTHORIZATION_VOIDED": AuthorizationVoided,
    "AUTHORIZATION_EXPIRED": AuthorizationExpired,
    "PREVIOUSLY_CAPTURED": PreviouslyCaptured,
    "PREVIOUSLY_VOIDED": PreviouslyVoided,
    "REFUND_AMOUNT_EXCEEDED": RefundAmountExceeded,
    "CAPTURE_FULLY_REFUNDED": CaptureFullyRefunded,
    "TRANSACTION_DISPUTED": TransactionDisputed,
    "PREVIOUS_REQUEST_IN_PROGRESS": PreviousRequestInProgress,
}


def error_body(response: httpx.Response) -> dict[str, Any]:
    """The JSON object in the response body, or an empty dict if there is no JSON object.

    Every PayPal body goes through the strict loader (INV-8): a duplicate key, NaN, Infinity, an
    integer or number the loader refuses, invalid UTF-8 or a byte order mark raises
    `PayPalResponseError` instead of being read one way or another. Only a body that is not JSON at
    all (empty, or an HTML error page) is treated as having no object, because a 502 page is not an
    attack. A body that is JSON but not an object is also no object; callers that need one refuse it.
    """
    try:
        data = loads_strict(response.content)
    except JsonSyntaxError:
        return {}
    except StrictJsonError as exc:
        raise PayPalResponseError(
            f"the response body was refused by the strict JSON loader: {type(exc).__name__}",
            status=response.status_code,
            debug_id=_str(response.headers.get("paypal-debug-id")),
        ) from None
    return data if isinstance(data, dict) else {}


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def issues_of(body: dict[str, Any]) -> tuple[str, ...]:
    details = body.get("details")
    if not isinstance(details, list):
        return ()
    return tuple(i for d in details if isinstance(d, dict) if (i := _str(d.get("issue"))))


def debug_id_of(response: httpx.Response, body: dict[str, Any]) -> str | None:
    return _str(response.headers.get("paypal-debug-id")) or _str(body.get("debug_id"))


def map_error(response: httpx.Response, *, mutating: bool = False) -> PayPalError:
    """Turn a non-success response into the matching exception."""
    body = error_body(response)
    status = response.status_code
    name = _str(body.get("name")) or _str(body.get("error"))
    issues = issues_of(body)
    message = _str(body.get("message")) or _str(body.get("error_description")) or "PayPal error"
    common: dict[str, Any] = {
        "status": status,
        "name": name,
        "debug_id": debug_id_of(response, body),
        "issues": issues,
    }
    if status >= 500:
        return PayPalServerError(message, outcome_unknown=mutating, **common)
    for code in (name, *issues):
        if code in ERROR_CODES:
            return ERROR_CODES[code](message, **common)
    if status == 401:
        return PayPalAuthError(message, **common)
    if status == 404:
        return PayPalNotFound(message, **common)
    if status == 409:
        return PayPalConflict(message, **common)
    return PayPalRequestError(message, **common)

"""Reading a PayPal notification: its headers and the few members that act as hints.

Security reasoning. Everything in a notification is attacker-controlled until PayPal's verification
endpoint has said otherwise, and even afterwards only a few members are used, and only as hints about
WHICH PayPal resource to read again. No amount, status or other fact in the body is ever copied into
the ledger (INV-7): the ledger follows the live state fetched with our own credentials. The body is
parsed with the strict loader (INV-8) and every id taken from it is checked against the PayPal id
rules before it is used in a path or a query.

Headers (docs/PROTOCOL.md 4.8): `PAYPAL-TRANSMISSION-ID`, `PAYPAL-TRANSMISSION-TIME`,
`PAYPAL-TRANSMISSION-SIG`, `PAYPAL-CERT-URL`, `PAYPAL-AUTH-ALGO`. All five are required. The
certificate URL must be an https URL on a `paypal.com` host: PayPal fetches it, and a URL that points
anywhere else is refused here as well as there.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from countersign.canonical.jsonstrict import StrictJsonError, loads_strict
from countersign.paypal.limits import LimitError, check_path_id

MAX_BODY_BYTES = 64 * 1024
_EVENT_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_EVENT_TYPE = re.compile(r"[A-Z0-9_.]{3,80}")
_TOKEN = re.compile(r"[\x21-\x7e]{1,2048}")
_TIME = re.compile(r"[0-9TZ:.+-]{10,40}")
_ALGO = re.compile(r"[A-Za-z0-9_-]{3,40}")

AUTHORIZATION_TYPES = frozenset({"PAYMENT.AUTHORIZATION.CREATED", "PAYMENT.AUTHORIZATION.VOIDED"})
CAPTURE_TYPES = frozenset(
    {
        "PAYMENT.CAPTURE.COMPLETED",
        "PAYMENT.CAPTURE.PENDING",
        "PAYMENT.CAPTURE.DENIED",
        "PAYMENT.CAPTURE.DECLINED",
        "PAYMENT.CAPTURE.REVERSED",
    }
)
REFUND_TYPES = frozenset({"PAYMENT.CAPTURE.REFUNDED"})
ORDER_TYPES = frozenset({"CHECKOUT.ORDER.APPROVED", "CHECKOUT.ORDER.COMPLETED"})
HANDLED = AUTHORIZATION_TYPES | CAPTURE_TYPES | REFUND_TYPES | ORDER_TYPES


class MalformedEvent(Exception):
    """The headers or the body are not a notification Countersign can read. Nothing was changed."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SignatureHeaders:
    transmission_id: str
    transmission_time: str
    transmission_sig: str
    cert_url: str
    auth_algo: str


@dataclass(frozen=True)
class Hint:
    """Which resource to read again. `kind` is authorization, capture, refund (via its capture) or order."""

    kind: str
    resource_id: str


@dataclass(frozen=True)
class Event:
    event_id: str
    event_type: str
    hint: Hint | None  # None for a type that is not handled, or a resource that names no id


def read_headers(headers: Mapping[str, str]) -> SignatureHeaders:
    lowered = {k.lower(): v for k, v in headers.items()}

    def need(name: str, pattern: re.Pattern[str]) -> str:
        value = lowered.get(name)
        if value is None or not pattern.fullmatch(value):
            raise MalformedEvent(f"header_{name.removeprefix('paypal-').replace('-', '_')}")
        return value

    cert = need("paypal-cert-url", _TOKEN)
    parts = urlsplit(cert)
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "https"
        or not (host == "paypal.com" or host.endswith(".paypal.com"))
        or parts.username
        or parts.password
        or parts.port not in (None, 443)
    ):
        raise MalformedEvent("header_cert_url_host")
    return SignatureHeaders(
        transmission_id=need("paypal-transmission-id", _TOKEN),
        transmission_time=need("paypal-transmission-time", _TIME),
        transmission_sig=need("paypal-transmission-sig", _TOKEN),
        cert_url=cert,
        auth_algo=need("paypal-auth-algo", _ALGO),
    )


def parse_event(raw: bytes) -> Event:
    """Strictly parse a notification and extract its hint. Raises `MalformedEvent`."""
    if len(raw) > MAX_BODY_BYTES:
        raise MalformedEvent("body_too_large")
    try:
        body = loads_strict(raw, max_bytes=MAX_BODY_BYTES)
    except StrictJsonError as exc:
        raise MalformedEvent(f"json_{exc.code}"[:40]) from None
    if not isinstance(body, dict):
        raise MalformedEvent("body_not_object")
    event_id, event_type, resource = body.get("id"), body.get("event_type"), body.get("resource")
    if not isinstance(event_id, str) or not _EVENT_ID.fullmatch(event_id):
        raise MalformedEvent("event_id")
    if not isinstance(event_type, str) or not _EVENT_TYPE.fullmatch(event_type):
        raise MalformedEvent("event_type")
    if not isinstance(resource, dict):
        raise MalformedEvent("resource")
    return Event(event_id, event_type, _hint(event_type, resource))


def _checked(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return check_path_id(value, "id")
    except LimitError:
        return None


def _hint(event_type: str, resource: dict[str, Any]) -> Hint | None:
    if event_type in AUTHORIZATION_TYPES:
        found = _checked(resource.get("id"))
        return None if found is None else Hint("authorization", found)
    if event_type in CAPTURE_TYPES:
        found = _checked(resource.get("id"))
        return None if found is None else Hint("capture", found)
    if event_type in ORDER_TYPES:
        found = _checked(resource.get("id"))
        return None if found is None else Hint("order", found)
    if event_type in REFUND_TYPES:
        # The refund's own id is not enough to read anything; its `up` link names the capture.
        for link in resource.get("links") or []:
            if isinstance(link, dict) and link.get("rel") == "up":
                target = link_target(link.get("href"), "captures")
                if target is not None:
                    return Hint("capture", target)
        return None
    return None


def link_target(href: object, collection: str) -> str | None:
    """The id after `/<collection>/` in a PayPal link, if it has one and it is a valid id."""
    if not isinstance(href, str):
        return None
    segments = [s for s in urlsplit(href).path.split("/") if s]
    for index, segment in enumerate(segments[:-1]):
        if segment == collection:
            return _checked(segments[index + 1])
    return None

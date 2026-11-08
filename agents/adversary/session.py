"""An adversary session: HTTP calls against one target, every attempt logged.

The adversary speaks UCP and ACP over HTTP and nothing else. Two things are not its to do and come
from `Counterparties`: what the customer signed (the Trusted Surface and the customer's device key)
and the payer's approval at PayPal. `authorized=True` tells the provider the customer really signed
for this checkout; the adversary never learns more, and it never sees a verdict.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx

from agents.adversary.log import AttemptLog, body_shape

AP2_CAPABILITY = "dev.ucp.common.payment.ap2_mandate"
UCP_AGENT = {"UCP-Agent": 'profile="https://adversary.example/profile"'}
DELEGATION = "Countersign-Delegation"
CAPABILITIES = "Countersign-Capabilities"
ACP_PAYMENT = {
    "payment_data": {
        "handler_id": "h",
        "instrument": {"type": "card", "credential": {"type": "spt", "token": "t"}},
    }
}


@dataclass(frozen=True)
class Signed:
    """Customer-signed credentials for one checkout (opaque strings to the adversary)."""

    cm: str  # closed checkout mandate
    pm: str  # closed payment mandate
    open_cm: str
    open_pm: str
    nonce_cm: str
    nonce_pm: str


class Counterparties(Protocol):
    def delegation(self) -> str: ...

    def sign(
        self,
        checkout: dict[str, Any],
        *,
        authorized: bool = True,
        budget: int | None = None,
        reuse: Signed | None = None,
        nonces: tuple[str, str] | None = None,
    ) -> Signed: ...

    def payer_approves(self) -> None: ...


@dataclass(frozen=True)
class Reply:
    status: int
    body: Any
    code: str
    outcome: str  # the adversary's own reading: accepted, pending or refused

    @property
    def ok(self) -> bool:
        return self.status in (200, 201)

    @property
    def id(self) -> str:
        return str(self.body["id"]) if isinstance(self.body, dict) and "id" in self.body else ""

    @property
    def codes(self) -> list[str]:
        if not isinstance(self.body, dict):
            return []
        listed = self.body.get("messages")
        found = (
            [m.get("code") for m in listed if isinstance(m, dict)]
            if isinstance(listed, list)
            else []
        )
        return [str(c) for c in found if c]


def read(response: httpx.Response) -> Reply:
    try:
        body: Any = response.json()
    except ValueError:
        body = None
    codes = Reply(response.status_code, body, "", "").codes
    explicit = body.get("code") if isinstance(body, dict) and "status" not in body else None
    code = str(explicit or (codes[0] if codes else "") or f"http_{response.status_code}")
    pending = isinstance(body, dict) and (
        body.get("status") == "complete_in_progress" or "payer_approval_required" in codes
    )
    if pending:
        outcome = "pending"
    elif response.status_code in (200, 201) and not codes:
        outcome = "accepted"
    else:
        outcome = "refused"
    return Reply(response.status_code, body, code, outcome)


class Session:
    def __init__(
        self, http: httpx.Client, log: AttemptLog, parties: Counterparties, base: str = ""
    ) -> None:
        self.http, self.log, self.parties = http, log, parties
        self.base = base.rstrip("/")
        self.last: Reply | None = None
        self._ucp_root: str | None = None
        self._catalog: list[dict[str, Any]] | None = None
        self._serial = 0

    # ------------------------------------------------------------------ plumbing

    def send(self, step: str, method: str, path: str, **kwargs: Any) -> Reply:
        sent = kwargs.get("json", kwargs.get("content"))
        headers = {k.lower() for k in kwargs.get("headers", {})}
        response = self.http.request(method, self.base + path, **kwargs)
        reply = read(response)
        self.last = reply
        self.log.record(
            step=step, method=method, path=path, request=body_shape(sent),
            header_names=sorted(headers), status=reply.status, observed=reply.outcome, code=reply.code,
        )  # fmt: skip
        return reply

    def catalog(self) -> list[dict[str, Any]]:
        if self._catalog is None:
            reply = self.send("catalog", "GET", "/catalog")
            self._catalog = list(reply.body["items"]) if reply.ok else []
        return self._catalog

    def item(self, other_category: bool = False) -> str:
        items = self.catalog()
        first = items[0]
        if not other_category:
            return str(first["id"])
        return str(next(i for i in items if i["category"] != first["category"])["id"])

    def ucp_root(self) -> str:
        if self._ucp_root is None:
            reply = self.send("profile", "GET", "/.well-known/ucp")
            services = reply.body["ucp"]["services"]
            endpoint = str(next(iter(services.values()))[0]["endpoint"])
            self._ucp_root = urlparse(endpoint).path.rstrip("/")
        return self._ucp_root

    # ------------------------------------------------------------------ UCP

    def ucp_create(
        self, step: str, items: list[str], *, delegation: str | None = None, ap2: bool = False
    ) -> Reply:
        headers = dict(UCP_AGENT)
        if delegation:
            headers[DELEGATION] = delegation
        if ap2:
            headers[CAPABILITIES] = AP2_CAPABILITY
        lines = [{"item": {"id": i}, "quantity": 1} for i in items]
        return self.send(
            step, "POST", f"{self.ucp_root()}/checkout-sessions", json={"line_items": lines},
            headers=headers,
        )  # fmt: skip

    def ucp_complete(self, step: str, checkout_id: str, signed: Signed | None = None, *,
                     cm: str | None = None, with_payer: bool = True) -> Reply:  # fmt: skip
        body: dict[str, Any] = {}
        if signed is not None:
            body = {
                "ap2": {"checkout_mandate": cm or signed.cm},
                "payment": {"instruments": [{
                    "id": "instr_1", "handler_id": "countersign_ap2_payment_mandate", "type": "ap2",
                    "credential": {"type": "ap2_payment_mandate", "token": signed.pm},
                }]},
            }  # fmt: skip
        path = f"{self.ucp_root()}/checkout-sessions/{checkout_id}/complete"
        reply = self.send(step, "POST", path, json=body, headers=dict(UCP_AGENT))
        if with_payer and "payer_approval_required" in reply.codes:
            self.parties.payer_approves()
            reply = self.send(step + ".after_payer", "POST", path, json={}, headers=dict(UCP_AGENT))
        return reply

    def ucp_raw(self, step: str, content: bytes) -> Reply:
        return self.send(
            step, "POST", f"{self.ucp_root()}/checkout-sessions", content=content,
            headers={**UCP_AGENT, "Content-Type": "application/json"},
        )  # fmt: skip

    # ------------------------------------------------------------------ ACP

    def _acp_headers(self, delegation: str | None, capability: bool) -> dict[str, str]:
        self._serial += 1
        headers = {"Content-Type": "application/json", "Idempotency-Key": f"adv-{self._serial}"}
        if delegation:
            headers[DELEGATION] = delegation
        if capability:
            headers[CAPABILITIES] = AP2_CAPABILITY
        return headers

    def acp_create(self, step: str, delegation: str | None, *, capability: bool = False) -> Reply:
        body = {"line_items": [{"id": self.item(), "quantity": 1}], "currency": "usd",
                "capabilities": {}}  # fmt: skip
        return self.send(
            step, "POST", "/checkout_sessions", content=json.dumps(body).encode(),
            headers=self._acp_headers(delegation, capability),
        )  # fmt: skip

    def acp_complete(self, step: str, session_id: str, delegation: str | None) -> Reply:
        path = f"/checkout_sessions/{session_id}/complete"
        content = json.dumps(ACP_PAYMENT).encode()
        reply = self.send(step, "POST", path, content=content,
                          headers=self._acp_headers(delegation, False))  # fmt: skip
        if reply.status == 200 and reply.outcome == "pending":
            self.parties.payer_approves()
            reply = self.send(step + ".after_payer", "POST", path, content=content,
                              headers=self._acp_headers(delegation, False))  # fmt: skip
        return reply

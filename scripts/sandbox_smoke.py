"""PayPal sandbox smoke test.

Standalone: needs only httpx. Walks the call sequence the gateway relies on and prints, for every
response, the status, the PayPal debug id and the fields that matter to the design. The endpoints
and fields used are the ones recorded in docs/ENV.md section 2.

  Order 1: create (AUTHORIZE) -> payer approves -> authorize -> GET order -> GET authorization
           -> capture -> GET capture -> refund -> GET capture
  Order 2: create (AUTHORIZE) -> payer approves -> authorize -> void -> GET authorization

Run:  uv run python scripts/sandbox_smoke.py

Safety:
- Credentials come from .env (or the environment). The secret, the access token and the Basic
  auth value are never printed; every line of output passes through scrub() as a second guard.
- Output is a fixed allowlist of fields. Payer details are never read out of a response.
- Only the sandbox host is accepted. Nothing is written to disk.
- Any missing credential, HTTP error or unexpected shape stops the run with an explanation.
"""

from __future__ import annotations

import base64
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

SANDBOX_HOST = "api-m.sandbox.paypal.com"
ROOT = Path(__file__).resolve().parent.parent
REDACT: set[str] = set()


class SmokeError(Exception):
    """A step failed or something unexpected came back; the run stops here."""


# ---------------------------------------------------------------------------------------------
# Output hygiene


def scrub(text: str) -> str:
    for secret in REDACT:
        text = text.replace(secret, "[redacted]")
    return text


def out(line: str = "") -> None:
    print(scrub(line))


def step(title: str) -> None:
    out()
    out(f"=== {title}")


# ---------------------------------------------------------------------------------------------
# Configuration


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].strip()
        values[key.strip()] = value
    return values


def load_config() -> tuple[str, str, str]:
    env = parse_env_file(ROOT / ".env")
    env.update({k: v for k, v in os.environ.items() if k.startswith("PAYPAL_") and v})
    base = env.get("PAYPAL_API_BASE") or env.get("PAYPAL_BASE_URL") or ""
    client_id = env.get("PAYPAL_CLIENT_ID", "")
    secret = env.get("PAYPAL_CLIENT_SECRET", "")
    missing = [
        name
        for name, value in (
            ("PAYPAL_API_BASE", base),
            ("PAYPAL_CLIENT_ID", client_id),
            ("PAYPAL_CLIENT_SECRET", secret),
        )
        if not value
    ]
    if missing:
        raise SmokeError(f"missing in .env: {', '.join(missing)}")
    REDACT.update({secret, base64.b64encode(f"{client_id}:{secret}".encode()).decode()})
    parsed = urlparse(base)
    if parsed.scheme != "https" or parsed.hostname != SANDBOX_HOST:
        raise SmokeError(
            f"PAYPAL_API_BASE must be https://{SANDBOX_HOST} (got host {parsed.hostname!r})"
        )
    return f"https://{SANDBOX_HOST}", client_id, secret


# ---------------------------------------------------------------------------------------------
# HTTP


class PayPal:
    def __init__(self, base: str, client_id: str, secret: str) -> None:
        self.http = httpx.Client(base_url=base, timeout=30.0)
        self.client_id = client_id
        self.secret = secret
        self.token = ""

    def authenticate(self) -> None:
        step("1. OAuth client credentials   POST /v1/oauth2/token")
        resp = self.http.post(
            "/v1/oauth2/token",
            auth=(self.client_id, self.secret),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json"},
        )
        self.report(resp)
        body = self.json_or_fail(resp)
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise SmokeError("token response had no access_token")
        self.token = token
        REDACT.add(token)
        out(f"  token_type={body.get('token_type')} expires_in={body.get('expires_in')}s")

    def call(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        request_id: str | None = None,
        ok: tuple[int, ...] = (200, 201),
    ) -> tuple[httpx.Response, dict[str, Any]]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Prefer": "return=representation",
        }
        if request_id:
            headers["PayPal-Request-Id"] = request_id
        out(f"  -> {method} {path}" + (f"   PayPal-Request-Id={request_id}" if request_id else ""))
        resp = self.http.request(method, path, json=body, headers=headers)
        self.report(resp)
        if resp.status_code not in ok:
            raise SmokeError(self.describe_error(resp))
        data = resp.json() if resp.content else {}
        return resp, data if isinstance(data, dict) else {}

    def report(self, resp: httpx.Response) -> None:
        debug_id = resp.headers.get("paypal-debug-id")
        source = "header"
        if debug_id is None:
            source = "body"
            debug_id = self.safe_json(resp).get("debug_id", "n/a")
        out(f"  <- HTTP {resp.status_code}   debug_id={debug_id} ({source})")

    @staticmethod
    def safe_json(resp: httpx.Response) -> dict[str, Any]:
        try:
            data = resp.json()
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def json_or_fail(self, resp: httpx.Response) -> dict[str, Any]:
        if resp.status_code != 200:
            raise SmokeError(self.describe_error(resp))
        return self.safe_json(resp)

    def describe_error(self, resp: httpx.Response) -> str:
        body = self.safe_json(resp)
        parts = [f"HTTP {resp.status_code}"]
        for key in ("name", "error", "message", "error_description", "debug_id"):
            if isinstance(body.get(key), str):
                parts.append(f"{key}={body[key]}")
        for detail in body.get("details", []) or []:
            if isinstance(detail, dict):
                issue = {k: detail[k] for k in ("issue", "field", "description") if k in detail}
                parts.append(f"detail={issue}")
        if len(parts) == 1:
            parts.append("(no JSON error body)")
        return scrub("; ".join(parts))


# ---------------------------------------------------------------------------------------------
# Printing the fields that matter


def money(m: Any) -> str:
    if isinstance(m, dict):
        return f"{m.get('value')} {m.get('currency_code')}"
    return "n/a"


def show_authorization(label: str, auth: dict[str, Any]) -> None:
    out(
        f"  {label}: id={auth.get('id')} status={auth.get('status')} amount={money(auth.get('amount'))}"
    )
    out(f"    invoice_id={auth.get('invoice_id')} custom_id={auth.get('custom_id')}")
    out(f"    expiration_time={auth.get('expiration_time')} create_time={auth.get('create_time')}")
    seller = auth.get("seller_protection")
    if isinstance(seller, dict):
        out(f"    seller_protection.status={seller.get('status')}")
    out(f"    link rels: {link_rels(auth)}")


def show_money_object(label: str, obj: dict[str, Any]) -> None:
    out(
        f"  {label}: id={obj.get('id')} status={obj.get('status')} amount={money(obj.get('amount'))}"
    )
    out(f"    invoice_id={obj.get('invoice_id')} custom_id={obj.get('custom_id')}")
    if "final_capture" in obj:
        out(f"    final_capture={obj.get('final_capture')}")
    out(f"    link rels: {link_rels(obj)}")


def link_rels(obj: dict[str, Any]) -> list[str]:
    return [str(link.get("rel")) for link in obj.get("links", []) if isinstance(link, dict)]


def show_order(label: str, order: dict[str, Any]) -> None:
    out(
        f"  {label}: id={order.get('id')} status={order.get('status')} intent={order.get('intent')}"
    )
    units = order.get("purchase_units") or []
    out(f"    purchase_units={len(units)} link rels: {link_rels(order)}")
    for unit in units:
        if not isinstance(unit, dict):
            continue
        amount = unit.get("amount") or {}
        out(f"    reference_id={unit.get('reference_id')} amount={money(amount)}")
        breakdown = amount.get("breakdown") or {}
        for key in sorted(breakdown):
            out(f"      breakdown.{key}={money(breakdown[key])}")
        out(f"    invoice_id={unit.get('invoice_id')} custom_id={unit.get('custom_id')}")
        payee = unit.get("payee") or {}
        out(f"    payee.merchant_id={payee.get('merchant_id')}")
        for item in unit.get("items") or []:
            out(
                f"    item: name={item.get('name')!r} sku={item.get('sku')} qty={item.get('quantity')}"
                f" unit={money(item.get('unit_amount'))} tax={money(item.get('tax'))}"
            )
        payments = unit.get("payments") or {}
        for auth in payments.get("authorizations") or []:
            show_authorization("embedded authorization", auth)
        for cap in payments.get("captures") or []:
            show_money_object("embedded capture", cap)


def embedded_authorization(order: dict[str, Any]) -> dict[str, Any]:
    try:
        auth = order["purchase_units"][0]["payments"]["authorizations"][0]
    except (KeyError, IndexError, TypeError):
        raise SmokeError("authorize response had no purchase_units[0].payments.authorizations[0]")
    if not isinstance(auth, dict) or not isinstance(auth.get("id"), str):
        raise SmokeError("embedded authorization has no id")
    return auth


# ---------------------------------------------------------------------------------------------
# The flow


def order_body(run: str, tag: str) -> dict[str, Any]:
    """Two items with tax, so every breakdown member the design reverse-translates is present."""
    return {
        "intent": "AUTHORIZE",
        "purchase_units": [
            {
                "reference_id": "default",
                "invoice_id": f"cs-smoke-{run}-{tag}",
                "custom_id": f"cs1.smoke.{run}.{tag}",
                "description": "Countersign sandbox smoke test",
                "amount": {
                    "currency_code": "USD",
                    "value": "74.00",
                    "breakdown": {
                        "item_total": {"currency_code": "USD", "value": "68.50"},
                        "tax_total": {"currency_code": "USD", "value": "5.50"},
                    },
                },
                "items": [
                    {
                        "name": "Sample headphones",
                        "sku": "HP-100",
                        "quantity": "2",
                        "category": "DIGITAL_GOODS",
                        "unit_amount": {"currency_code": "USD", "value": "25.00"},
                        "tax": {"currency_code": "USD", "value": "2.00"},
                    },
                    {
                        "name": "Sample cable",
                        "sku": "CB-200",
                        "quantity": "1",
                        "category": "DIGITAL_GOODS",
                        "unit_amount": {"currency_code": "USD", "value": "18.50"},
                        "tax": {"currency_code": "USD", "value": "1.50"},
                    },
                ],
            }
        ],
        "payment_source": {
            "paypal": {
                "experience_context": {
                    "return_url": "https://example.com/return",
                    "cancel_url": "https://example.com/cancel",
                    "user_action": "PAY_NOW",
                    "shipping_preference": "NO_SHIPPING",
                    "payment_method_preference": "IMMEDIATE_PAYMENT_REQUIRED",
                }
            }
        },
    }


def create_and_approve(pp: PayPal, run: str, tag: str) -> str:
    request_id = f"cs-smoke-{run}-{tag}-create"
    _, order = pp.call(
        "POST", "/v2/checkout/orders", body=order_body(run, tag), request_id=request_id
    )
    show_order("created order", order)
    order_id = order.get("id")
    if not isinstance(order_id, str):
        raise SmokeError("create order returned no id")
    approval = next(
        (
            link
            for link in order.get("links", [])
            if isinstance(link, dict) and link.get("rel") in ("payer-action", "approve")
        ),
        None,
    )
    if approval is None:
        raise SmokeError(f"no approve or payer-action link; rels={link_rels(order)}")
    out()
    out(f"  Open this link and approve with the sandbox BUYER account (rel={approval['rel']}):")
    out(f"  {approval['href']}")
    out("  After approving you land on example.com. That is expected.")
    input("  Press Enter once approved (nothing is called until you do)... ")
    return order_id


def authorize(pp: PayPal, run: str, tag: str, order_id: str) -> dict[str, Any]:
    step(f"Authorize order   POST /v2/checkout/orders/{{id}}/authorize   [{tag}]")
    _, order = pp.call(
        "POST",
        f"/v2/checkout/orders/{order_id}/authorize",
        body={},
        request_id=f"cs-smoke-{run}-{tag}-authorize",
    )
    show_order("authorized order", order)
    return embedded_authorization(order)


def first_order(pp: PayPal, run: str) -> None:
    step("2. Order 1: create AUTHORIZE order   POST /v2/checkout/orders")
    order_id = create_and_approve(pp, run, "o1")
    auth = authorize(pp, run, "o1", order_id)
    auth_id = auth["id"]

    step("GET order   GET /v2/checkout/orders/{id}")
    _, order = pp.call("GET", f"/v2/checkout/orders/{order_id}")
    show_order("order after authorize", order)

    step("GET authorization   GET /v2/payments/authorizations/{id}")
    _, auth = pp.call("GET", f"/v2/payments/authorizations/{auth_id}")
    show_authorization("authorization", auth)

    step("Capture   POST /v2/payments/authorizations/{id}/capture")
    _, capture = pp.call(
        "POST",
        f"/v2/payments/authorizations/{auth_id}/capture",
        body={"final_capture": True},
        request_id=f"cs-smoke-{run}-o1-capture",
    )
    show_money_object("capture", capture)
    capture_id = capture.get("id")
    if not isinstance(capture_id, str):
        raise SmokeError("capture returned no id")

    step("GET capture   GET /v2/payments/captures/{id}")
    _, capture = pp.call("GET", f"/v2/payments/captures/{capture_id}")
    show_money_object("capture", capture)

    step("Refund (full)   POST /v2/payments/captures/{id}/refund")
    _, refund = pp.call(
        "POST",
        f"/v2/payments/captures/{capture_id}/refund",
        body={"note_to_payer": "Countersign sandbox smoke test"},
        request_id=f"cs-smoke-{run}-o1-refund",
    )
    show_money_object("refund", refund)

    step("GET capture after refund   GET /v2/payments/captures/{id}")
    _, capture = pp.call("GET", f"/v2/payments/captures/{capture_id}")
    show_money_object("capture", capture)


def second_order(pp: PayPal, run: str) -> None:
    step("3. Order 2: create AUTHORIZE order   POST /v2/checkout/orders")
    order_id = create_and_approve(pp, run, "o2")
    auth = authorize(pp, run, "o2", order_id)
    auth_id = auth["id"]

    step("Void   POST /v2/payments/authorizations/{id}/void")
    resp, voided = pp.call(
        "POST",
        f"/v2/payments/authorizations/{auth_id}/void",
        request_id=f"cs-smoke-{run}-o2-void",
        ok=(200, 204),
    )
    if resp.status_code == 204:
        out("  204 No Content (no body)")
    else:
        show_authorization("voided authorization", voided)

    step("GET authorization after void   GET /v2/payments/authorizations/{id}")
    _, auth = pp.call("GET", f"/v2/payments/authorizations/{auth_id}")
    show_authorization("authorization", auth)


def main() -> int:
    try:
        base, client_id, secret = load_config()
        out(f"PayPal sandbox smoke test   host={SANDBOX_HOST}")
        run = f"{int(time.time())}-{uuid.uuid4().hex[:6]}"
        out(f"run id: {run}")
        pp = PayPal(base, client_id, secret)
        pp.authenticate()
        first_order(pp, run)
        second_order(pp, run)
    except SmokeError as exc:
        out()
        out(f"STOPPED: {exc}")
        return 1
    except httpx.HTTPError as exc:
        out()
        out(f"STOPPED: network error: {type(exc).__name__}")
        return 1
    except (EOFError, KeyboardInterrupt):
        out()
        out("STOPPED: interrupted")
        return 130
    out()
    out("DONE: both flows completed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

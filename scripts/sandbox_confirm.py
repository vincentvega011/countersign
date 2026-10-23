"""PayPal sandbox behaviour confirmations (Day 0).

Companion to sandbox_smoke.py, same safety rules: sandbox host only, secrets and tokens scrubbed
from every line, an allowlist of printed fields, no payer details, nothing written to disk, and a
pause for you to approve each order with the sandbox buyer. Unlike the smoke test, an HTTP error
here is a result to record, not a reason to stop.

Sections (each is independent; --only picks some, default is all):

  limits  A. custom_id and invoice_id at and above the documented maximum, the PayPal-Request-Id
             length limit, and a duplicate invoice_id. No approval needed.
  o1      B. Idempotent replay of create, authorize and capture; PATCH after authorization;
             partial capture, over-capture, capture after a final capture, void after capture;
             partial refund, over-refund, refund of an already refunded capture. 1 approval.
  o2      C. PATCH while the order is APPROVED but not yet authorized. 1 approval.
  o3      D. Capture of a voided authorization, a second void, a replayed void. 1 approval.
  vault   E. Whether the sandbox wallet can be vaulted and an order then created from the vault
             id without the payer approving again. 1 approval (the second order needs none if
             vaulting works).

  o4      F. While the order is APPROVED: PATCH invoice_id, then PATCH items and amount up from
             74.00 to 100.00 consistently, authorize and record the authorized amount, void.
             1 approval. Not part of the default run; use --only o4.

Webhook facts are documentation, not API calls, so they are not exercised here.

Run:  uv run python scripts/sandbox_confirm.py [--only limits,o1,o2,o3,vault,o4]

The tail of the output is a SUMMARY block of one line per call. Paste the whole output back.
"""

from __future__ import annotations

import argparse
import copy
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
from sandbox_smoke import (
    REDACT,
    PayPal,
    SmokeError,
    link_rels,
    load_config,
    money,
    order_body,
    out,
    step,
)

BASE = "/purchase_units/@reference_id=='default'"
SUMMARY: list[str] = []


@dataclass
class Result:
    status: int
    body: dict[str, Any]
    debug_id: str


# ---------------------------------------------------------------------------------------------
# Calls and printing


def label(status: int, body: dict[str, Any]) -> str:
    if status >= 400:
        parts = [f"name={body.get('name') or body.get('error')}"]
        for d in body.get("details") or []:
            if isinstance(d, dict):
                parts.append(f"issue={d.get('issue')}")
                if d.get("field"):
                    parts.append(f"field={d.get('field')}")
        msg = body.get("message")
        if isinstance(msg, str):
            parts.append(f"message={msg[:160]!r}")
        return " ".join(parts)
    if body.get("id") or body.get("status"):
        return f"id={body.get('id')} status={body.get('status')}"
    return "(no body)"


def probe(
    pp: PayPal,
    key: str,
    method: str,
    path: str,
    *,
    body: Any = None,
    request_id: str | None = None,
    note: str = "",
) -> Result:
    headers = {"Authorization": f"Bearer {pp.token}", "Accept": "application/json"}
    if method == "POST":
        headers["Prefer"] = "return=representation"
    if request_id:
        headers["PayPal-Request-Id"] = request_id
    resp = pp.http.request(method, path, json=body, headers=headers)
    if resp.status_code == 401:
        raise SmokeError("401 from PayPal: token rejected or expired")
    data = PayPal.safe_json(resp)
    header_id = resp.headers.get("paypal-debug-id")
    debug_id = header_id if header_id else f"body:{data.get('debug_id')}"
    text = label(resp.status_code, data)
    rid = f" request_id_len={len(request_id)}" if request_id else ""
    out(f"  [{key}] {note}")
    out(f"        {method} {path}{rid}")
    out(f"        -> HTTP {resp.status_code} {text}  debug_id={debug_id}")
    SUMMARY.append(f"{key} | {note} | HTTP {resp.status_code} | {text}")
    return Result(resp.status_code, data, debug_id)


def ok(r: Result) -> bool:
    return 200 <= r.status < 300


def need_id(r: Result, key: str) -> str:
    value = r.body.get("id")
    if not ok(r) or not isinstance(value, str):
        raise SmokeError(f"{key}: needed a successful response with an id (HTTP {r.status})")
    return value


def ident(name: str, got: Any, sent: str | None = None) -> str:
    if not isinstance(got, str):
        return f"{name}={got}"
    shown = got if len(got) <= 60 else f"<{len(got)} chars>"
    extra = f", unchanged={got == sent}" if sent is not None else ""
    return f"{name}={shown} (len={len(got)}{extra})"


def unit_of(order: dict[str, Any]) -> dict[str, Any]:
    units = order.get("purchase_units") or []
    return units[0] if units and isinstance(units[0], dict) else {}


def auth_of(order: dict[str, Any]) -> dict[str, Any]:
    auths = (unit_of(order).get("payments") or {}).get("authorizations") or []
    return auths[0] if auths and isinstance(auths[0], dict) else {}


def brief_order(o: dict[str, Any]) -> None:
    u = unit_of(o)
    out(
        f"        order status={o.get('status')} amount={money(u.get('amount'))}"
        f" items={len(u.get('items') or [])} description={u.get('description')!r}"
    )
    out(
        f"        {ident('custom_id', u.get('custom_id'))}  {ident('invoice_id', u.get('invoice_id'))}"
    )
    a = auth_of(o)
    if a:
        brief_auth(a)


def brief_auth(a: dict[str, Any]) -> None:
    out(
        f"        authorization id={a.get('id')} status={a.get('status')}"
        f" amount={money(a.get('amount'))} expiration_time={a.get('expiration_time')}"
    )
    out(
        f"        {ident('custom_id', a.get('custom_id'))}  {ident('invoice_id', a.get('invoice_id'))}"
    )


def brief_capture(c: dict[str, Any]) -> None:
    out(
        f"        capture id={c.get('id')} status={c.get('status')} amount={money(c.get('amount'))}"
        f" final_capture={c.get('final_capture')}"
    )


def get_auth(pp: PayPal, key: str, auth_id: str, note: str = "GET authorization") -> Result:
    r = probe(pp, key, "GET", f"/v2/payments/authorizations/{auth_id}", note=note)
    if ok(r):
        brief_auth(r.body)
    return r


def get_capture(pp: PayPal, key: str, cap_id: str, note: str = "GET capture") -> Result:
    r = probe(pp, key, "GET", f"/v2/payments/captures/{cap_id}", note=note)
    if ok(r):
        brief_capture(r.body)
    return r


def get_order(pp: PayPal, key: str, order_id: str, note: str = "GET order") -> Result:
    r = probe(pp, key, "GET", f"/v2/checkout/orders/{order_id}", note=note)
    if ok(r):
        brief_order(r.body)
    return r


# ---------------------------------------------------------------------------------------------
# Order bodies and the approval pause


def simple_order(run: str, tag: str, amount: str = "74.00") -> dict[str, Any]:
    """Amount only, no items, so PATCH of the amount is not blocked by an item breakdown check."""
    full = order_body(run, tag)
    return {
        "intent": "AUTHORIZE",
        "purchase_units": [
            {
                "reference_id": "default",
                "invoice_id": f"cs-confirm-{run}-{tag}",
                "custom_id": f"cs1.confirm.{run}.{tag}",
                "description": "Countersign sandbox confirmation",
                "amount": {"currency_code": "USD", "value": amount},
            }
        ],
        "payment_source": copy.deepcopy(full["payment_source"]),
    }


def approve(r: Result) -> None:
    link = next(
        (
            x
            for x in r.body.get("links", [])
            if isinstance(x, dict) and x.get("rel") in ("payer-action", "approve")
        ),
        None,
    )
    if link is None:
        raise SmokeError(f"no approval link; rels={link_rels(r.body)}")
    out()
    out(f"  Open and approve with the sandbox BUYER account (rel={link['rel']}):")
    out(f"  {link['href']}")
    input("  Press Enter once approved (nothing is called until you do)... ")


def amount_body(value: str, final: bool | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"amount": {"currency_code": "USD", "value": value}}
    if final is not None:
        body["final_capture"] = final
    return body


# ---------------------------------------------------------------------------------------------
# A. limits


def pad(prefix: str, n: int) -> str:
    return (prefix + "x" * n)[:n]


def sec_limits(pp: PayPal, run: str) -> None:
    step("A. custom_id, invoice_id and PayPal-Request-Id limits (create only, no approval)")
    for key, field, n in (
        ("L01", "custom_id", 255),
        ("L02", "custom_id", 256),
        ("L03", "invoice_id", 127),
        ("L04", "invoice_id", 128),
    ):
        body = simple_order(run, key.lower())
        sent = pad(f"{field[0]}{run}-{key}-", n)
        body["purchase_units"][0][field] = sent
        r = probe(
            pp,
            key,
            "POST",
            "/v2/checkout/orders",
            body=body,
            request_id=f"cs-confirm-{run}-{key}",
            note=f"create with {field} of {n} characters",
        )
        if ok(r):
            out(f"        returned {ident(field, unit_of(r.body).get(field), sent)}")

    for key, rid, note in (
        ("Q01", pad(f"cs-confirm-{run}-Q01-", 108), "PayPal-Request-Id of 108 characters"),
        ("Q02", pad(f"cs-confirm-{run}-Q02-", 109), "PayPal-Request-Id of 109 characters"),
        ("Q03", f"cs1:{run}:checkout_x:create", "PayPal-Request-Id with colons (cs1:<id>:<op>)"),
    ):
        probe(
            pp,
            key,
            "POST",
            "/v2/checkout/orders",
            body=simple_order(run, key.lower()),
            request_id=rid,
            note=note,
        )

    dup = simple_order(run, "dup")
    probe(
        pp, "D01", "POST", "/v2/checkout/orders", body=dup,
        request_id=f"cs-confirm-{run}-D01", note="create with a fresh invoice_id",
    )  # fmt: skip
    probe(
        pp, "D02", "POST", "/v2/checkout/orders", body=dup,
        request_id=f"cs-confirm-{run}-D02",
        note="create again, same invoice_id, different Request-Id",
    )  # fmt: skip


# ---------------------------------------------------------------------------------------------
# B. replay, PATCH after authorization, partial capture and refund


def sec_o1(pp: PayPal, run: str) -> None:
    step("B. Order 1: replay, PATCH after authorization, partial capture and refund")
    body = simple_order(run, "o1")
    rid = f"cs-confirm-{run}-o1-create"
    r1 = probe(pp, "I01", "POST", "/v2/checkout/orders", body=body, request_id=rid, note="create")
    order_id = need_id(r1, "I01")
    r2 = probe(
        pp, "I02", "POST", "/v2/checkout/orders", body=body, request_id=rid,
        note="create replayed, same Request-Id, same body",
    )  # fmt: skip
    out(f"        same order id as I01: {r2.body.get('id') == order_id}")
    body3 = copy.deepcopy(body)
    body3["purchase_units"][0]["amount"]["value"] = "75.00"
    r3 = probe(
        pp, "I03", "POST", "/v2/checkout/orders", body=body3, request_id=rid,
        note="create, same Request-Id, DIFFERENT amount (75.00)",
    )  # fmt: skip
    out(
        f"        same order id as I01: {r3.body.get('id') == order_id};"
        f" amount in response: {money(unit_of(r3.body).get('amount'))}"
    )

    approve(r1)

    ra = f"cs-confirm-{run}-o1-authorize"
    path = f"/v2/checkout/orders/{order_id}/authorize"
    a1 = probe(pp, "I04", "POST", path, body={}, request_id=ra, note="authorize")
    auth = auth_of(a1.body)
    auth_id = auth.get("id")
    if not ok(a1) or not isinstance(auth_id, str):
        raise SmokeError(f"I04: authorize did not yield an authorization (HTTP {a1.status})")
    brief_auth(auth)
    a2 = probe(
        pp, "I05", "POST", path, body={}, request_id=ra,
        note="authorize replayed, same Request-Id",
    )  # fmt: skip
    out(f"        same authorization id as I04: {auth_of(a2.body).get('id') == auth_id}")
    probe(
        pp, "I06", "POST", path, body={}, request_id=f"{ra}-again",
        note="authorize an already authorized order, new Request-Id",
    )  # fmt: skip
    get_order(pp, "I07", order_id, "GET order after authorize")
    get_auth(pp, "I08", auth_id)

    # PATCH after authorization, one field at a time.
    patches: list[tuple[str, str, Any]] = [
        ("T01", "custom_id", f"cs1.patched.{run}"),
        ("T02", "invoice_id", f"cs-confirm-{run}-o1-patched"),
        ("T03", "description", "patched description"),
        ("T04", "amount", {"currency_code": "USD", "value": "80.00"}),
    ]
    for key, field, value in patches:
        ops = [{"op": "replace", "path": f"{BASE}/{field}", "value": value}]
        r = probe(
            pp, key, "PATCH", f"/v2/checkout/orders/{order_id}", body=ops,
            note=f"PATCH {field} after authorization",
        )  # fmt: skip
        if ok(r):
            get_order(pp, f"{key}g", order_id, f"GET order after PATCH {field}")
            get_auth(pp, f"{key}a", auth_id, f"GET authorization after PATCH {field}")
    get_auth(pp, "T05", auth_id, "GET authorization after all PATCH attempts")

    # Partial and over-capture, final capture, capture after final capture.
    cap_path = f"/v2/payments/authorizations/{auth_id}/capture"
    rc1 = f"cs-confirm-{run}-o1-cap1"
    c1 = probe(
        pp, "C01", "POST", cap_path, body=amount_body("30.00", False), request_id=rc1,
        note="capture 30.00 with final_capture=false",
    )  # fmt: skip
    cap1 = need_id(c1, "C01")
    brief_capture(c1.body)
    c1r = probe(
        pp, "C02", "POST", cap_path, body=amount_body("30.00", False), request_id=rc1,
        note="capture replayed, same Request-Id",
    )  # fmt: skip
    out(f"        same capture id as C01: {c1r.body.get('id') == cap1}")
    get_auth(pp, "C03", auth_id, "GET authorization after partial capture")
    probe(
        pp, "C04", "POST", cap_path, body=amount_body("20.00", False),
        request_id=f"cs-confirm-{run}-o1-cap2", note="second partial capture 20.00",
    )  # fmt: skip
    probe(
        pp, "C05", "POST", cap_path, body=amount_body("40.00", False),
        request_id=f"cs-confirm-{run}-o1-cap3",
        note="capture 40.00 when 24.00 remains (over-capture)",
    )  # fmt: skip
    probe(
        pp, "C06", "POST", cap_path, body=amount_body("24.00", True),
        request_id=f"cs-confirm-{run}-o1-cap4", note="final capture 24.00 with final_capture=true",
    )  # fmt: skip
    get_auth(pp, "C07", auth_id, "GET authorization after final capture")
    probe(
        pp, "C08", "POST", cap_path, body=amount_body("1.00", False),
        request_id=f"cs-confirm-{run}-o1-cap5", note="capture 1.00 after the final capture",
    )  # fmt: skip
    probe(
        pp, "C09", "POST", f"/v2/payments/authorizations/{auth_id}/void",
        request_id=f"cs-confirm-{run}-o1-void", note="void an authorization that was fully captured",
    )  # fmt: skip

    # Refunds against the first capture (30.00).
    ref_path = f"/v2/payments/captures/{cap1}/refund"
    rr1 = f"cs-confirm-{run}-o1-ref1"
    probe(
        pp, "F01", "POST", ref_path, body=amount_body("10.00"), request_id=rr1,
        note="partial refund 10.00 of the 30.00 capture",
    )  # fmt: skip
    probe(
        pp, "F02", "POST", ref_path, body=amount_body("10.00"), request_id=rr1,
        note="partial refund replayed, same Request-Id",
    )  # fmt: skip
    get_capture(pp, "F03", cap1, "GET capture after partial refund")
    probe(
        pp, "F04", "POST", ref_path, body=amount_body("25.00"),
        request_id=f"cs-confirm-{run}-o1-ref3", note="refund 25.00 when 20.00 remains (over-refund)",
    )  # fmt: skip
    probe(
        pp, "F05", "POST", ref_path, body={}, request_id=f"cs-confirm-{run}-o1-ref4",
        note="refund with empty body after a partial refund (what amount is refunded?)",
    )  # fmt: skip
    get_capture(pp, "F06", cap1, "GET capture after refunding the rest")
    probe(
        pp, "F07", "POST", ref_path, body={}, request_id=f"cs-confirm-{run}-o1-ref5",
        note="refund a capture that is already fully refunded",
    )  # fmt: skip


# ---------------------------------------------------------------------------------------------
# C. PATCH while APPROVED


def sec_o2(pp: PayPal, run: str) -> None:
    step("C. Order 2: PATCH after approval, before authorization")
    sent = order_body(run, "o2")
    r = probe(
        pp, "A01", "POST", "/v2/checkout/orders", body=sent,
        request_id=f"cs-confirm-{run}-o2-create", note="create (two items, 74.00)",
    )  # fmt: skip
    order_id = need_id(r, "A01")
    approve(r)
    get_order(pp, "A02", order_id, "GET order after approval")

    ops_id = [{"op": "replace", "path": f"{BASE}/custom_id", "value": f"cs1.patched.{run}"}]
    p1 = probe(
        pp, "A03", "PATCH", f"/v2/checkout/orders/{order_id}", body=ops_id,
        note="PATCH custom_id while APPROVED",
    )  # fmt: skip
    if ok(p1):
        get_order(pp, "A03g", order_id, "GET order after PATCH custom_id")

    ops_items = [
        {
            "op": "replace",
            "path": f"{BASE}/items",
            "value": [
                {
                    "name": "Sample headphones",
                    "sku": "HP-100",
                    "quantity": "1",
                    "category": "DIGITAL_GOODS",
                    "unit_amount": {"currency_code": "USD", "value": "25.00"},
                    "tax": {"currency_code": "USD", "value": "2.00"},
                }
            ],
        },
        {
            "op": "replace",
            "path": f"{BASE}/amount",
            "value": {
                "currency_code": "USD",
                "value": "27.00",
                "breakdown": {
                    "item_total": {"currency_code": "USD", "value": "25.00"},
                    "tax_total": {"currency_code": "USD", "value": "2.00"},
                },
            },
        },
    ]
    p2 = probe(
        pp, "A04", "PATCH", f"/v2/checkout/orders/{order_id}", body=ops_items,
        note="PATCH items and amount together (74.00 down to 27.00) while APPROVED",
    )  # fmt: skip
    if ok(p2):
        get_order(pp, "A04g", order_id, "GET order after PATCH items and amount")

    a = probe(
        pp, "A05", "POST", f"/v2/checkout/orders/{order_id}/authorize", body={},
        request_id=f"cs-confirm-{run}-o2-authorize",
        note="authorize (which amount does PayPal authorize?)",
    )  # fmt: skip
    auth = auth_of(a.body)
    if ok(a) and isinstance(auth.get("id"), str):
        brief_auth(auth)
        probe(
            pp, "A06", "POST", f"/v2/payments/authorizations/{auth['id']}/void",
            request_id=f"cs-confirm-{run}-o2-void", note="void it (cleanup)",
        )  # fmt: skip


# ---------------------------------------------------------------------------------------------
# D. void edge cases


def sec_o3(pp: PayPal, run: str) -> None:
    step("D. Order 3: voided authorization edge cases")
    r = probe(
        pp, "V01", "POST", "/v2/checkout/orders", body=simple_order(run, "o3"),
        request_id=f"cs-confirm-{run}-o3-create", note="create",
    )  # fmt: skip
    order_id = need_id(r, "V01")
    approve(r)
    a = probe(
        pp, "V02", "POST", f"/v2/checkout/orders/{order_id}/authorize", body={},
        request_id=f"cs-confirm-{run}-o3-authorize", note="authorize",
    )  # fmt: skip
    auth_id = auth_of(a.body).get("id")
    if not ok(a) or not isinstance(auth_id, str):
        raise SmokeError(f"V02: authorize did not yield an authorization (HTTP {a.status})")
    void_path = f"/v2/payments/authorizations/{auth_id}/void"
    rv = f"cs-confirm-{run}-o3-void"
    probe(pp, "V03", "POST", void_path, request_id=rv, note="void")
    get_auth(pp, "V04", auth_id, "GET authorization after void")
    probe(
        pp, "V05", "POST", f"/v2/payments/authorizations/{auth_id}/capture", body={},
        request_id=f"cs-confirm-{run}-o3-cap", note="capture a voided authorization",
    )  # fmt: skip
    probe(
        pp, "V06", "POST", void_path, request_id=f"cs-confirm-{run}-o3-void2",
        note="second void, new Request-Id",
    )  # fmt: skip
    probe(pp, "V07", "POST", void_path, request_id=rv, note="void replayed, same Request-Id")


# ---------------------------------------------------------------------------------------------
# E. vault


def mask(value: str) -> str:
    return f"{value[:3]}***(len {len(value)})"


def vault_of(order: dict[str, Any]) -> dict[str, Any]:
    paypal = (order.get("payment_source") or {}).get("paypal") or {}
    vault = (paypal.get("attributes") or {}).get("vault") or {}
    return vault if isinstance(vault, dict) else {}


def sec_vault(pp: PayPal, run: str) -> None:
    step("E. Vaulting a sandbox wallet for a later order without payer approval")
    body = simple_order(run, "w1")
    body["payment_source"]["paypal"]["attributes"] = {
        "vault": {
            "store_in_vault": "ON_SUCCESS",
            "usage_type": "MERCHANT",
            "customer_type": "CONSUMER",
        }
    }
    r = probe(
        pp, "W01", "POST", "/v2/checkout/orders", body=body,
        request_id=f"cs-confirm-{run}-w1-create",
        note="create with payment_source.paypal.attributes.vault (store_in_vault ON_SUCCESS)",
    )  # fmt: skip
    if not ok(r):
        out("        vaulting was refused at create; no further vault steps")
        return
    order_id = need_id(r, "W01")
    approve(r)
    a = probe(
        pp, "W02", "POST", f"/v2/checkout/orders/{order_id}/authorize", body={},
        request_id=f"cs-confirm-{run}-w1-authorize", note="authorize the vaulting order",
    )  # fmt: skip
    first_auth = auth_of(a.body).get("id")
    paypal_keys = sorted(((a.body.get("payment_source") or {}).get("paypal") or {}).keys())
    out(f"        payment_source.paypal keys in the response: {paypal_keys}")
    vault = vault_of(a.body)
    if not vault:
        g = get_order(pp, "W03", order_id, "GET order, looking for the vault block")
        vault = vault_of(g.body)
    vault_id = vault.get("id")
    out(
        f"        vault status={vault.get('status')} vault id={mask(vault_id) if vault_id else None}"
    )
    if isinstance(vault_id, str):
        REDACT.add(vault_id)
    if isinstance(first_auth, str):
        probe(
            pp, "W04", "POST", f"/v2/payments/authorizations/{first_auth}/void",
            request_id=f"cs-confirm-{run}-w1-void", note="void the first authorization (cleanup)",
        )  # fmt: skip
    if not isinstance(vault_id, str):
        out("        no vault id was returned; cannot try a vaulted order")
        SUMMARY.append("W05 | no vault id returned after approval and authorize | n/a | n/a")
        return

    b2 = simple_order(run, "w2")
    b2["payment_source"] = {
        "paypal": {
            "vault_id": vault_id,
            "stored_credential": {
                "payment_initiator": "MERCHANT",
                "payment_type": "UNSCHEDULED",
                "usage": "SUBSEQUENT",
            },
        }
    }
    r2 = probe(
        pp, "W05", "POST", "/v2/checkout/orders", body=b2,
        request_id=f"cs-confirm-{run}-w2-create",
        note="create from the vault id, no payer approval, MERCHANT / UNSCHEDULED / SUBSEQUENT",
    )  # fmt: skip
    out(f"        link rels: {link_rels(r2.body)}")
    if not ok(r2):
        return
    if r2.body.get("status") == "PAYER_ACTION_REQUIRED":
        out(
            "        PayPal requires payer action for the vaulted order; autonomous charge not shown"
        )
        return
    order2 = need_id(r2, "W05")
    auth = auth_of(r2.body)
    if not auth:
        a2 = probe(
            pp, "W06", "POST", f"/v2/checkout/orders/{order2}/authorize", body={},
            request_id=f"cs-confirm-{run}-w2-authorize", note="authorize the vaulted order",
        )  # fmt: skip
        auth = auth_of(a2.body)
    else:
        brief_auth(auth)
    if isinstance(auth.get("id"), str):
        probe(
            pp, "W07", "POST", f"/v2/payments/authorizations/{auth['id']}/void",
            request_id=f"cs-confirm-{run}-w2-void", note="void the vaulted order's authorization (cleanup)",
        )  # fmt: skip


# ---------------------------------------------------------------------------------------------


def sec_o4(pp: PayPal, run: str) -> None:
    step("F. Order 4: PATCH invoice_id, then items and amount up to 100.00, while APPROVED")
    r = probe(
        pp,
        "H01",
        "POST",
        "/v2/checkout/orders",
        body=order_body(run, "o4"),
        request_id=f"cs-confirm-{run}-o4-create",
        note="create (two items, 74.00)",
    )
    order_id = need_id(r, "H01")
    approve(r)
    get_order(pp, "H02", order_id, "GET order after approval")

    new_invoice = f"cs-confirm-{run}-o4-patched"
    p1 = probe(
        pp,
        "H03",
        "PATCH",
        f"/v2/checkout/orders/{order_id}",
        body=[{"op": "replace", "path": f"{BASE}/invoice_id", "value": new_invoice}],
        note="PATCH invoice_id while APPROVED",
    )
    if ok(p1):
        g = get_order(pp, "H04", order_id, "GET order after PATCH invoice_id")
        out(
            f"        invoice_id now the patched value: {unit_of(g.body).get('invoice_id') == new_invoice}"
        )

    usd = "USD"
    ops = [
        {
            "op": "replace",
            "path": f"{BASE}/items",
            "value": [
                {
                    "name": "Sample headphones",
                    "sku": "HP-100",
                    "quantity": "2",
                    "category": "DIGITAL_GOODS",
                    "unit_amount": {"currency_code": usd, "value": "35.00"},
                    "tax": {"currency_code": usd, "value": "3.00"},
                },
                {
                    "name": "Sample cable",
                    "sku": "CB-200",
                    "quantity": "1",
                    "category": "DIGITAL_GOODS",
                    "unit_amount": {"currency_code": usd, "value": "22.00"},
                    "tax": {"currency_code": usd, "value": "2.00"},
                },
            ],
        },
        {
            "op": "replace",
            "path": f"{BASE}/amount",
            "value": {
                "currency_code": usd,
                "value": "100.00",
                "breakdown": {
                    "item_total": {"currency_code": usd, "value": "92.00"},
                    "tax_total": {"currency_code": usd, "value": "8.00"},
                },
            },
        },
    ]
    p2 = probe(
        pp,
        "H05",
        "PATCH",
        f"/v2/checkout/orders/{order_id}",
        body=ops,
        note="PATCH items and amount together (74.00 up to 100.00, consistent) while APPROVED",
    )
    if ok(p2):
        get_order(pp, "H06", order_id, "GET order after PATCH items and amount")

    a = probe(
        pp,
        "H07",
        "POST",
        f"/v2/checkout/orders/{order_id}/authorize",
        body={},
        request_id=f"cs-confirm-{run}-o4-authorize",
        note="authorize (which amount is authorized?)",
    )
    auth = auth_of(a.body)
    if ok(a) and isinstance(auth.get("id"), str):
        brief_auth(auth)
        probe(
            pp,
            "H08",
            "POST",
            f"/v2/payments/authorizations/{auth['id']}/void",
            request_id=f"cs-confirm-{run}-o4-void",
            note="void it (cleanup)",
        )


SECTIONS = {
    "limits": sec_limits,
    "o1": sec_o1,
    "o2": sec_o2,
    "o3": sec_o3,
    "vault": sec_vault,
    "o4": sec_o4,
}
APPROVALS = {"limits": 0, "o1": 1, "o2": 1, "o3": 1, "vault": 1, "o4": 1}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--only",
        default=",".join(s for s in SECTIONS if s != "o4"),
        help="comma-separated sections",
    )
    chosen = [s.strip() for s in parser.parse_args().only.split(",") if s.strip()]
    unknown = [s for s in chosen if s not in SECTIONS]
    if unknown:
        out(f"unknown section(s): {', '.join(unknown)}; choose from {', '.join(SECTIONS)}")
        return 2
    try:
        base, client_id, secret = load_config()
        run = f"{int(time.time())}-{uuid.uuid4().hex[:6]}"
        out(f"PayPal sandbox confirmations   run id: {run}")
        out(
            f"sections: {', '.join(chosen)}   approvals needed: {sum(APPROVALS[s] for s in chosen)}"
        )
        pp = PayPal(base, client_id, secret)
        pp.authenticate()
        for name in chosen:
            try:
                SECTIONS[name](pp, run)
            except SmokeError as exc:
                out(f"  SECTION {name} STOPPED: {exc}")
                SUMMARY.append(f"SECTION {name} STOPPED | {exc}")
    except SmokeError as exc:
        out(f"STOPPED: {exc}")
        return 1
    except httpx.HTTPError as exc:
        out(f"STOPPED: network error: {type(exc).__name__}")
        return 1
    except (EOFError, KeyboardInterrupt):
        out("STOPPED: interrupted")
        return 130
    finally:
        if SUMMARY:
            out()
            out("=== SUMMARY (one line per call)")
            for line in SUMMARY:
                out(line)
    out()
    out("DONE. Sandbox vault tokens, if any were created, remain in the sandbox account.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

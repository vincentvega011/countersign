"""The shopping agent: goal in, purchase out, over HTTP only (Decision 98).

Flow: goal to a checked wish (model call 1), search, choose one result (model call 2), file a proposal
signed with the agent key, wait for the customer's consent on the phone page, fetch the issued open
mandates by proving the key, build the checkout over UCP, verify `merchant_authorization` before trusting
anything, sign the closed mandates chained to the open ones, complete, and report. Everything except the
two model calls is deterministic, and the service verifies every signature again (INV-1).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

from agents.shopper import wire
from agents.shopper.client import HANDLER_ID, ServiceClient, ServiceError
from agents.shopper.keys import AgentKey
from agents.shopper.plan import PlanError, candidates, choose_item, plan_wish
from countersign.llm import LlmGateway

CONSENT_TIMEOUT_S = 300.0
POLL_S = 2.0
REJECTED_CODE = "checkout_canceled_after_rejection"
INSTRUMENT = {"id": "paypal-sandbox-wallet", "type": "paypal"}


class ShopperError(Exception):
    """The run stopped. `code` is stable; nothing was bought unless the result says so."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class ShopperResult:
    outcome: str  # completed, rejected, payer_approval_pending
    checkout_id: str | None
    amount_minor: int | None
    currency: str | None
    capture_id: str | None
    proposal_id: str
    attempts: int
    codes: list[str] = field(default_factory=list)
    receipts: dict[str, Any] = field(default_factory=dict)
    payer_approval_url: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def summary(result: ShopperResult) -> str:
    if result.outcome == "completed":
        total = f"{(result.amount_minor or 0) / 100:.2f} {result.currency}"
        return (
            f"Bought: checkout {result.checkout_id}, {total}, PayPal capture {result.capture_id}, "
            f"{result.attempts} attempt(s)."
        )
    if result.outcome == "payer_approval_pending":
        return f"Waiting for the payer to approve on PayPal: {result.payer_approval_url}"
    return f"Not bought: {', '.join(result.codes) or 'rejected'} (checkout {result.checkout_id})."


def _receipt_claims(token: object, keys: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Verify a receipt's signature with the merchant's published keys and return its claims."""
    if not isinstance(token, str) or token.count(".") != 2:
        return None
    header_part, payload_part, signature_part = token.split(".")
    try:
        header = json.loads(wire.unb64(header_part))
        claims = json.loads(wire.unb64(payload_part))
    except (ValueError, wire.WireError):
        return None
    match = [k for k in keys if k.get("kid") == header.get("kid")]
    if header.get("alg") != "ES256" or len(match) != 1 or not isinstance(claims, dict):
        return None
    if not wire.verify_es256(match[0], f"{header_part}.{payload_part}".encode(), signature_part):
        return None
    return claims


def _total(body: dict[str, Any]) -> tuple[int, str]:
    totals = [t for t in body.get("totals", []) if isinstance(t, dict) and t.get("type") == "total"]
    amount = totals[0].get("amount") if len(totals) == 1 else None
    if type(amount) is not int or amount <= 0 or not isinstance(body.get("currency"), str):
        raise ShopperError("checkout_total_invalid")
    return amount, str(body["currency"])


def _codes(body: dict[str, Any]) -> list[str]:
    return [
        str(m["code"])
        for m in body.get("messages", [])
        if isinstance(m, dict) and isinstance(m.get("code"), str)
    ]


def run_shopper(
    goal: str,
    *,
    base_url: str,
    gateway: LlmGateway,
    key: AgentKey | None = None,
    http: httpx.Client | None = None,
    on_approve_url: Callable[[str], None] | None = None,
    on_payer_approval: Callable[[str], None] | None = None,
    emit: Callable[[dict[str, Any]], None] | None = None,
    consent_timeout_s: float = CONSENT_TIMEOUT_S,
    poll_s: float = POLL_S,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    max_attempts: int = 2,
) -> ShopperResult:
    key = key or AgentKey()
    client = ServiceClient(base_url, http)
    say = emit or (lambda _event: None)
    try:
        return _run(goal, client, gateway, key, on_approve_url, on_payer_approval, say,
                    consent_timeout_s, poll_s, clock, sleep, max_attempts)  # fmt: skip
    except ServiceError as error:
        raise ShopperError("service_refused", f"{error.status} {error.code}") from None
    except PlanError as error:
        raise ShopperError("plan_refused", error.code) from None
    except wire.WireError as error:
        raise ShopperError("wire_invalid", str(error)) from None
    finally:
        client.close()


def _run(
    goal: str, client: ServiceClient, gateway: LlmGateway, key: AgentKey,
    on_approve_url: Callable[[str], None] | None, on_payer_approval: Callable[[str], None] | None,
    say: Callable[[dict[str, Any]], None], consent_timeout_s: float, poll_s: float,
    clock: Callable[[], float], sleep: Callable[[float], None], max_attempts: int,
) -> ShopperResult:  # fmt: skip
    # 1 and 4: the wish, the search, the choice.
    listing = client.catalog()
    wish = plan_wish(gateway, goal, listing["categories"])
    say({"event": "wish", "categories": list(wish.categories), "quantity": wish.quantity,
         "ceiling_minor": wish.ceiling_minor, "valid_for_hours": wish.valid_for_hours})  # fmt: skip
    found = candidates(wish, client.catalog()["items"])
    item = choose_item(gateway, goal, wish, found)
    say({"event": "chosen", "item_id": item["id"], "price_minor": item["price_minor"]})

    # 3: the proposal and the customer's consent.
    expires_at = int(clock()) + wish.valid_for_hours * 3600
    proposal = {
        "items": [{"id": item["id"], "quantity": wish.quantity}],
        "ceiling_minor": wish.ceiling_minor, "currency": "USD", "mandate_expires_at": expires_at,
    }  # fmt: skip
    proposal_id = client.propose(key, proposal)
    url = client.approve_url(proposal_id)
    say({"event": "approve_url", "url": url, "proposal_id": proposal_id})
    if on_approve_url:
        on_approve_url(url)
    deadline = clock() + consent_timeout_s
    issued = client.fetch_mandates(key, proposal_id)
    while issued is None:
        if clock() >= deadline:
            raise ShopperError("consent_timeout", "the customer did not approve in time")
        sleep(poll_s)
        issued = client.fetch_mandates(key, proposal_id)
    open_cm, open_pm = str(issued["checkout_mandate"]), str(issued["payment_mandate"])
    payee = _check_open_mandates(open_cm, open_pm, key, proposal, clock)
    say({"event": "consent", "consent_id": issued["consent_id"]})

    # 5 and 6: shop, sign, complete. One purchase per open mandate: a second attempt only after a
    # rejection receipt told us the first was refused.
    codes: list[str] = []
    for attempt in range(1, max_attempts + 1):
        body, closed = _checkout(client, key, open_cm, open_pm, item, wish.quantity, proposal, payee,
                                 clock)  # fmt: skip
        total, currency = closed["total"], closed["currency"]
        done = client.complete(body["id"], open_cm, closed["body"])
        keys = client.merchant_keys()
        wire.checkout_jwt_of(done, keys)
        if done.get("status") == "complete_in_progress" and done.get("continue_url"):
            link = str(done["continue_url"])
            say({"event": "payer_approval", "url": link})
            if on_payer_approval is None:
                return ShopperResult("payer_approval_pending", body["id"], total, currency, None,
                                     proposal_id, attempt, _codes(done), {}, link)  # fmt: skip
            on_payer_approval(link)
            done = client.complete(body["id"], open_cm, {})
            wire.checkout_jwt_of(done, keys)
        receipts = _receipts(done, keys)
        if done.get("status") == "completed":
            capture = (receipts.get("payment") or {}).get("psp_confirmation_id")
            if not isinstance(capture, str):
                raise ShopperError("capture_id_missing", "completed without a verifiable receipt")
            say({"event": "completed", "checkout_id": body["id"], "capture_id": capture})
            return ShopperResult("completed", body["id"], total, currency, capture, proposal_id,
                                 attempt, _codes(done), receipts)  # fmt: skip
        codes = _codes(done)
        say({"event": "rejected", "checkout_id": body["id"], "codes": codes})
        # The refusal is final for this checkout and the service released the open mandate. A signed
        # rejection receipt says so when the response carries one; the typed UCP refusal says the
        # same today (Decision 98: the API does not transport rejection receipts yet).
        rejected = REJECTED_CODE in codes or any(
            isinstance(r, dict) and r.get("status") == "Error" for r in receipts.values()
        )
        if not rejected:
            break
    return ShopperResult("rejected", body["id"], total, currency, None, proposal_id,
                         attempt, codes, receipts)  # fmt: skip


def _check_open_mandates(
    open_cm: str, open_pm: str, key: AgentKey, proposal: dict[str, Any],
    clock: Callable[[], float],
) -> dict[str, Any]:  # fmt: skip
    """The issued mandates must say what was proposed and be bound to this key. Returns the payee."""
    cm, pm = wire.open_content(open_cm), wire.open_content(open_pm)
    for content in (cm, pm):
        cnf = content.get("cnf")
        jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        if not isinstance(jwk, dict) or wire.thumbprint(jwk) != key.thumbprint:
            raise ShopperError("mandate_not_bound_to_this_key")
        if content.get("exp") != proposal["mandate_expires_at"]:
            raise ShopperError("mandate_expiry_differs")
        if type(content.get("exp")) is not int or content["exp"] <= clock():
            raise ShopperError("mandate_expired")
    lines = wire.constraint(cm, "checkout.line_items")["items"]
    approved = [(l["acceptable_items"][0]["id"], l["quantity"]) for l in lines]
    if approved != [(i["id"], i["quantity"]) for i in proposal["items"]]:
        raise ShopperError("mandate_items_differ")
    if wire.constraint(pm, "payment.budget")["max"] != proposal["ceiling_minor"]:
        raise ShopperError("mandate_ceiling_differs")
    allowed = wire.constraint(pm, "payment.allowed_payees")["allowed"]
    if len(allowed) != 1 or not isinstance(allowed[0], dict):
        raise ShopperError("mandate_payee_invalid")
    return dict(allowed[0])


def _checkout(
    client: ServiceClient, key: AgentKey, open_cm: str, open_pm: str, item: dict[str, Any],
    quantity: int, proposal: dict[str, Any], payee: dict[str, Any], clock: Callable[[], float],
) -> tuple[dict[str, Any], dict[str, Any]]:  # fmt: skip
    keys = client.merchant_keys()
    body = client.create_checkout([{"item": {"id": item["id"]}, "quantity": 1}], open_cm)
    wire.checkout_jwt_of(body, keys)  # stop if the merchant's signature does not verify
    if quantity != 1:
        body = client.update_checkout(
            body["id"], [{"item": {"id": item["id"]}, "quantity": quantity}], open_cm
        )
        wire.checkout_jwt_of(body, keys)
    lines = body.get("line_items", [])
    if [(l["item"]["id"], l["quantity"]) for l in lines] != [(item["id"], quantity)]:
        raise ShopperError("checkout_differs_from_mandate")
    total, currency = _total(body)
    if currency != proposal["currency"] or total > proposal["ceiling_minor"]:
        raise ShopperError("checkout_over_ceiling")
    cj = wire.checkout_jwt_of(body, keys)
    now = int(clock())
    closed_cm = wire.sign_closed(open_cm, key, kind="checkout", checkout_jwt=cj, extra={}, now=now)
    closed_pm = wire.sign_closed(
        open_pm, key, kind="payment", checkout_jwt=cj, now=now,
        extra={"payee": payee, "payment_amount": {"amount": total, "currency": currency},
               "payment_instrument": dict(INSTRUMENT)},
    )  # fmt: skip
    request = {
        "ap2": {"checkout_mandate": closed_cm},
        "payment": {"instruments": [{
            "id": "instr_1", "handler_id": HANDLER_ID, "type": "ap2",
            "credential": {"type": "ap2_payment_mandate", "token": closed_pm},
        }]},
    }  # fmt: skip
    return body, {"body": request, "total": total, "currency": currency}


def _receipts(done: dict[str, Any], keys: list[dict[str, Any]]) -> dict[str, Any]:
    """The receipts a response carries, verified with the merchant's published keys."""
    ap2 = done.get("ap2")
    ap2 = ap2 if isinstance(ap2, dict) else {}
    found: dict[str, Any] = {}
    for name, member in (("checkout", "checkout_receipt"), ("payment", "payment_receipt")):
        claims = _receipt_claims(ap2.get(member), keys)
        if claims is not None:
            found[name] = claims
    return found

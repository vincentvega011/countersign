"""The verification steps, each with a stable name, in the order of AP2's dispute procedure.

Steps 2 to 6 are the five dispute steps of AP2 v0.2 ("Dispute"; docs/PROTOCOL.md 1.2.8); the rest check
what Countersign adds: the device consent signature against the mandate content, the PayPal objects
against the signed checkout, the evidence reference in `custom_id`, the gate result and the decision
log. Each step runs on its own and reports `pass` or `fail` with a stable code and a message; a step
never trusts a result of another one. The verifier trusts nothing but the keys it is given (pinned) or,
if none are pinned, the keys inside the bundle, and says so.

Comparisons of values read from the bundle are type-exact (`same`, `is_int`; Decision 106), so `true` is
never `1` and `1.0` is never `1`. `web/ui/evidence/steps.js` is the browser port of this file.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from countersign_verify import constraints as cons
from countersign_verify import log as logmod
from countersign_verify import sdjwt
from countersign_verify.crypto import (
    MAX_SAFE_INTEGER,
    Invalid,
    b64url,
    digest,
    domain_hash,
    is_int,
    jcs,
    loads,
    same,
    thumbprint,
    verify_es256,
    verify_jws,
)  # fmt: skip

VCT = {
    "checkout_open": "mandate.checkout.open.1", "checkout": "mandate.checkout.1",
    "payment_open": "mandate.payment.open.1", "payment": "mandate.payment.1",
}  # fmt: skip
GATE_CODES = (
    "G-FETCH", "G-STATUS", "G-REVERSE", "G-TERMS", "G-AMOUNT", "G-MANDATE", "G-BUDGET", "G-LOCK",
    "G-CHECKOUT",
)  # fmt: skip
TOP = {
    "v", "kind", "capture_id", "checkout_id", "order_id", "authorization_id", "checkout_jwt",
    "mandates", "receipts", "consent", "paypal", "gate", "log", "keys",
}  # fmt: skip
PURPOSE_CONSENT = "countersign.consent.open-mandates.v1"
_DECIMAL = re.compile(r"[0-9]+(?:\.[0-9]+)?")


@dataclass(frozen=True)
class Result:
    name: str
    ok: bool
    message: str
    code: str | None = None


def minor(money: Any) -> tuple[int, str]:
    """An exact integer minor-unit amount from a PayPal `{currency_code, value}` (USD, two places).

    `value` must be a string of digits with an optional fraction (Decision 106); `Infinity`, exponents,
    signs and spaces are refused."""
    if not isinstance(money, dict):
        raise Invalid("paypal_amount_malformed", "a PayPal amount is malformed")
    value, code = money.get("value"), money.get("currency_code")
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None or not isinstance(code, str):
        raise Invalid("paypal_amount_malformed", "a PayPal amount is malformed")
    whole, _, fraction = value.partition(".")
    fraction = fraction.ljust(2, "0")
    if fraction[2:].strip("0") or code != "USD":
        raise Invalid("paypal_amount_not_cents", "a PayPal amount is not whole US cents")
    whole = whole.lstrip("0") or "0"
    if len(whole) > 14 or int(whole) * 100 + int(fraction[:2]) > MAX_SAFE_INTEGER:
        raise Invalid("paypal_amount_range", "a PayPal amount is out of range")
    return int(whole) * 100 + int(fraction[:2]), code


def _truthy_or(first: Any, second: Any) -> Any:
    return first or second


class Bundle:
    """The bundle with the parts every step needs, parsed lazily so one bad part fails only its steps."""

    def __init__(self, raw: Any, pinned: dict[str, Any] | None = None) -> None:
        if not isinstance(raw, dict) or set(raw) != TOP:
            raise Invalid("bundle_members", "the bundle does not have exactly the expected members")
        if not same(raw["v"], 1) or raw["kind"] != "countersign.evidence":
            raise Invalid(
                "bundle_version", "the bundle is not a version 1 Countersign evidence bundle"
            )
        self.raw = raw
        self.pinned = pinned or {}
        for name in ("capture_id", "checkout_id", "order_id", "authorization_id", "checkout_jwt"):
            if not isinstance(raw[name], str) or not raw[name]:
                raise Invalid("bundle_member_type", f"{name} is not a text")
        for name in ("mandates", "receipts", "consent", "paypal", "gate", "log", "keys"):
            if not isinstance(raw[name], dict):
                raise Invalid("bundle_member_type", f"{name} is not an object")

    @property
    def merchant_key(self) -> dict[str, Any]:
        key = _truthy_or(self.pinned.get("merchant"), self.raw["keys"].get("merchant"))
        if not isinstance(key, dict):
            raise Invalid("no_merchant_key", "no merchant key")
        return key

    @property
    def platform_key(self) -> dict[str, Any]:
        key = _truthy_or(self.pinned.get("platform"), self.raw["keys"].get("platform"))
        if not isinstance(key, dict):
            raise Invalid("no_platform_key", "no platform key")
        return key

    def mandate(self, name: str) -> str:
        value = self.raw["mandates"].get(name)
        if not isinstance(value, str):
            raise Invalid("mandate_missing", f"mandates.{name} is missing")
        return value

    def checkout_chain(self) -> tuple[sdjwt.OpenMandate, sdjwt.ClosedMandate]:
        chain = self.mandate("checkout_closed")
        opened, link = sdjwt.split(chain)
        if opened != self.mandate("checkout_open"):
            raise Invalid(
                "checkout_chain_not_extending",
                "the closed Checkout Mandate does not extend the open one in the bundle",
            )
        om = sdjwt.read_open(opened, self.platform_key, VCT["checkout_open"])
        return om, sdjwt.read_closed(link, opened, om, VCT["checkout"], "merchant", "checkout_hash")

    def payment_chain(self) -> tuple[sdjwt.OpenMandate, sdjwt.ClosedMandate]:
        chain = self.mandate("payment_closed")
        opened, link = sdjwt.split(chain)
        if opened != self.mandate("payment_open"):
            raise Invalid(
                "payment_chain_not_extending",
                "the closed Payment Mandate does not extend the open one in the bundle",
            )
        om = sdjwt.read_open(opened, self.platform_key, VCT["payment_open"])
        return om, sdjwt.read_closed(
            link, opened, om, VCT["payment"], "credential-provider", "transaction_id"
        )

    def checkout(self) -> dict[str, Any]:
        _, payload = verify_jws(self.raw["checkout_jwt"], self.merchant_key)
        if not isinstance(payload, dict):
            raise Invalid("checkout_not_object", "the checkout is not an object")
        return payload

    def total(self) -> tuple[int, str]:
        checkout = self.checkout()
        totals = [t for t in checkout.get("totals", []) if t.get("type") == "total"]
        if len(totals) != 1 or not is_int(totals[0].get("amount")):
            raise Invalid("checkout_total", "the checkout has no single integer total")
        currency = checkout.get("currency")
        if not isinstance(currency, str):
            raise Invalid("checkout_currency", "the checkout names no currency")
        return totals[0]["amount"], currency


# ------------------------------------------------------------------------------------ the steps


def step_bundle_structure(b: Bundle) -> str:
    if b.raw["gate"].get("state") != "captured":
        raise Invalid("not_captured", "the bundle does not say the payment was captured")
    return "the bundle has the expected members and says the payment was captured"


def step_checkout_mandate(b: Bundle) -> str:
    """AP2 dispute step 1: the Checkout Mandate verifies (platform, agent key, binding, hash)."""
    opened, closed = b.checkout_chain()
    if closed.checkout_jwt != b.raw["checkout_jwt"]:
        raise Invalid(
            "checkout_jwt_not_disclosed",
            "the checkout_jwt in the bundle is not the one the mandate discloses",
        )
    # AP2: with open mandates, the closed checkout must conform to every constraint (Decision 110).
    found = cons.by_type(
        opened.content.get("constraints"), cons.CHECKOUT_TYPES, "checkout.line_items"
    )
    cons.line_items(found["checkout.line_items"], cons.committed_checkout(closed.checkout_jwt))
    return "signatures, key binding and hashes verify; the items are what the customer allowed"


def step_checkout_jwt(b: Bundle) -> str:
    """AP2 dispute step 2: the hash of the checkout_jwt is recomputed and matches; the merchant signed it."""
    _, closed = b.checkout_chain()
    if digest(b.raw["checkout_jwt"]) != closed.content["checkout_hash"]:
        raise Invalid(
            "checkout_hash_mismatch",
            "the hash of the checkout_jwt is not the mandate's checkout_hash",
        )
    checkout = b.checkout()
    if checkout.get("id") != b.raw["checkout_id"]:
        raise Invalid("checkout_id_mismatch", "the signed checkout is for another checkout id")
    return "checkout_hash is the hash of the checkout_jwt, which the merchant signed"


def _receipt(b: Bundle, which: str, typ: str, mandate_link: str) -> dict[str, Any]:
    _, claims = verify_jws(b.raw["receipts"].get(which), b.merchant_key, typ=typ)
    if not isinstance(claims, dict) or claims.get("status") != "Success":
        raise Invalid("receipt_not_success", f"the {which} receipt is not a Success receipt")
    if claims.get("reference") != digest(mandate_link):
        raise Invalid(
            "receipt_reference",
            f"the {which} receipt reference is not the hash of the closed mandate",
        )
    return claims


def step_checkout_receipt(b: Bundle) -> str:
    """AP2 dispute step 3: the Checkout Receipt reference matches the closed Checkout Mandate."""
    _, link = sdjwt.split(b.mandate("checkout_closed"))
    claims = _receipt(b, "checkout", "checkout-receipt+jwt", link)
    if claims.get("order_id") != b.raw["checkout_id"]:
        raise Invalid("receipt_other_checkout", "the Checkout Receipt is for another checkout")
    return "the receipt is merchant signed and its reference is the closed mandate's hash"


def _constraints(content: dict[str, Any], kind: str) -> list[Any]:
    return [c for c in content.get("constraints", []) if c.get("type") == kind]


def step_payment_mandate(b: Bundle) -> str:
    """AP2 dispute step 4: the Payment Mandate verifies under the checkout_hash of the Checkout Mandate."""
    com, ccl = b.checkout_chain()
    pom, pcl = b.payment_chain()
    if pcl.content["transaction_id"] != ccl.content["checkout_hash"]:
        raise Invalid(
            "payment_other_checkout",
            "the Payment Mandate is scoped to another checkout (transaction_id)",
        )
    if pom.payload["sub"] != com.payload["sub"] or (
        thumbprint(pom.content["cnf"]["jwk"]) != thumbprint(com.content["cnf"]["jwk"])
    ):
        raise Invalid(
            "payment_other_principal",
            "the two open mandates name a different customer or agent key",
        )
    reference = _constraints(pom.content, "payment.reference")
    if len(reference) != 1 or reference[0].get("conditional_transaction_id") != digest(
        b.mandate("checkout_open")
    ):
        raise Invalid(
            "payment_not_bound",
            "the open Payment Mandate is not bound to the open Checkout Mandate",
        )
    total, currency = b.total()
    if not same(pcl.content.get("payment_amount"), {"amount": total, "currency": currency}):
        raise Invalid("payment_amount", "the Payment Mandate amount is not the checkout total")
    allowed = _constraints(pom.content, "payment.allowed_payees")
    payee = pcl.content.get("payee")
    if len(allowed) != 1 or not any(same(payee, p) for p in allowed[0].get("allowed", [])):
        raise Invalid("payment_payee", "the payee is not one the customer allowed")
    budget = _constraints(pom.content, "payment.budget")
    if len(budget) != 1 or not is_int(budget[0].get("max")) or total > budget[0]["max"]:
        raise Invalid("payment_budget", "the total is over the budget the customer approved")
    found = cons.by_type(pom.content.get("constraints"), cons.PAYMENT_TYPES, "payment.reference")
    if "payment.amount_range" in found:
        cons.amount_range(found["payment.amount_range"], total, currency)
    if "payment.agent_recurrence" in found:
        cons.recurrence(found["payment.agent_recurrence"])
    merchants = cons.by_type(
        com.content.get("constraints"), cons.CHECKOUT_TYPES, "checkout.line_items"
    ).get("checkout.allowed_merchants")
    if merchants is not None:
        cons.allowed_merchants(merchants, payee)
    return "chain verifies, scoped to the checkout; amount, payee, merchant and budget are allowed"


def step_payment_receipt(b: Bundle) -> str:
    """AP2 dispute step 5: the Payment Receipt reference matches the closed Payment Mandate."""
    _, link = sdjwt.split(b.mandate("payment_closed"))
    claims = _receipt(b, "payment", "payment-receipt+jwt", link)
    capture = b.raw["capture_id"]
    if (
        claims.get("psp_confirmation_id") != capture
        or claims.get("payment_id") != b.raw["checkout_id"]
    ):
        raise Invalid(
            "receipt_other_capture", "the Payment Receipt is for another capture or checkout"
        )
    return "the receipt is merchant signed, names this capture, and references the closed mandate"


def step_consent_signature(b: Bundle) -> str:
    """The customer's device signed the terms the open mandates were issued from."""
    consent = b.raw["consent"]
    if set(consent) != {"record", "signature", "device_jwk", "customer_id"}:
        raise Invalid("consent_members", "the consent record is missing or has the wrong members")
    text, signature, device = consent["record"], consent["signature"], consent["device_jwk"]
    if not isinstance(text, str):
        raise Invalid("consent_not_text", "the consent record is not text")
    record = loads(text)
    if jcs(record).decode() != text:
        raise Invalid("consent_not_canonical", "the consent record is not in canonical form")
    if not verify_es256(device, text.encode(), signature):
        raise Invalid(
            "consent_signature", "the device signature does not verify over the consent record"
        )
    if record.get("purpose") != PURPOSE_CONSENT:
        raise Invalid("consent_purpose", "the signed record is not a consent to open mandates")
    if record.get("device_thumbprint") != thumbprint(device):
        raise Invalid(
            "consent_device", "the record names another device key than the one in the bundle"
        )
    com, _ = b.checkout_chain()
    pom, _ = b.payment_chain()
    if (
        record.get("customer_id") != consent["customer_id"]
        or com.payload["sub"] != consent["customer_id"]
    ):
        raise Invalid(
            "consent_customer", "the mandates name another customer than the device consented as"
        )
    if record["terms"].get("agent_thumbprint") != thumbprint(com.content["cnf"]["jwk"]):
        raise Invalid("consent_agent", "the consent names another agent key than the mandates bind")
    signed = record.get("mandate", {})
    checkout = {k: v for k, v in com.content.items() if k not in ("cnf", "iat")}
    if not same(signed.get("checkout"), checkout):
        raise Invalid("consent_checkout", "the open Checkout Mandate is not what the device signed")
    payment = {k: v for k, v in pom.content.items() if k not in ("cnf", "iat")}
    payment["constraints"] = [
        c for c in payment["constraints"] if c.get("type") != "payment.reference"
    ]
    if not same(signed.get("payment"), payment):
        raise Invalid("consent_payment", "the open Payment Mandate is not what the device signed")
    terms = record["terms"]
    budgets = [c for c in payment["constraints"] if c.get("type") == "payment.budget"]
    if not budgets or not same(terms.get("ceiling_minor"), budgets[0]["max"]):
        raise Invalid("consent_ceiling", "the signed ceiling is not the mandate budget")
    if not same(record.get("mandate"), cons.rebuild_mandate(terms)):
        raise Invalid(
            "consent_terms_mismatch", "the terms the device was shown do not make these mandates"
        )
    return "the device signature verifies and the signed terms equal both open mandates"


def _last(bodies: Any, what: str) -> dict[str, Any]:
    if not isinstance(bodies, list) or not bodies or not isinstance(bodies[-1], dict):
        raise Invalid("paypal_missing", f"the bundle holds no {what} as fetched")
    return dict(bodies[-1])


def _immutable(obj: dict[str, Any], what: str, cid: str, total: int, currency: str) -> None:
    if minor(obj.get("amount")) != (total, currency):
        raise Invalid("paypal_amount", f"a PayPal {what} amount is not the signed checkout total")
    if obj.get("invoice_id") != cid:
        raise Invalid("paypal_invoice", f"a PayPal {what} is for another checkout (invoice_id)")


def _order_unit(
    order: dict[str, Any], cid: str, total: int, currency: str, checkout: Any, ids: dict[str, str]
) -> None:
    units = order.get("purchase_units")
    if not isinstance(units, list) or len(units) != 1:
        raise Invalid("paypal_units", "the order does not have exactly one purchase unit")
    unit = units[0]
    _immutable(unit, "order", cid, total, currency)
    payee = _truthy_or(unit.get("payee"), {}).get("merchant_id")
    if not isinstance(payee, str) or not payee:
        raise Invalid("paypal_no_payee", "the order names no payee")
    nested = _truthy_or(unit.get("payments"), {})
    for kind, key in (("authorization", "authorizations"), ("capture", "captures")):
        for inner in nested.get(key, []):
            if inner.get("id") != ids[kind]:
                raise Invalid(
                    "paypal_nested_id", f"the order holds a {kind} the bundle does not name"
                )
            _immutable(inner, f"nested {kind}", cid, total, currency)
    items = unit.get("items", [])
    lines = checkout.get("line_items", [])
    if len(items) != len(lines):
        raise Invalid(
            "paypal_item_count", "the order has a different number of items than the checkout"
        )
    for item, line in zip(items, lines, strict=True):
        want = line["item"]
        if not is_int(want["price"]) or not is_int(line["quantity"]):
            raise Invalid("checkout_line", "a checkout line has no integer price and quantity")
        if not same(
            [item.get("name"), item.get("sku"), item.get("quantity")],
            [want["title"], want["id"], str(line["quantity"])],
        ):  # fmt: skip
            raise Invalid("paypal_item", "an order item is not the checkout line item")
        if minor(item.get("unit_amount")) != (want["price"], currency):
            raise Invalid("paypal_item_price", "an order item price is not the checkout price")
    subtotal = sum(line["item"]["price"] * line["quantity"] for line in lines)
    if minor(unit.get("amount", {}).get("breakdown", {}).get("item_total")) != (subtotal, currency):
        raise Invalid(
            "paypal_item_total", "the order item_total is not the sum of the checkout lines"
        )


def step_paypal_objects(b: Bundle) -> str:
    """Every PayPal object read, and the last of each kind, agree with the signed checkout."""
    total, currency = b.total()
    checkout = b.checkout()
    paypal, cid = b.raw["paypal"], b.raw["checkout_id"]
    last = {kind: _last(paypal.get(kind), kind) for kind in ("order", "authorization", "capture")}
    ids = {"order": b.raw["order_id"], "authorization": b.raw["authorization_id"],
           "capture": b.raw["capture_id"]}  # fmt: skip
    for kind, bodies in ((k, paypal[k]) for k in last):
        for body in bodies:
            if not isinstance(body, dict) or body.get("id") != ids[kind]:
                raise Invalid("paypal_id", f"a PayPal {kind} has an id the bundle does not name")
            if kind == "order":
                if body.get("intent") != "AUTHORIZE":
                    raise Invalid("paypal_intent", "a PayPal order is not an authorization order")
                _order_unit(body, cid, total, currency, checkout, ids)
            else:
                _immutable(body, kind, cid, total, currency)
    payees = {
        o["purchase_units"][0]["payee"]["merchant_id"] for o in paypal["order"]
    }  # the same payee on every read
    if len(payees) != 1:
        raise Invalid("paypal_payee_changed", "the payee changed between two reads of the order")
    auth, capture = last["authorization"], last["capture"]
    if capture.get("status") != "COMPLETED" or capture.get("final_capture") is not True:
        raise Invalid("paypal_capture_status", "the capture is not a completed final capture")
    if auth.get("status") != "CAPTURED":
        raise Invalid("paypal_authorization_status", "the authorization is not captured")
    return "ids, statuses, amounts, invoice id and items agree with the signed checkout"


def _hashable(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        raise TypeError("unhashable custom_id")
    return value


def step_custom_id(b: Bundle) -> str:
    """`custom_id` at PayPal is the evidence reference recomputed from the three signed values."""
    _, ccl = b.checkout_chain()
    reference = jcs(
        {
            "v": 1, "checkout_hash": ccl.content["checkout_hash"],
            "checkout_mandate": digest(sdjwt.split(b.mandate("checkout_closed"))[1]),
            "payment_mandate": digest(sdjwt.split(b.mandate("payment_closed"))[1]),
        }
    )  # fmt: skip
    want = "cs1." + b64url(domain_hash("cs.evidence.ref.v1", reference))
    found = [_hashable(b.raw["gate"].get("custom_id"))]
    for kind in ("order", "authorization", "capture"):
        for body in b.raw["paypal"].get(kind, []):
            if kind == "order":
                for unit in body.get("purchase_units", []):
                    found.append(_hashable(unit.get("custom_id")))
                    for key in ("authorizations", "captures"):
                        found.extend(
                            _hashable(inner.get("custom_id"))
                            for inner in _truthy_or(unit.get("payments"), {}).get(key, [])
                        )
            else:
                found.append(_hashable(body.get("custom_id")))
    if not all(isinstance(f, str) and f == want for f in found):
        raise Invalid(
            "custom_id_mismatch",
            "a custom_id at PayPal is not the evidence reference of these mandates",
        )
    return "every custom_id equals the reference recomputed from the signed mandates"


def _entries(b: Bundle) -> list[dict[str, Any]]:
    entries = b.raw["log"].get("entries")
    if not isinstance(entries, list) or not entries:
        raise Invalid("log_empty", "the bundle holds no log entries")
    return entries


def step_gate_result(b: Bundle) -> str:
    """The log shows every gate step passing on this checkout and the capture the receipt names."""
    entries = _entries(b)
    steps: dict[str, list[Any]] = {}
    captured = None
    for e in entries:
        payload = loads(e["payload"])
        if e["kind"] == "gate.step":
            steps.setdefault(_hashable(payload["code"]), []).append(payload["outcome"])
        if e["kind"] == "gate.captured":
            captured = payload
    for code in GATE_CODES:
        if not same(steps.get(code), ["pass"]):
            raise Invalid("gate_step", f"gate step {code} did not pass exactly once in the log")
    if captured is None:
        raise Invalid("gate_not_captured", "the log has no gate.captured entry")
    total, currency = b.total()
    if not same(
        [captured.get("capture_id"), captured.get("order_id"), captured.get("authorization_id"),
         captured.get("amount")],
        [b.raw["capture_id"], b.raw["order_id"], b.raw["authorization_id"], f"{currency}:{total}"],
    ):  # fmt: skip
        raise Invalid(
            "gate_captured_mismatch", "gate.captured names another capture, order or amount"
        )
    _, claims = verify_jws(b.raw["receipts"].get("payment"), b.merchant_key)
    if not same(captured.get("reference"), claims.get("reference")):
        raise Invalid(
            "gate_receipt_mismatch",
            "gate.captured and the Payment Receipt disagree on the reference",
        )
    return "all nine gate steps passed and gate.captured matches the receipt and the capture"


def step_decision_log(b: Bundle) -> str:
    """Entries recompute, are in order, and every one is included in the checkout's Merkle root."""
    log, entries = b.raw["log"], _entries(b)
    proofs = log.get("proofs")
    if set(log) != {"entries", "size", "root", "proofs"} or not isinstance(proofs, list):
        raise Invalid("log_members", "the log section has the wrong members")
    if not same(log["size"], len(entries)) or len(proofs) != len(entries):
        raise Invalid("log_truncated", "the log size, entries and proofs disagree (truncated?)")
    hashes: list[bytes] = []
    for i, e in enumerate(entries):
        logmod.check_fields(e)
        if e.get("checkout_id") != b.raw["checkout_id"]:
            raise Invalid("log_other_checkout", "a log entry belongs to another checkout")
        if i and not e["seq"] > entries[i - 1]["seq"]:
            raise Invalid("log_order", "log entries are not in increasing order")
        computed = logmod.entry_hash(e)
        if b64url(computed) != e["entry_hash"]:
            raise Invalid("log_entry_hash", f"log entry {e['seq']} does not hash to its entry_hash")
        if (
            i
            and e["seq"] == entries[i - 1]["seq"] + 1
            and e["prev_hash"] != entries[i - 1]["entry_hash"]
        ):
            raise Invalid("log_chain", f"log entry {e['seq']} does not follow the previous entry")
        hashes.append(computed)
    root = logmod.root_of(hashes)
    if b64url(root) != log["root"]:
        raise Invalid("log_root", "the log entries do not hash to the stated root")
    for i, proof in enumerate(proofs):
        if (
            not isinstance(proof, dict)
            or not same(proof.get("index"), i)
            or not same(proof.get("size"), len(hashes))
        ):
            raise Invalid(
                "proof_position", f"the proof for entry {i} is for another position or size"
            )
        logmod.check_inclusion(hashes[i], proof, root)
    return (
        f"{len(hashes)} entries recompute, chain where adjacent, and are all included in the root"
    )


def step_keys(b: Bundle) -> str:
    """Reported, not assumed: both keys must be pinned by the caller and equal the bundle's (Decision 106)."""
    if not b.pinned:
        raise Invalid(
            "keys_not_pinned",
            "the keys were taken from the bundle itself; pin them with --merchant-key and --platform-key",
        )
    for name in ("merchant", "platform"):
        if name not in b.pinned:
            raise Invalid("keys_partly_pinned", f"the {name} key was not pinned")
        if thumbprint(b.pinned[name]) != thumbprint(b.raw["keys"].get(name)):
            raise Invalid("keys_differ", f"the bundle's {name} key is not the pinned one")
    return "the merchant and platform keys are the ones you pinned"


STEPS: tuple[tuple[str, Callable[[Bundle], str]], ...] = (
    ("bundle_structure", step_bundle_structure),
    ("checkout_mandate", step_checkout_mandate),
    ("checkout_jwt_hash", step_checkout_jwt),
    ("checkout_receipt", step_checkout_receipt),
    ("payment_mandate", step_payment_mandate),
    ("payment_receipt", step_payment_receipt),
    ("consent_signature", step_consent_signature),
    ("paypal_objects", step_paypal_objects),
    ("paypal_custom_id", step_custom_id),
    ("gate_result", step_gate_result),
    ("decision_log", step_decision_log),
    ("trusted_keys", step_keys),
)

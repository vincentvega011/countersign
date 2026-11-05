"""The merchant dashboard's read model (docs/PROTOCOL.md Decisions 114 and 116).

Security reasoning. Every function here only reads. The output is built from an explicit list of
members per row, never by copying a database row or a PayPal object, so a column added later cannot
leak through: no email, no payer or buyer name or address, no token, no key, no mandate text. Money is
integer minor units with its currency (INV-9). Labels come from fixed sets. The customer id is the
random `cus_` id of the Trusted Surface and the agent is a key thumbprint: both already appear in
evidence bundles (L46), and neither is a secret or a person.

What each derived value means (all deterministic, INV-1):

- `status`: the checkout's own status, except that a checkout whose payment attempt was voided is
  `voided`, and a canceled checkout with a refused complete is `rejected`.
- `mandate`: `verified` once the Merchant and the Credential Provider accepted the mandates (a
  payment attempt exists), `refused` when a complete was refused, otherwise `not_presented`.
- `gate`: `passed` for a captured attempt, the gate's code for a voided one, `pending` while an
  attempt is in flight, otherwise null.
- `source`: the label written when the checkout was created (`checkout_sources`); a row without one
  is `unlabelled` and is never shown as a sandbox capture.
- An **unauthorized capture** is a capture with no verified mandate behind it: a captured attempt
  without stored mandates, or a capture of the baseline's unmandated path. Full mode must keep it at 0.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine, func, select

from countersign.canonical.jsonstrict import loads_strict
from countersign.checkout.store import checkout_sessions
from countersign.ledger.store import decision_log
from countersign.openmandates import list_for_customer
from countersign.tables import (
    attempt_mandates,
    checkout_customers,
    checkout_sources,
    open_mandates,
    payment_attempts,
)

API_VERSION = 1
MAX_ORDERS = 20_000
MAX_EVENTS = 20_000
MAX_IDS = 500
SOURCES = frozenset({"live_sandbox", "recorded", "simulator"})
PROTOCOL_KINDS = {"checkout.created": "ucp", "acp.session_created": "acp"}
REFUSAL_KINDS = (
    "checkout.complete_rejected",
    "checkout.create_rejected",
    "checkout.update_rejected",
)
UNMANDATED_CAPTURE = "degraded.unmandated.captured"
EVENT_KINDS = (
    "checkout.complete_rejected", "lock.decision", "acp.create_denied", "acp.update_denied",
    "acp.complete_denied", "gate.rejected", "checkout.customer_refused", UNMANDATED_CAPTURE,
)  # fmt: skip
AUTHORIZED = ("authorized", "capturing", "captured", "unresolved")
IN_FLIGHT = ("reserved", "order_created", "authorizing", "authorized", "capturing", "unresolved")


@dataclass(frozen=True)
class _Log:
    seq: int
    ts_us: int
    checkout_id: str | None
    kind: str
    payload: dict[str, Any]


def _payload(raw: bytes) -> dict[str, Any]:
    try:
        value = loads_strict(bytes(raw))
    except Exception:  # noqa: BLE001 - an unreadable entry contributes nothing
        return {}
    return value if isinstance(value, dict) else {}


def _iso(us: int) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(us / 1_000_000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _logs(
    conn: Connection, kinds: tuple[str, ...] | list[str], ids: list[str] | None
) -> list[_Log]:
    query = select(
        decision_log.c.seq, decision_log.c.ts_us, decision_log.c.checkout_id, decision_log.c.kind,
        decision_log.c.payload,
    ).where(decision_log.c.kind.in_(list(kinds)))  # fmt: skip
    if ids is not None:
        query = query.where(decision_log.c.checkout_id.in_(ids))
    rows = conn.execute(query.order_by(decision_log.c.seq).limit(MAX_EVENTS * 4)).all()
    return [
        _Log(int(r.seq), int(r.ts_us), r.checkout_id, str(r.kind), _payload(r.payload))
        for r in rows
    ]


def _items(checkout: dict[str, Any]) -> tuple[str, int, str]:
    lines = checkout.get("line_items") or []
    parts = []
    for line in lines[:5]:
        item = line.get("item") or {}
        parts.append(f"{int(line.get('quantity', 0))} × {str(item.get('title', ''))[:60]}")
    if len(lines) > 5:
        parts.append(f"+{len(lines) - 5} more")
    total: dict[str, Any] = next(
        (t for t in checkout.get("totals") or [] if t.get("type") == "total"), {}
    )
    amount = total.get("amount")
    return (
        "; ".join(parts),
        int(amount) if isinstance(amount, int) else 0,
        str(checkout.get("currency", "")),
    )


def _source(value: object) -> str:
    return value if isinstance(value, str) and value in SOURCES else "unlabelled"


def orders(engine: Engine, ids: list[str] | None = None) -> list[dict[str, Any]]:
    """One row per checkout, newest first. `ids` limits the result (the live stream asks by id)."""
    if ids is not None:
        ids = [i for i in ids if isinstance(i, str) and 0 < len(i) <= 64][:MAX_IDS]
        if not ids:
            return []
    with engine.connect() as conn:
        query = select(
            checkout_sessions.c.id, checkout_sessions.c.status, checkout_sessions.c.checkout,
            checkout_sessions.c.created_us, checkout_sessions.c.updated_us,
        )  # fmt: skip
        if ids is not None:
            query = query.where(checkout_sessions.c.id.in_(ids))
        sessions = conn.execute(
            query.order_by(checkout_sessions.c.created_us.desc()).limit(MAX_ORDERS)
        ).all()
        wanted = [s.id for s in sessions]
        if not wanted:
            return []
        owners = {
            r.checkout_id: r
            for r in conn.execute(
                select(checkout_customers).where(checkout_customers.c.checkout_id.in_(wanted))
            )
        }
        sources = {
            r.checkout_id: r.source
            for r in conn.execute(
                select(checkout_sources).where(checkout_sources.c.checkout_id.in_(wanted))
            )
        }
        attempts = {
            r.checkout_id: r
            for r in conn.execute(
                select(
                    payment_attempts.c.checkout_id, payment_attempts.c.state,
                    payment_attempts.c.capture_id, payment_attempts.c.gate_code,
                    payment_attempts.c.principal,
                ).where(payment_attempts.c.checkout_id.in_(wanted))
            )
        }  # fmt: skip
        with_mandates = {
            r.checkout_id
            for r in conn.execute(
                select(attempt_mandates.c.checkout_id).where(
                    attempt_mandates.c.checkout_id.in_(wanted)
                )
            )
        }
        logs = _logs(
            conn, [*PROTOCOL_KINDS, *REFUSAL_KINDS, UNMANDATED_CAPTURE, "lock.decision"], wanted
        )
    protocol: dict[str, str] = {}
    refused: dict[str, str] = {}
    unmandated: dict[str, str] = {}
    for entry in logs:
        cid = entry.checkout_id or ""
        if entry.kind in PROTOCOL_KINDS:
            protocol.setdefault(cid, PROTOCOL_KINDS[entry.kind])
        elif entry.kind in REFUSAL_KINDS:
            codes = entry.payload.get("codes") or []
            if codes and isinstance(codes[0], str):
                refused[cid] = codes[0][:64]
        elif entry.kind == UNMANDATED_CAPTURE:
            capture = entry.payload.get("capture_id")
            unmandated[cid] = capture if isinstance(capture, str) else ""
    out = []
    for s in sessions:
        try:
            body = loads_strict(bytes(s.checkout))
        except Exception:  # noqa: BLE001 - a row that does not parse is shown without items
            body = {}
        items, amount, currency = _items(body if isinstance(body, dict) else {})
        attempt = attempts.get(s.id)
        owner = owners.get(s.id)
        status = str(s.status)
        gate: str | None = None
        if attempt is not None:
            if attempt.state == "captured":
                gate = "passed"
            elif attempt.state == "voided":
                gate = attempt.gate_code or "voided"
                status = "voided"
            elif attempt.state in IN_FLIGHT:
                gate = "pending"
        if status == "canceled" and s.id in refused:
            status = "rejected"
        if attempt is not None:
            mandate = "verified"
        elif s.id in refused:
            mandate = "refused"
        else:
            mandate = "not_presented"
        capture = attempt.capture_id if attempt is not None else None
        if s.id in unmandated:
            capture, mandate, gate = unmandated[s.id] or None, "not_presented", "not_run"
        captured = gate == "passed" or s.id in unmandated
        unauthorized = s.id in unmandated or (
            attempt is not None and attempt.state == "captured" and s.id not in with_mandates
        )
        stage = 0
        if mandate != "not_presented":
            stage = 1
        if mandate == "verified":
            stage = 2
        if attempt is not None and (
            attempt.state in AUTHORIZED or (attempt.state == "voided" and attempt.gate_code)
        ):
            stage = 3
        if captured:
            stage = 4
        blocked = status in ("rejected", "voided") or s.id in refused
        agent = owner.agent_thumbprint if owner is not None else None
        if agent is None and attempt is not None:
            agent = attempt.principal
        out.append(
            {
                "id": s.id,
                "created_at": _iso(int(s.created_us)),
                "created_us": int(s.created_us),
                "updated_us": int(s.updated_us),
                "agent": agent,
                "customer_id": owner.customer_id if owner is not None else None,
                "items": items,
                "amount_minor": amount,
                "currency": currency,
                "status": status,
                "mandate": mandate,
                "protocol": protocol.get(s.id, "ucp"),
                "gate": gate,
                "refusal": refused.get(s.id),
                "capture_id": capture,
                "source": _source(sources.get(s.id)),
                "funnel_stage": stage,
                "captured_minor": amount if captured else 0,
                "blocked": 1 if blocked else 0,
                "reason": (refused.get(s.id) or (gate if status == "voided" else None))
                if blocked
                else None,
                "unauthorized": 1 if unauthorized else 0,
            }
        )
    return out


def unauthorized_captures(engine: Engine) -> int:
    """Captures with no verified mandate behind them (see the module docstring)."""
    with engine.connect() as conn:
        without_mandates = conn.execute(
            select(func.count())
            .select_from(
                payment_attempts.outerjoin(
                    attempt_mandates,
                    attempt_mandates.c.checkout_id == payment_attempts.c.checkout_id,
                )
            )
            .where(payment_attempts.c.state == "captured", attempt_mandates.c.checkout_id.is_(None))
        ).scalar_one()
        unmandated = conn.execute(
            select(func.count())
            .select_from(decision_log)
            .where(decision_log.c.kind == UNMANDATED_CAPTURE)
        ).scalar_one()
    return int(without_mandates) + int(unmandated)


def mandates(engine: Engine, now_s: int) -> list[dict[str, Any]]:
    """Every open mandate with its lifecycle state and what was spent under it."""
    out: list[dict[str, Any]] = []
    with engine.connect() as conn:
        customers = [
            r[0]
            for r in conn.execute(
                select(open_mandates.c.customer_id)
                .distinct()
                .order_by(open_mandates.c.customer_id)
                .limit(2000)
            )
        ]
        for customer in customers:
            for view in list_for_customer(conn, customer, now_s):
                spent = view.purchase.get("amount_minor") if view.purchase else None
                out.append(
                    {
                        "id": view.id, "customer_id": customer, "agent": view.agent_thumbprint,
                        "state": view.state, "ceiling_minor": view.ceiling_minor,
                        "spent_minor": spent if isinstance(spent, int) else 0,
                        "currency": view.currency, "expires_at": _iso(view.exp * 1_000_000),
                        "created_at": _iso(view.created_us),
                    }
                )  # fmt: skip
    return out


def _event(entry: _Log, sources: dict[str, str]) -> dict[str, Any] | None:
    p = entry.payload
    stage, outcome, reason = "", "blocked", ""
    if entry.kind == "checkout.complete_rejected":
        codes = p.get("codes") or []
        stage, reason = "complete", codes[0] if codes and isinstance(codes[0], str) else "rejected"
    elif entry.kind == "lock.decision":
        if p.get("allowed") is not False:
            return None
        stage, reason = f"lock:{p.get('operation', '')}", str(p.get("reason", "denied"))
    elif entry.kind.startswith("acp.") and entry.kind.endswith("_denied"):
        stage, reason = "acp", str(p.get("reason", "denied"))
    elif entry.kind == "gate.rejected":
        stage, outcome, reason = "gate", "voided", str(p.get("code", "gate_rejected"))
    elif entry.kind == "checkout.customer_refused":
        stage, reason = "complete", str(p.get("code", "checkout_customer_mismatch"))
    elif entry.kind == UNMANDATED_CAPTURE:
        stage, outcome, reason = "baseline", "captured_unmandated", "no_mandate"
    else:
        return None
    cid = entry.checkout_id
    return {
        "seq": entry.seq, "at": _iso(entry.ts_us), "checkout_id": cid, "stage": stage[:40],
        "outcome": outcome, "reason": reason[:64],
        "source": _source(sources.get(cid or "")),
    }  # fmt: skip


def protection_events(engine: Engine) -> list[dict[str, Any]]:
    """Blocked and voided attempts with their reason codes, newest first."""
    with engine.connect() as conn:
        logs = _logs(conn, EVENT_KINDS, None)
        ids = sorted({e.checkout_id for e in logs if e.checkout_id})
        sources: dict[str, str] = {}
        for start in range(0, len(ids), 5000):
            chunk = ids[start : start + 5000]
            sources.update(
                {
                    r.checkout_id: r.source
                    for r in conn.execute(
                        select(checkout_sources).where(checkout_sources.c.checkout_id.in_(chunk))
                    )
                }
            )
    events = [e for e in (_event(x, sources) for x in logs) if e is not None]
    return list(reversed(events))[:MAX_EVENTS]


def eval_summary(path: Path) -> dict[str, Any] | None:
    """The summary of the latest eval report: counts only, no case detail."""
    try:
        report = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    summary = report.get("summary") if isinstance(report, dict) else None
    if not isinstance(summary, dict):
        return None
    keys = ("cases", "attacks_succeeded", "unauthorized_captures", "duplicate_paypal_objects",
            "mismatches", "errors")  # fmt: skip
    modes = {
        mode: {k: int(v[k]) for k in keys if isinstance(v.get(k), int)}
        for mode, v in summary.items()
        if mode in ("full", "baseline") and isinstance(v, dict)
    }
    generated = report.get("generated_at")
    return {
        "suite": str(report.get("suite", ""))[:40],
        "generated_at": generated if isinstance(generated, str) else None,
        "modes": modes,
    }


def latest_seq(engine: Engine) -> int:
    with engine.connect() as conn:
        value = conn.execute(select(func.max(decision_log.c.seq))).scalar_one()
    return int(value or 0)


def changed_since(engine: Engine, seq: int) -> tuple[int, list[str]]:
    """The checkouts named by log entries after `seq`, and the newest seq seen."""
    with engine.connect() as conn:
        rows = conn.execute(
            select(decision_log.c.seq, decision_log.c.checkout_id)
            .where(decision_log.c.seq > seq)
            .order_by(decision_log.c.seq)
            .limit(5000)
        ).all()
    if not rows:
        return seq, []
    ids = sorted({r.checkout_id for r in rows if r.checkout_id})[:MAX_IDS]
    return int(rows[-1].seq), ids


__all__ = [
    "API_VERSION", "changed_since", "eval_summary", "latest_seq", "mandates", "orders",
    "protection_events", "unauthorized_captures",
]  # fmt: skip

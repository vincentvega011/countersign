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
import math
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
    evidence_bundles,
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
SIMULATED_MANDATE_PREFIX = "om_sim_"  # reserved for ids the dev seed writes (Decision 123)
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
                        "source": "simulator"
                        if view.id.startswith(SIMULATED_MANDATE_PREFIX)
                        else "unlabelled",
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


def order_detail(engine: Engine, checkout_id: str) -> dict[str, Any] | None:
    """One order's row plus the stored evidence bundle text, or the reason there is none.

    The bundle is the one `GET /evidence/{capture_id}` serves: sanitized when it was stored (PayPal
    members pass an allowlist, the customer is a random id, only public keys). It is returned as the
    exact stored text so the browser verifier checks the same bytes the offline CLI would. Nothing here
    calls PayPal. `evidence.state` is one of: `bundle`; `simulated` (no bundle, a simulated row);
    `unmandated` (the baseline captured without a mandate, so no bundle can exist); `missing` (a
    verified capture with no bundle, L49); `not_captured` (nothing was captured).
    """
    rows = orders(engine, [checkout_id])
    if not rows:
        return None
    row = rows[0]
    with engine.connect() as conn:
        found = conn.execute(
            select(evidence_bundles.c.bundle).where(evidence_bundles.c.checkout_id == checkout_id)
        ).first()
    text = None if found is None else str(found[0])
    if text is not None:
        state = "bundle"
    elif row["source"] == "simulator":
        state = "simulated"
    elif row["unauthorized"]:
        state = "unmandated"
    elif row["gate"] == "passed":
        state = "missing"
    else:
        state = "not_captured"
    return {"order": row, "state": state, "bundle_text": text}


def eval_summary(path: Path) -> dict[str, Any] | None:
    """The summary of the latest eval report, with one short entry per case and mode."""
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
    cases: list[dict[str, Any]] = []
    for c in (report.get("cases") if isinstance(report.get("cases"), list) else [])[:400]:
        if not isinstance(c, dict) or c.get("mode") not in ("full", "baseline"):
            continue
        reason = c.get("reason_code")
        cases.append(
            {
                "case": str(c.get("case", ""))[:80], "category": str(c.get("category", ""))[:80],
                "mode": c["mode"], "outcome": str(c.get("outcome", ""))[:20],
                "reason_code": reason[:64] if isinstance(reason, str) else None,
                "unauthorized_captures": int(c["unauthorized_captures"])
                if isinstance(c.get("unauthorized_captures"), int) else 0,
                "captured_minor": int(c["captured_minor"])
                if isinstance(c.get("captured_minor"), int) else 0,
            }
        )  # fmt: skip
    return {
        "suite": str(report.get("suite", ""))[:40],
        "generated_at": generated if isinstance(generated, str) else None,
        "modes": modes,
        "cases": cases,
    }


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _num(value: Any) -> float:
    """A finite number or 0.0; `Infinity` or `NaN` in a report would make the JSON response fail."""
    ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    return float(value) if ok and math.isfinite(value) else 0.0


def _text(value: Any, limit: int = 300) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any, limit: int = 100) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)][:limit] if isinstance(value, list) else []


def eval_results(path: Path) -> dict[str, Any] | None:
    """The headline results of the frozen full evaluation (`results` in latest.json), reduced to the
    fields the Results view shows. Every value is re-typed here; a missing or malformed block is None."""
    try:
        report = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    res = report.get("results") if isinstance(report, dict) else None
    if not isinstance(res, dict):
        return None

    def mode_block(name: str, mode: str) -> dict[str, int]:
        block = _dict(_dict(res.get(name)).get(mode))
        keys = ("cases", "attacks_succeeded", "unauthorized_captures", "duplicate_paypal_objects")
        return {k: _int(block.get(k)) for k in keys}

    tasks = _dict(res.get("tasks"))
    gate = _dict(res.get("gate_latency"))
    evidence = _dict(res.get("evidence"))

    def task_block(mode: str) -> dict[str, Any]:
        t = _dict(tasks.get(mode))
        stage = _dict(t.get("capture_stage"))
        return {
            "runs": _int(t.get("runs")), "completed": _int(t.get("completed")),
            "false_blocks": _int(t.get("false_blocks")),
            "completion_rate": _num(t.get("completion_rate")),
            "false_block_rate": _num(t.get("false_block_rate")),
            "unauthorized_captures": _int(t.get("unauthorized_captures")),
            "duplicate_paypal_objects": _int(t.get("duplicate_paypal_objects")),
            "stage_p50_ms": _num(stage.get("p50_ms")), "stage_p95_ms": _num(stage.get("p95_ms")),
            "stage_calls": _int(stage.get("n")),
        }  # fmt: skip

    def evidence_block(mode: str) -> dict[str, int]:
        e = _dict(evidence.get(mode))
        keys = ("captures", "bundles", "python_pass", "browser_pass", "both_pass",
                "captures_without_bundle")  # fmt: skip
        return {k: _int(e.get(k)) for k in keys}

    return {
        "run_id": _text(res.get("run_id"), 40), "generated_at": _text(res.get("generated_at"), 40),
        "seeds": [_int(x) for x in res.get("seeds", [])][:10] if isinstance(res.get("seeds"), list) else [],
        "seed_invariant": res.get("seed_invariant") is True,
        "simulator": _text(res.get("simulator")),
        "attacks": {m: mode_block("attacks", m) for m in ("full", "baseline")},
        "adversary": {m: mode_block("adversary", m) for m in ("full", "baseline")},
        "tasks": {m: task_block(m) for m in ("full", "baseline")},
        "evidence": {m: evidence_block(m) for m in ("full", "baseline")},
        "gate_added_p50_ms": _num(gate.get("added_p50_ms")),
        "gate_added_p95_ms": _num(gate.get("added_p95_ms")),
        "baseline_gap": [_text(c, 80) for c in res.get("baseline_gap", [])][:60]
        if isinstance(res.get("baseline_gap"), list) else [],
        "categories": [
            {
                "category": _text(c.get("category"), 80), "cases": _int(c.get("cases")),
                "full_succeeded": _int(c.get("full_succeeded")),
                "baseline_succeeded": _int(c.get("baseline_succeeded")),
            }
            for c in _dicts(res.get("categories"))
        ],
        "ablations": [
            {
                "flag": _text(a.get("flag"), 60), "cases": _int(a.get("cases")),
                "reopened_count": _int(a.get("reopened_count")),
                "reopened": ", ".join(_text(x, 80) for x in a.get("reopened", []))[:400]
                if isinstance(a.get("reopened"), list) else "",
                "unauthorized_captures": _int(a.get("unauthorized_captures")),
                "duplicate_paypal_objects": _int(a.get("duplicate_paypal_objects")),
                "another_defense": len(a["blocked_by_another_defense"])
                if isinstance(a.get("blocked_by_another_defense"), list) else 0,
                "note": _text(a.get("note")),
            }
            for a in _dicts(res.get("ablations"))
        ],
        "targets": [
            {"target": _text(t.get("target")), "status": "met" if t.get("status") == "met" else "missed",
             "evidence": _text(t.get("evidence"), 500)}
            for t in _dicts(res.get("targets"))
        ],
        "caveats": [_text(c, 500) for c in res.get("caveats", [])][:20]
        if isinstance(res.get("caveats"), list) else [],
    }  # fmt: skip


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
    "API_VERSION", "changed_since", "eval_results", "eval_summary", "latest_seq", "mandates", "order_detail", "orders",
    "protection_events", "unauthorized_captures",
]  # fmt: skip

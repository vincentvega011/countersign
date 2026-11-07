"""The fixed catalog of read-only tools (docs/PROTOCOL.md Decision 125) and what each one does.

Security reasoning. A tool is a pure function from validated arguments and a `DataSource` to a
`ToolResult`: it reads the dashboard's own read models and builds fixed-template lines whose numbers and
identifiers all come from the rows it read, each bound to a citation. No tool writes, none can reach
PayPal, a secret or an authorization code path (this package imports none, and a test says so). A tool
never echoes a string chosen by the model, only values found in the data or fixed text. Arguments from the
planner are validated against the tool's JSON schema before anything runs (`catalog.validate_call`).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from countersign.assistant import codes
from countersign.assistant.data import DataSource
from countersign.assistant.model import Cite, Line, ToolResult

ID_PATTERN = "^[A-Za-z0-9_-]{1,64}$"
STATUSES = [
    "ready_for_complete",
    "incomplete",
    "complete_in_progress",
    "completed",
    "canceled",
    "rejected",
    "voided",
]
GROUPS = ["status", "mandate", "protocol", "source", "reason", "gate", "agent", "customer_id"]
MAX_ROWS = 10
MAX_CITES = 5


def money(minor: int, currency: str = "USD") -> str:
    sign = "-" if minor < 0 else ""
    major, cents = divmod(abs(minor), 100)
    body = f"{major:,}.{cents:02d}"
    return f"{sign}${body}" if currency == "USD" else f"{sign}{body} {currency}"


def plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def _order_cite(row: dict[str, Any]) -> Cite:
    return Cite("order", str(row["id"]), str(row["id"]))


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    schema: dict[str, Any]
    run: Callable[[DataSource, dict[str, Any]], ToolResult]


# ---------------------------------------------------------------------------------------- query_orders

_FILTERS = ("status", "mandate", "source", "protocol", "gate", "reason", "customer_id")


def _matches(row: dict[str, Any], args: dict[str, Any]) -> bool:
    for key in _FILTERS:
        if key in args and row.get(key) != args[key]:
            return False
    if "agent" in args and not str(row.get("agent") or "").startswith(args["agent"]):
        return False
    if "captured" in args and (row.get("captured_minor", 0) > 0) != args["captured"]:
        return False
    if "blocked" in args and bool(row.get("blocked")) != args["blocked"]:
        return False
    if "unauthorized" in args and bool(row.get("unauthorized")) != args["unauthorized"]:
        return False
    amount = int(row.get("amount_minor", 0))
    if "min_amount_minor" in args and amount < args["min_amount_minor"]:
        return False
    return not ("max_amount_minor" in args and amount > args["max_amount_minor"])


def query_orders(source: DataSource, args: dict[str, Any]) -> ToolResult:
    rows = [r for r in source.orders() if _matches(r, args)]
    currencies = sorted({str(r.get("currency", "")) for r in rows})
    currency = currencies[0] if len(currencies) == 1 else "USD"
    total = sum(int(r.get("amount_minor", 0)) for r in rows)
    captured = sum(int(r.get("captured_minor", 0)) for r in rows)
    limit = int(args.get("limit", 5))
    data: dict[str, Any] = {
        "count": len(rows),
        "amount_minor": total,
        "captured_minor": captured,
        "currency": currency,
        "rows": [
            {
                k: r.get(k)
                for k in (
                    "id",
                    "status",
                    "amount_minor",
                    "currency",
                    "mandate",
                    "gate",
                    "reason",
                    "source",
                    "created_at",
                )
            }
            for r in rows[:limit]
        ],
        "groups": [],
    }
    lines: list[Line] = []
    n = len(rows)
    cites = tuple(_order_cite(r) for r in rows[:MAX_CITES])
    lines.append(
        Line(f"{n} {plural(n, 'order matches', 'orders match')} the filter.", cites)
        if args
        else Line(
            f"There {plural(n, 'is', 'are')} {n} {plural(n, 'order', 'orders')} in total.", cites
        )
    )
    if n:
        lines.append(
            Line(
                f"Their total is {money(total, currency)}; captured: {money(captured, currency)}.",
                cites,
            )
        )
    group_by = args.get("group_by")
    if group_by and n:
        groups: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            value = r.get(group_by)
            groups.setdefault("none" if value in (None, "") else str(value), []).append(r)
        for key, members in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:MAX_ROWS]:
            size = len(members)
            data["groups"].append(
                {
                    "key": key,
                    "count": size,
                    "amount_minor": sum(int(m.get("amount_minor", 0)) for m in members),
                }
            )
            lines.append(
                Line(
                    f"{group_by} {key}: {size} {plural(size, 'order', 'orders')}, "
                    f"{money(sum(int(m.get('amount_minor', 0)) for m in members), currency)}.",
                    tuple(_order_cite(m) for m in members[:MAX_CITES]),
                )
            )
    elif not group_by:
        for r in rows[:limit]:
            lines.append(
                Line(
                    f"Order {r['id']}: {r['status']}, {money(int(r['amount_minor']), str(r['currency']))}, "
                    f"mandate {r['mandate']}, gate {r.get('gate') or 'not run'}.",
                    (_order_cite(r),),
                )
            )
    return ToolResult("query_orders", args, data, tuple(lines))


_QUERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string", "enum": STATUSES},
        "mandate": {"type": "string", "enum": ["verified", "refused", "not_presented"]},
        "source": {
            "type": "string",
            "enum": ["live_sandbox", "recorded", "simulator", "unlabelled"],
        },
        "protocol": {"type": "string", "enum": ["ucp", "acp"]},
        "gate": {
            "type": "string",
            "maxLength": 40,
            "description": "passed, pending, or a gate code",
        },
        "reason": {"type": "string", "maxLength": 64, "description": "a reason code"},
        "customer_id": {"type": "string", "pattern": ID_PATTERN},
        "agent": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{4,64}$",
            "description": "key thumbprint prefix",
        },
        "captured": {"type": "boolean"},
        "blocked": {"type": "boolean"},
        "unauthorized": {"type": "boolean", "description": "captured with no verified mandate"},
        "min_amount_minor": {"type": "integer", "minimum": 0},
        "max_amount_minor": {"type": "integer", "minimum": 0},
        "group_by": {"type": "string", "enum": GROUPS},
        "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
    },
}

# ----------------------------------------------------------------------------------------- order tools

_ORDER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["order_id"],
    "properties": {
        "order_id": {
            "type": "string",
            "pattern": ID_PATTERN,
            "description": "a checkout id, or latest, latest_captured or latest_voided",
        }
    },
}


REFS = ("latest", "latest_captured", "latest_voided")


def _find(source: DataSource, order_id: str) -> dict[str, Any] | None:
    """An order by id, or by one of the fixed references (newest first), resolved here, not by the model."""
    rows = source.orders()
    if order_id == "latest":
        return rows[0] if rows else None
    if order_id == "latest_captured":
        return next((r for r in rows if int(r.get("captured_minor", 0)) > 0), None)
    if order_id == "latest_voided":
        return next((r for r in rows if r.get("status") == "voided"), None)
    return next((r for r in rows if r.get("id") == order_id), None)


NOT_FOUND = "No order with that id exists."


def get_order(source: DataSource, args: dict[str, Any]) -> ToolResult:
    row = _find(source, args["order_id"])
    if row is None:
        return ToolResult("get_order", args, {"found": False}, (Line(NOT_FOUND),))
    cite = (_order_cite(row),)
    cur = str(row["currency"])
    data = {
        "found": True,
        "order": {
            k: row.get(k)
            for k in (
                "id",
                "status",
                "amount_minor",
                "currency",
                "mandate",
                "gate",
                "reason",
                "refusal",
                "source",
                "capture_id",
                "protocol",
                "created_at",
                "captured_minor",
            )
        },
    }
    lines = [
        Line(
            f"Order {row['id']} is {row['status']} for {money(int(row['amount_minor']), cur)}.",
            cite,
        ),
        Line(
            f"Mandate: {row['mandate']}. Gate: {row.get('gate') or 'not run'}. Protocol: {row['protocol']}.",
            cite,
        ),
        Line(f"Source: {row['source']}. Created {row['created_at']}.", cite),
    ]
    if row.get("capture_id"):
        lines.append(
            Line(
                f"PayPal capture {row['capture_id']} for {money(int(row['captured_minor']), cur)}.",
                cite,
            )
        )
    if row.get("reason"):
        lines.append(
            Line(
                f"Stopped with reason {row['reason']}.",
                (*cite, Cite("code", str(row["reason"]), str(row["reason"]))),
            )
        )
    return ToolResult("get_order", args, data, tuple(lines))


def get_gate_steps(source: DataSource, args: dict[str, Any]) -> ToolResult:
    row = _find(source, args["order_id"])
    if row is None:
        return ToolResult("get_gate_steps", args, {"found": False}, (Line(NOT_FOUND),))
    cite = (_order_cite(row),)
    gate = row.get("gate")
    steps: list[dict[str, str]] = []
    lines: list[Line] = []
    if gate is None or gate == "not_run":
        lines.append(Line("The capture gate did not run for this order.", cite))
    elif gate == "pending":
        lines.append(Line("The capture gate has not finished for this order.", cite))
    elif gate == "passed":
        steps = [{"code": c, "result": "passed"} for c in codes.GATE_ORDER]
    elif gate in codes.GATE_ORDER or gate == "G-CAPTURE":
        failed_at = (
            codes.GATE_ORDER.index(gate) if gate in codes.GATE_ORDER else len(codes.GATE_ORDER)
        )
        for i, c in enumerate(codes.GATE_ORDER):
            steps.append(
                {
                    "code": c,
                    "result": "passed"
                    if i < failed_at
                    else "failed"
                    if i == failed_at
                    else "not run",
                }
            )
        if gate == "G-CAPTURE":
            steps.append({"code": "G-CAPTURE", "result": "failed"})
    else:
        lines.append(Line("The order was voided but no gate step was recorded for it.", cite))
    for s in steps:
        extra = (Cite("code", s["code"], s["code"]),) if s["result"] == "failed" else ()
        meaning = (
            f" {codes.CODES[s['code']]}"
            if s["result"] == "failed" and s["code"] in codes.CODES
            else ""
        )
        lines.append(Line(f"{s['code']}: {s['result']}.{meaning}", (*cite, *extra)))
    return ToolResult(
        "get_gate_steps", args, {"found": True, "gate": gate, "steps": steps}, tuple(lines)
    )


def explain_error_code(source: DataSource, args: dict[str, Any]) -> ToolResult:
    code = args["code"]
    meaning = codes.CODES.get(code)
    if meaning is None:
        return ToolResult(
            "explain_error_code",
            args,
            {"known": False},
            (Line("I have no recorded explanation for that code."),),
        )
    return ToolResult(
        "explain_error_code",
        args,
        {"known": True, "code": code},
        (Line(f"{code}: {meaning}", (Cite("code", code, code),)),),
    )


def summarize_evidence(source: DataSource, args: dict[str, Any]) -> ToolResult:
    row = _find(source, args["order_id"])
    order_id = str(row["id"]) if row else args["order_id"]
    found = source.evidence(order_id) if row else None
    if found is None:
        return ToolResult("summarize_evidence", args, {"found": False}, (Line(NOT_FOUND),))
    cite = (Cite("order", order_id, order_id),)
    state = str(found.get("state"))
    steps = found.get("steps")
    if state != "bundle" or not isinstance(steps, list):
        text = codes.NO_EVIDENCE.get(state, "There is no evidence bundle for this order.")
        return ToolResult(
            "summarize_evidence",
            args,
            {"found": True, "state": state, "steps": []},
            (Line(text, cite),),
        )
    passed = sum(1 for s in steps if s.get("ok"))
    lines = [Line(f"{passed} of {len(steps)} evidence steps passed for order {order_id}.", cite)]
    for s in steps:
        name = str(s.get("name"))
        title = codes.STEP_TITLES.get(name, name)
        if s.get("ok"):
            outcome = "passed"
        elif s.get("code") == "keys_not_pinned":
            outcome = "not checked, because no trusted keys are pinned in the dashboard"
        else:
            outcome = f"failed with code {s.get('code') or 'unknown'}"
        lines.append(Line(f"{title}: {outcome}.", (Cite("evidence_step", order_id, title, name),)))
    return ToolResult(
        "summarize_evidence",
        args,
        {
            "found": True,
            "state": state,
            "passed": passed,
            "total": len(steps),
            "steps": [
                {"name": s.get("name"), "ok": bool(s.get("ok")), "code": s.get("code")}
                for s in steps
            ],
        },
        tuple(lines),
    )


# --------------------------------------------------------------------------------------- evaluation


def compare_modes(source: DataSource, args: dict[str, Any]) -> ToolResult:
    report = source.evaluation()
    if not report or not report.get("modes"):
        return ToolResult(
            "compare_modes",
            args,
            {"found": False},
            (Line("No evaluation report is available yet."),),
        )
    modes = report["modes"]
    suite = str(report.get("suite", ""))
    lines: list[Line] = []
    for mode in ("full", "baseline"):
        m = modes.get(mode)
        if not m:
            continue
        lines.append(
            Line(
                f"{mode.capitalize()} mode: {m.get('attacks_succeeded', 0)} of {m.get('cases', 0)} attack "
                f"cases succeeded; {m.get('unauthorized_captures', 0)} unauthorized captures; "
                f"{m.get('duplicate_paypal_objects', 0)} duplicate PayPal objects.",
                (
                    Cite(
                        "eval_case", suite or "attacks", f"{suite or 'attacks'} report, {mode} mode"
                    ),
                ),
            )
        )
    cases = report.get("cases") or []
    by: dict[str, dict[str, str]] = {}
    for c in cases:
        by.setdefault(str(c.get("case")), {})[str(c.get("mode"))] = str(c.get("outcome"))
    both = sorted(
        k for k, v in by.items() if v.get("full") == "blocked" and v.get("baseline") == "blocked"
    )
    differ = sorted(
        k for k, v in by.items() if v.get("full") == "blocked" and v.get("baseline") == "success"
    )
    if by:
        lines.append(
            Line(
                f"{len(differ)} {plural(len(differ), 'case separates', 'cases separate')} the modes; "
                f"{len(both)} {plural(len(both), 'case is', 'cases are')} blocked in both.",
                tuple(Cite("eval_case", k, f"{k}, baseline") for k in differ[:MAX_CITES]),
            )
        )
    data = {"found": True, "modes": modes, "separating": len(differ), "blocked_in_both": len(both)}
    return ToolResult("compare_modes", args, data, tuple(lines))


def blocked_attempts_by_reason(source: DataSource, args: dict[str, Any]) -> ToolResult:
    events = source.events()
    if "outcome" in args:
        events = [e for e in events if e.get("outcome") == args["outcome"]]
    counts = Counter(str(e.get("reason") or "none") for e in events)
    top = counts.most_common(int(args.get("limit", MAX_ROWS)))
    n = len(events)
    data = {"count": n, "reasons": [{"reason": r, "count": c} for r, c in top]}
    lines = [
        Line(
            f"There {plural(n, 'is', 'are')} {n} blocked or voided {plural(n, 'attempt', 'attempts')} in the decision log."
        )
    ]
    for reason, c in top:
        members = [e for e in events if str(e.get("reason") or "none") == reason]
        cites = tuple(Cite("log", str(e["seq"]), str(e["seq"])) for e in members[:MAX_CITES])
        lines.append(Line(f"{reason}: {c} {plural(c, 'attempt', 'attempts')}.", cites))
    return ToolResult("blocked_attempts_by_reason", args, data, tuple(lines))


def open_mandate_state(source: DataSource, args: dict[str, Any]) -> ToolResult:
    rows = source.mandates()
    if "state" in args:
        rows = [r for r in rows if r.get("state") == args["state"]]
    counts = Counter(str(r.get("state")) for r in rows)
    n = len(rows)
    cur = str(rows[0].get("currency", "USD")) if rows else "USD"
    data = {
        "count": n,
        "states": dict(counts),
        "mandates": [
            {
                k: r.get(k)
                for k in ("id", "state", "ceiling_minor", "spent_minor", "currency", "source")
            }
            for r in rows[:MAX_ROWS]
        ],
    }
    lines = [
        Line(
            f"There {plural(n, 'is', 'are')} {n} open {plural(n, 'mandate', 'mandates')} matching."
        )
    ]
    for state, c in sorted(counts.items()):
        members = [r for r in rows if r.get("state") == state]
        lines.append(
            Line(
                f"{codes.STATE_TEXT.get(state, state)}: {c}.",
                tuple(Cite("mandate", str(r["id"]), str(r["id"])) for r in members[:MAX_CITES]),
            )
        )
    for r in rows[: int(args.get("limit", 5))]:
        lines.append(
            Line(
                f"Mandate {r['id']} is {codes.STATE_TEXT.get(str(r['state']), r['state'])}: ceiling "
                f"{money(int(r['ceiling_minor']), cur)}, spent {money(int(r['spent_minor']), cur)}.",
                (Cite("mandate", str(r["id"]), str(r["id"])),),
            )
        )
    return ToolResult("open_mandate_state", args, data, tuple(lines))


# ------------------------------------------------------------------------------------------ catalog

TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "query_orders",
        "Count, total and list orders by exact filters, optionally grouped by one field.",
        _QUERY_SCHEMA,
        query_orders,
    ),
    ToolSpec("get_order", "Show one order by its checkout id.", _ORDER_SCHEMA, get_order),
    ToolSpec(
        "get_gate_steps",
        "Show the capture gate steps of one order and which one stopped it.",
        _ORDER_SCHEMA,
        get_gate_steps,
    ),
    ToolSpec(
        "explain_error_code",
        "Explain a Countersign error, reason or gate code.",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["code"],
            "properties": {"code": {"type": "string", "pattern": ID_PATTERN}},
        },
        explain_error_code,
    ),
    ToolSpec(
        "summarize_evidence",
        "Run the evidence verifier on one order's bundle and describe each step's result.",
        _ORDER_SCHEMA,
        summarize_evidence,
    ),
    ToolSpec(
        "compare_modes",
        "Compare full and baseline protection mode in the latest evaluation report.",
        {"type": "object", "additionalProperties": False, "properties": {}},
        compare_modes,
    ),
    ToolSpec(
        "blocked_attempts_by_reason",
        "Count blocked and voided attempts in the decision log by reason code.",
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "outcome": {"type": "string", "enum": ["blocked", "voided", "captured_unmandated"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
            },
        },
        blocked_attempts_by_reason,
    ),
    ToolSpec(
        "open_mandate_state",
        "Count open mandates by lifecycle state and list them with ceiling and spend.",
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "state": {"type": "string", "enum": list(codes.STATE_TEXT)},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
            },
        },
        open_mandate_state,
    ),
)
BY_NAME = {t.name: t for t in TOOLS}

"""Ask Countersign over the dashboard read API (Decisions 125 to 129): two GET routes, no writes.

`GET /dashboard/api/v1/assistant/suggestions` lists the recorded questions and the mode.
`GET /dashboard/api/v1/assistant/ask?q=...` plans with the model (or replays the recorded plan), runs the
read-only tools and returns the templated, cited, grounded answer. GET keeps the dashboard API free of any
mutating method; the call does not change any stored data.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter, FastAPI, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from countersign.assistant import Assistant
from countersign.dashboard.assistant_data import DashboardData
from countersign.dashboard.service import DashboardService
from countersign.llm import LlmConfig, LlmError, build_gateway

log = structlog.get_logger("countersign.assistant")
API = "/dashboard/api/v1/assistant"
ROOT = Path(__file__).resolve().parents[3]
RECORDED = ROOT / "eval" / "cassettes" / "assistant.json"
HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def recorded_model(path: Path = RECORDED) -> str | None:
    """The model id the planner cassettes were recorded with (the cassette key includes it)."""
    try:
        model = json.loads(path.read_text(encoding="utf-8")).get("model")
    except (OSError, ValueError):
        return None
    return model if isinstance(model, str) and model else None


def build_assistant(service: DashboardService) -> Assistant | None:
    """An assistant from the environment: replay by default. A bad live configuration disables it."""
    try:
        config = LlmConfig.from_env()
        if config.mode == "replay":
            config = replace(config, model=recorded_model() or config.model)
        return Assistant(build_gateway(config), DashboardData(service))
    except LlmError as error:
        log.warning("assistant_disabled", error=type(error).__name__)
        return None


def install(app: FastAPI, service: DashboardService) -> None:
    router = APIRouter()

    @router.get(f"{API}/suggestions")
    async def suggestions() -> JSONResponse:
        assistant: Assistant | None = service.assistant
        body: dict[str, Any] = {
            "version": 1,
            "mode": assistant.mode if assistant else "disabled",
            "suggestions": Assistant.suggestions(),
        }
        return JSONResponse(body, headers=HEADERS)

    @router.get(f"{API}/ask")
    async def ask(q: str = Query("", max_length=600)) -> JSONResponse:
        assistant: Assistant | None = service.assistant
        if assistant is None:
            body = {"status": "unavailable", "text": "The assistant is not available right now.",
                    "lines": [], "calls": [], "replaced": 0}  # fmt: skip
            return JSONResponse({"version": 1, "mode": "disabled", "answer": body}, headers=HEADERS)
        answer = await run_in_threadpool(assistant.ask, q)
        return JSONResponse(
            {"version": 1, "mode": assistant.mode, "answer": answer.to_dict()}, headers=HEADERS
        )

    app.include_router(router)

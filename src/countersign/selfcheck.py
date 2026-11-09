"""The startup self-check: what mode this process runs in and that no dev or evaluation switch is on.

Served as `GET /selfcheck` and logged once at start. It reports labels and booleans only: no secret,
no id, no URL with credentials, and environment variable NAMES but never values. `ok` is true only when
no ablation and no development switch is on, the mode is `full` (or the process is a labelled baseline
instance), and, in a public environment, no attack launcher is installed unless an administrator
database was deliberately named. `seed` holds counts only (orders, open mandates, bundles, whether the
demo seed is complete) in the dev and demo environments, `null` elsewhere; it never changes `ok`. A public deployment that reports `ok: false` should not be trusted.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from countersign.runtime import PUBLIC_ENVS, Mode, RuntimeSettings, dev_switches_on

VERSION = 1


def report(
    settings: RuntimeSettings,
    env: Mapping[str, str],
    *,
    dashboard: Any = None,
    webhook_configured: bool = False,
    rate_limited: bool = False,
    seed: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    switches = dev_switches_on(env)
    launcher = bool(dashboard is not None and dashboard.attack_runs_enabled())
    public = settings.app_env in PUBLIC_ENVS
    assistant = getattr(dashboard, "assistant", None)
    admin_url_named = bool(env.get("EVAL_DATABASE_ADMIN_URL"))
    ok = (
        not settings.ablations.any
        and not switches
        and not (public and launcher and not admin_url_named)
    )
    return {
        "version": VERSION,
        "ok": ok,
        "mode": settings.mode.value,
        "baseline_instance": settings.mode is Mode.BASELINE,
        "app_env": settings.app_env,
        "public_environment": public,
        "ablations": list(settings.active_ablations),
        "dev_switches_on": switches,
        "attack_runs_enabled": launcher,
        "dashboard_read_only": bool(dashboard is not None and settings.app_env != "dev"),
        "assistant_mode": getattr(assistant, "mode", "disabled") if assistant else "disabled",
        "paypal_sandbox_configured": bool(dashboard is not None and dashboard.paypal_configured),
        "webhook_verification_configured": webhook_configured,
        "rate_limited": rate_limited,
        "seed": dict(seed) if seed is not None else None,
    }

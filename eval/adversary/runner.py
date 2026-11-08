"""Run a scripted adversary goal against a fresh instance in one mode and judge it.

The target is a whole app built by the composition root and reached through its HTTP interface (the
ASGI test client, not a network socket). The verdict is the judge's, from PayPal state and the
decision log; the attempt log only records what the adversary did and saw.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agents.adversary.log import AttemptLog
from agents.adversary.scripts import SCRIPTS
from agents.adversary.session import Session
from eval.adversary.consent import EvalCounterparties
from eval.core import Ctx
from eval.harness import CaseRun, Databases
from eval.judge import judge
from tests.mode_support import make_world, reset, settings_for


@dataclass
class AdversaryRun:
    run: CaseRun
    attempts: int
    log_path: Path | None


def run_goal(
    attack_id: str, mode: str, dbs: Databases, log_path: Path | None = None
) -> AdversaryRun:
    if attack_id not in SCRIPTS:
        raise KeyError(attack_id)
    reset(dbs.admin)
    settings = settings_for(mode)
    world = make_world(dbs.app, settings)
    ctx = Ctx(world, dbs.admin, settings.mode.value)
    log = AttemptLog(attack_id, mode, log_path)
    session = Session(world.client, log, EvalCounterparties(ctx))
    error = None
    with world.client:
        try:
            SCRIPTS[attack_id](session)
        except Exception as exc:  # noqa: BLE001 - a crashed script is reported, never counted as blocked
            error = f"{type(exc).__name__}: {exc}"[:200]
    reason = session.last.code if session.last else None
    verdict = judge(ctx, dbs.app)
    return AdversaryRun(CaseRun(verdict, reason, [], error), len(log.entries), log_path)

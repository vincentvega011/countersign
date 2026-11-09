"""Ablation switches for evaluation (docs/architecture.md section 6, runtime modes), allowed in dev and eval only.

An ablation turns one protection off so the evaluation can show what it prevents. Only a dev or eval
process may run with one, so `Ablations.from_env` raises when any switch is set while `APP_ENV` is
anything else (demo, prod, or an unknown value), and the process does not start (INV-10). The test is
an allowlist on purpose: a new environment name is refused until it is added here. Unknown values are refused too: only
`0`, `1` and an unset variable are accepted, so a typo cannot silently turn a protection off or leave
it on.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

NAMES = (
    "ABL_NO_GATE",
    "ABL_NO_PRINCIPAL_LOCK",
    "ABL_NO_BUDGET_RECON",
    "ABL_NO_GLOBAL_NONCE",
    "ABL_NO_STRICT_JSON",
    "ABL_NO_PREAUTH_CHECK",
)


ABLATION_ENVS = ("dev", "eval")


class AblationRefused(RuntimeError):
    """An ablation is set where it is not allowed, or its value is not 0 or 1."""


@dataclass(frozen=True)
class Ablations:
    no_gate: bool = False
    no_principal_lock: bool = False
    no_budget_recon: bool = False
    no_global_nonce: bool = False
    no_strict_json: bool = False
    no_preauth_check: bool = False

    @property
    def any(self) -> bool:
        return any(vars(self).values())

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Ablations:
        source = os.environ if env is None else env
        flags: dict[str, bool] = {}
        for name in NAMES:
            value = source.get(name, "0")
            if value not in ("0", "1"):
                raise AblationRefused(f"{name} must be 0 or 1")
            flags[name.removeprefix("ABL_").lower()] = value == "1"
        result = cls(**flags)
        env_name = source.get("APP_ENV", "dev")
        if result.any and env_name not in ABLATION_ENVS:
            raise AblationRefused(f"ablations are refused when APP_ENV={env_name}")
        return result

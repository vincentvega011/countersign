"""Runtime mode and ablations, decided once at startup (docs/architecture.md section 6).

`CS_MODE` is `full` (the default) or `baseline`. `baseline` is the naive but careful gateway the
evaluation compares against; it is never selected by default and never inferred. Ablations switch off
exactly one protection inside `full`.

Security reasoning (INV-10). Every ambiguity fails the start, not the request:

- `CS_MODE` accepts only the two exact values. A typo cannot leave a deployment in a weaker mode.
- An ablation is refused when `APP_ENV=demo` (`countersign.ablations`), so a public deployment cannot
  be weakened by an environment variable.
- An ablation together with `CS_MODE=baseline` is refused. Baseline already is the weakened
  configuration; mixing the two would make a result impossible to name.
- Baseline is allowed in demo, because the side by side comparison needs it, but it must be asked for
  by name, it is logged at startup, and every response carries the mode (`MODE_HEADER`).

The settings are plain data. The composition root (`countersign.composition`) turns them into the
policy objects the invariant modules receive; those modules do not read the mode themselves.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from countersign.ablations import NAMES, AblationRefused, Ablations

MODE_HEADER = "X-Countersign-Mode"
ABLATIONS_HEADER = "X-Countersign-Ablations"


class Mode(StrEnum):
    FULL = "full"
    BASELINE = "baseline"


class ModeRefused(RuntimeError):
    """`CS_MODE` or its combination with ablations is not allowed. The process does not start."""


@dataclass(frozen=True)
class RuntimeSettings:
    mode: Mode = Mode.FULL
    app_env: str = "dev"
    ablations: Ablations = field(default_factory=Ablations)

    @property
    def active_ablations(self) -> tuple[str, ...]:
        """The `ABL_*` names that are on, in the order of `ablations.NAMES`."""
        return tuple(n for n in NAMES if getattr(self.ablations, n.removeprefix("ABL_").lower()))

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RuntimeSettings:
        source = os.environ if env is None else env
        raw = source.get("CS_MODE", "full")
        try:
            mode = Mode(raw)
        except ValueError:
            raise ModeRefused("CS_MODE must be 'full' or 'baseline'") from None
        app_env = source.get("APP_ENV", "dev")
        try:
            ablations = Ablations.from_env(source)
        except AblationRefused as error:
            raise ModeRefused(str(error)) from None
        if mode is Mode.BASELINE and ablations.any:
            raise ModeRefused("ablations are defined inside CS_MODE=full; unset them for baseline")
        return cls(mode, app_env, ablations)

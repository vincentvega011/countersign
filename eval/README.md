# Evaluation

`eval/` runs the attack cases against a whole Countersign app and judges each one from PayPal state
and the decision log. Figures are not repeated here: every number and table lives in the generated
report (`eval/reports/latest.json`, and `report.md` next to it in the newest timestamped directory).

## Run

```
make db                                    # Postgres from docker-compose
uv run python -m eval.run --suite attacks --mode both
uv run python -m eval.run --suite all --mode both     # every suite below
uv run python -m eval.run --mode full --case nonce_replay_new_session --no-write
```

- `--seeds 0,1,2` (with `--suite all --mode both`, also `make eval`): the release run. Every suite per seed, all ablations, evidence
  verification, charts, `results` in `latest.json` (Decision 134).
- `--suite attacks | adversary | tasks | properties | concurrency | all`. `--mode full | baseline | both`
  (not used by `properties` and `concurrency`). `--case ID` (repeatable) runs selected cases, goals or
  tasks. `--no-write` prints only.
- `attacks`: the cases under `eval/attacks/`, each re-performed by the test issuer and judged below.
- `adversary`: the scripted goals of `agents/adversary`, a separate process that speaks HTTP only. Each
  goal is named after the attack case it re-performs and must reach that case's declared outcome.
- `tasks`: legitimate purchases (`eval/tasks`): completion rate, false block rate, latency. One of them
  is a Human Present purchase through the Trusted Surface routes.
- `properties`, `concurrency`: pytest over fixed file lists with `--hypothesis-seed=0` (`eval/suites.py`).
- Scripted goals are fewer than the plan's twenty and are not model-planned (LIMITATIONS L65).
- A run creates a scratch database, migrates it, runs every case in every mode against a fresh
  application built by `countersign.composition.build_app` over the PayPal simulator, and drops it.
- It writes `eval/reports/<timestamp>/report.json`, `report.md` and merges into `eval/reports/latest.json`:
  a partial run replaces only the sections it ran, and every section carries its own date.
- The exit status is 1 if a case's outcome differs from its declared expectation, a case or task
  crashed, a task did not complete, or a pytest suite failed.
- The dashboard's "Run attack" button (dev, eval and demo only) runs one adversary goal against a fresh
  baseline and a fresh full instance (`eval/launch.py`, Decision 131).
- The results are deterministic: no identifier is part of a row, and `tests/integration/test_attack_suite.py`
  runs the suite twice and compares.

## What counts as success

An attack succeeds when money is captured outside what was signed or allowed, judged by `eval/judge.py`:

- a capture for a checkout no mandate covers;
- a capture above the signed total, of other goods than signed, or under a `custom_id` other than the
  recorded evidence reference;
- a capture made under a mandate that was void (for example revoked);
- a second capture under a key that may back one purchase (the open mandate, a closed nonce), or
  captures above the budget the open mandate was signed with;
- a PayPal call that can move money while handling input that must never move it.

A second order, authorization or capture for one checkout is a duplicate PayPal object and also counts.
No model output and no response body from Countersign is ever an input to the verdict. A case may also
record a non-money symptom (`side_effects`, for example an ambiguous body that was accepted); it is
reported and never counted as success.

## Add a case

Create `eval/attacks/<name>.py` that exports `CASE = AttackCase(...)`:

- `id`, `category` (see `docs/threat-model.md`), one line `description`, `actor`, `steps`, and the
  attacker's `success_condition` in words;
- `expected` for `"full"` and for `"baseline"`: `Expect(outcome, reason_code, note)`. Declare the true
  outcome. When baseline also blocks, say why in the note (defense in depth);
- `run(ctx)`: perform the steps with the helpers of `tests/mode_support.py`. Call `ctx.buy(...)` or
  `ctx.register(...)` for what the customer really signed, and `ctx.note(response)` on the decisive
  response so the report carries a reason code. Never decide success in the case: the judge does.

A case that succeeds in `full` is a security finding. Report it; do not change the expectation.

## Layout

| file | role |
| --- | --- |
| `core.py` | `AttackCase`, `Expect`, `Ctx` (what a case may do and register) |
| `suites.py` | the task rows and the pytest-backed property and concurrency suites |
| `release.py`, `verify.py`, `charts.py` | the release run, bundle verification with both verifiers, SVG charts |
| `launch.py` | one adversary goal against baseline and full, for the dashboard |
| `adversary/` | the harness side of the adversary: the customer and payer it is given, the runner |
| `tasks/` | the fixed legitimate purchases and their runner |
| `judge.py` | ground truth from the simulator's PayPal objects and the hash-chained log |
| `harness.py` | scratch database, one case in one configuration |
| `report.py` | `report.json`, `report.md`, `latest.json` |
| `run.py` | the command line |
| `attacks/` | one file per case |

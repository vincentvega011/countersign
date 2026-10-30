# Evaluation

`eval/` runs the attack cases against a whole Countersign app and judges each one from PayPal state
and the decision log. Figures are not repeated here: every number and table lives in the generated
report (`eval/reports/latest.json`, and `report.md` next to it in the newest timestamped directory).

## Run

```
make db                                    # Postgres from docker-compose
uv run python -m eval.run --suite attacks --mode both
uv run python -m eval.run --mode full --case nonce_replay_new_session --no-write
```

- `--mode full | baseline | both`. `--case ID` (repeatable) runs selected cases. `--no-write` prints
  only.
- A run creates a scratch database, migrates it, runs every case in every mode against a fresh
  application built by `countersign.composition.build_app` over the PayPal simulator, and drops it.
- It writes `eval/reports/<timestamp>/report.json`, `report.md` and updates `eval/reports/latest.json`.
- The exit status is 1 if a case's outcome differs from its declared expectation or a case crashed.
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
| `judge.py` | ground truth from the simulator's PayPal objects and the hash-chained log |
| `harness.py` | scratch database, one case in one configuration |
| `report.py` | `report.json`, `report.md`, `latest.json` |
| `run.py` | the command line |
| `attacks/` | one file per case |

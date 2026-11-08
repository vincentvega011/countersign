# Evaluation report 20261108T063449Z

Generated 2026-11-08T06:45:56Z. Seeds 0, 1, 2. Ground truth: PayPal state as held by the PayPal simulator (tests/paypal_sim.py), not live PayPal, the hash-chained decision log, and the two evidence verifiers. No model output or response body is an input to any verdict.

Per-run data: `report.json` in this directory. Charts: `charts/`.

## Totals per mode

Attack suite, one seed (the suites below are repeated for every seed and the results are identical across seeds: **True**).

| mode | cases | attacks succeeded | unauthorized captures | duplicate PayPal objects | mismatches | errors |
| --- | --- | --- | --- | --- | --- | --- |
| full | 40 | 0 | 0 | 0 | 0 | 0 |
| baseline | 40 | 11 | 12 | 0 | 0 | 0 |

Scripted adversary goals, one seed.

| mode | goals | succeeded | unauthorized captures | duplicate PayPal objects |
| --- | --- | --- | --- | --- |
| full | 12 | 0 | 0 | 0 |
| baseline | 12 | 6 | 6 | 0 |

## Per category

| category | cases | full: succeeded | baseline: succeeded | baseline: unauthorized captures |
| --- | --- | --- | --- | --- |
| agent_self_approval | 1 | 0 | 0 | 0 |
| alg_confusion | 2 | 0 | 0 | 0 |
| budget_split | 1 | 0 | 0 | 0 |
| cancel_during_completion | 1 | 0 | 0 | 0 |
| category_escape | 1 | 0 | 0 | 0 |
| checkout_swap | 2 | 0 | 0 | 0 |
| consent_missing | 2 | 0 | 0 | 0 |
| custom_id_tamper | 2 | 0 | 2 | 3 |
| decimal_ambiguity | 2 | 0 | 0 | 0 |
| double_complete_retry | 2 | 0 | 0 | 0 |
| double_spend_across_protocols | 1 | 0 | 1 | 1 |
| duplicate_json_keys | 1 | 0 | 0 | 0 |
| evidence_tamper | 1 | 0 | 0 | 0 |
| mandate_expired | 1 | 0 | 0 | 0 |
| mandate_forged | 4 | 0 | 0 | 0 |
| mandate_revoked | 4 | 0 | 1 | 1 |
| merchant_authorization_strip | 1 | 0 | 0 | 0 |
| new_session_escape | 1 | 0 | 0 | 0 |
| nonce_replay | 1 | 0 | 1 | 1 |
| open_mandate_double_spend | 2 | 0 | 2 | 2 |
| order_changed_after_approval | 2 | 0 | 2 | 2 |
| price_change_before_complete | 2 | 0 | 0 | 0 |
| protocol_downgrade_acp | 1 | 0 | 1 | 1 |
| unmandated_acp_unlocked | 1 | 0 | 1 | 1 |
| webhook_spoof | 1 | 0 | 0 | 0 |

Cases that succeed in baseline (11): `custom_id_tamper`, `double_spend_across_protocols`, `invoice_id_tamper`, `mandate_revoked`, `nonce_replay_new_session`, `open_mandate_double_spend`, `open_mandate_reuse_new_presentation`, `order_items_changed_after_approval`, `order_raised_after_approval`, `protocol_downgrade_acp`, `unmandated_acp_unlocked`.

## Per ablation

Each ablation turns one protection off in `full` mode and runs all 40 attack cases. "Reopens" means the attack succeeded (money captured outside what was signed or allowed).

| ablation | reopens | unauthorized captures | duplicate PayPal objects | still blocked, by a different reason | note |
| --- | --- | --- | --- | --- | --- |
| `ABL_NO_GATE` | nothing | 0 | 0 | none | Reopens nothing and changes no case's outcome or reason code in this suite. No attack case reaches the gate with a difference to catch: PayPal rejects every change after authorization (PROTOCOL 4.3), so checks that run before authorization stop every case first. The combined row shows the cases the gate alone stops once the pre-authorize check is also off. |
| `ABL_NO_PREAUTH_CHECK` | nothing | 0 | 0 | `custom_id_tamper`, `invoice_id_tamper`, `order_items_changed_after_approval`, `order_raised_after_approval` | Reopens nothing: 4 case(s) change reason code (payment_failed) but stay blocked. The gate voids the authorization instead (the cases end blocked with payment_failed). |
| `ABL_NO_PRINCIPAL_LOCK` | nothing | 0 | 0 | `double_spend_across_protocols`, `protocol_downgrade_acp` | Reopens nothing: 2 case(s) change reason code (unmandated_checkout_not_allowed) but stay blocked. Another check still refuses the unmandated completes, with a different reason code. |
| `ABL_NO_BUDGET_RECON` | nothing | 0 | 0 | `webhook_spoof` | Reopens nothing: 1 case(s) change reason code (http_404) but stay blocked. The only case it touches is the webhook spoof, which is refused because no webhook endpoint is mounted without reconciliation; no case drives the budget through PayPal-side state. |
| `ABL_NO_GLOBAL_NONCE` | `nonce_replay_new_session`, `open_mandate_double_spend`, `open_mandate_reuse_new_presentation` | 3 | 0 | none | Reopens the listed attacks. |
| `ABL_NO_STRICT_JSON` | nothing | 0 | 0 | `decimal_ambiguity`, `duplicate_json_keys` | Reopens nothing: 2 case(s) change reason code (http_201, invalid_field) but stay blocked. The lenient parser accepts the body, and the field validation downstream still refuses it. |
| `ABL_NO_GATE+ABL_NO_PREAUTH_CHECK` | `custom_id_tamper`, `invoice_id_tamper`, `mandate_revoked`, `order_items_changed_after_approval`, `order_raised_after_approval` | 7 | 0 | none | Both layers off at once (not an architecture ablation): reopens the listed attacks. |

## Legitimate tasks

27 tasks per seed, 3 seeds, pooled.

| mode | runs | completed | completion rate | false blocks | false block rate | unauthorized captures |
| --- | --- | --- | --- | --- | --- | --- |
| full | 81 | 81 | 100.0% | 0 | 0.0% | 0 |
| baseline | 81 | 81 | 100.0% | 0 | 0.0% | 0 |

## Gate latency

Measured over the PayPal simulator (tests/paypal_sim.py), not live PayPal: the time spent in the capture stage per call (the gate in full, immediate capture in baseline). It excludes the HTTP layer and the Credential Provider. It is simulator latency: real PayPal round trips are slower and are not in these numbers.

| mode | calls | p50 ms | p95 ms | end-to-end task p50 ms | end-to-end p95 ms |
| --- | --- | --- | --- | --- | --- |
| full | 162 | 28.4 | 34.1 | 92.2 | 136.2 |
| baseline | 162 | 10.1 | 11.8 | 68.1 | 106.6 |

Added by the gate: +18.3 ms at p50, +22.3 ms at p95 (full minus baseline).

## Evidence bundles

Every stored bundle, with the merchant and platform keys pinned, run through the Python CLI and the browser verifier (Node), twelve steps each. Bundles from seed 0 (attack and task suites).

| mode | captures | bundles | Python verifier passes | browser verifier passes | both pass | captures without a bundle |
| --- | --- | --- | --- | --- | --- | --- |
| full | 37 | 0 | 0 | 0 | 0 | 37 |
| baseline | 48 | 0 | 0 | 0 | 0 | 48 |

Recorded sandbox capture 49029167TJ689282S (the P3 gate replay, the only capture with a bundle): Python CLI pass, browser verifier pass.

## Properties and concurrency

| seed | properties passed | failed | concurrency passed | failed |
| --- | --- | --- | --- | --- |
| 0 | 74 | 0 | 27 | 0 |
| 1 | 74 | 0 | 27 | 0 |
| 2 | 74 | 0 | 27 | 0 |

## Targets

| target | status | evidence |
| --- | --- | --- |
| Unauthorized captures: 0 (full) | met | 0 across attacks, adversary goals and tasks; baseline attacks: 12 |
| Attack success rate: 0% on deterministic cases (full) | met | 0 of 40 (baseline 11 of 40) |
| Duplicate PayPal objects: 0 | met | 0 in full |
| Evidence bundles verifying: 100% of captures | missed | 0 of 37 full-mode captures have a bundle that passes all steps in both verifiers; 37 captures have no bundle (bundles are assembled only for an open-then-closed chain backed by a device consent; the test issuer signs no consent and the human-present flow has no open mandate) |
| The recorded sandbox capture's bundle verifies in both verifiers | met | capture 49029167TJ689282S, replayed through the P3 gate test: Python CLI pass, browser verifier pass, twelve steps each, keys pinned |
| Legitimate task completion: at least 90% | met | 100.0% (81 of 81 runs) |
| False block rate: reported | met | 0.0% (0 of 81) |
| Gate added latency p50 and p95: reported | met | +18.3 ms p50, +22.3 ms p95, over the simulator |
| Attack suite: at least 40 cases | met | 40 cases |
| Agent task suite: at least 25 legitimate purchases | met | 27 tasks per seed through the issuer, not the model-driven shopper |
| Concurrency and properties green | met | properties [74, 74, 74], concurrency [27, 27, 27] |
| Adversary LLM runs: 20 goals x 3 seeds, ASR with a 95% CI | missed | missed: 12 scripted goals per seed, no model-planned adversary (L65), so no ASR or CI is reported |
| Spec conformance as a runner suite | missed | missed: the conformance tests run in make test, not as an eval suite |
| Baseline vs full and per-ablation charts | met | charts/ in the run directory |

## What these numbers do not show

- The adversary is scripted: 12 fixed goals per seed, each re-performing one attack case. No model plans an attack, so there is no attack success rate with a confidence interval, and no claim about an adaptive attacker (L65).
- The baseline gap is 11 of 40 cases. The other cases are blocked in baseline too (defense in depth in the careful baseline), so the cases widen coverage without widening the gap between the modes (L67).
- Latency is simulator latency. The PayPal simulator answers in memory, so the gate's added time is its own computation and database work, not PayPal round trips.
- The legitimate tasks run through the test issuer and the PayPal simulator, not the model-driven shopper or live PayPal. The completion rate is for those fixed purchases.
- Seeds change only the Hypothesis examples. The attack, adversary and task suites have no randomness, so three seeds are three repetitions, not three samples of a distribution.
- Ground truth is simulator state. The simulator is our model of PayPal; agreement with live PayPal is established by the recorded cassettes and the sandbox smoke script, not by this report.
- Nothing here is a claim about PayPal buyer or seller protection or dispute outcomes. The evidence bundles are verified for internal consistency and signatures, not for how any dispute would be decided.
- Passing counts are counts of passing tests under a seed, not of Hypothesis examples.

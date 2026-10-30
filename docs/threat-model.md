# Threat model

Notes recorded so far. The full model (assets, actors, trust boundaries, and each attack category
mapped to an invariant and a test) is written later.

## Order changes between payer approval and authorization

- **Fact.** In the sandbox, PATCH of an order's items and amount was accepted while the order was
  `APPROVED`, and authorize then authorized the patched amount, with no new payer approval. After
  authorization every PATCH was rejected ([PROTOCOL.md](PROTOCOL.md) section 4.3).
- **Who can do it.** PayPal's schema lists only OAuth 2.0 bearer authentication for the update
  order operation (documentation, not tested with other credentials). The PATCH calls in the runs
  used the merchant app's access token. The modeled actor is therefore a compromised or buggy
  merchant-side component, or a confused deputy using the merchant app credentials, not the buyer
  or the agent. Countersign does not claim that the agent can alter orders.
- **Defense.** The pre-authorize check ([PROTOCOL.md](PROTOCOL.md) Decision 11), with the capture
  gate as the second layer.
- **Attack case.** `order_changed_after_approval`.

## Attack cases, invariants and tests

The first 25 attack cases live in `eval/attacks/` (one file each) and run in `full` and `baseline`
with `uv run python -m eval.run --suite attacks --mode both`. Each is judged from PayPal state and the
decision log (`eval/judge.py`), never from a response body. The outcome of the latest run is in
`eval/reports/latest.json`; this table says what defends against what. Every case is exercised by
`tests/integration/test_attack_suite.py`; the second test column is the unit or integration test of the
defense itself.

| Case | Category | Actor | Invariant | Defense test |
| --- | --- | --- | --- | --- |
| `protocol_downgrade_acp` | protocol_downgrade_acp | malicious agent | INV-3, INV-5 | `test_acp.py`, `test_lock.py` |
| `new_session_escape` | new_session_escape | malicious agent | INV-3, INV-5 | `test_lock_ucp.py` |
| `double_spend_across_protocols` | double_spend_across_protocols | malicious agent | INV-3, INV-5, INV-6 | `test_acp.py` |
| `unmandated_acp_unlocked` | unmandated_acp_unlocked | malicious agent | INV-3 | `test_acp.py` (unmandated seam) |
| `order_raised_after_approval` | order_changed_after_approval | compromised merchant-side component | INV-4, INV-10 | `test_ucp_complete.py`, `test_gate_flow.py` |
| `order_items_changed_after_approval` | order_changed_after_approval | compromised merchant-side component | INV-4, INV-10 | `test_gate_flow.py` |
| `custom_id_tamper` | custom_id_tamper | compromised merchant-side component | INV-4, INV-10 | `test_gate_flow.py` |
| `invoice_id_tamper` | custom_id_tamper | compromised merchant-side component | INV-4, INV-11 | `test_gate_flow.py` |
| `mandate_revoked` | mandate_revoked | malicious agent | INV-4 | `test_gate_flow.py` (G-MANDATE) |
| `nonce_replay_new_session` | nonce_replay | malicious agent | INV-6 | `test_cp_database.py`, `test_ucp_complete.py` |
| `open_mandate_double_spend` | open_mandate_double_spend | malicious agent | INV-6 | `test_merchant_decision_log.py`, `test_cp_concurrency.py` |
| `budget_split` | budget_split | malicious agent | INV-6, INV-7 | `test_cp_budget_property.py` |
| `checkout_swap` | checkout_swap | malicious agent | INV-1, INV-6 | `test_merchant_verify.py` |
| `price_change_before_complete` | price_change_before_complete | malicious agent | INV-1, INV-9 | `test_merchant_verify.py` |
| `category_escape` | category_escape | malicious agent | INV-1 | `test_constraints_wiring.py` |
| `consent_missing` | consent_missing | malicious agent | INV-1, INV-2 | `test_mandates_units.py` |
| `mandate_forged` | mandate_forged | malicious agent | INV-1 | `test_mandate_mutation.py` |
| `alg_confusion_none` | alg_confusion | malicious agent | INV-1 | `test_mandate_vectors.py` |
| `alg_confusion_hs256` | alg_confusion | malicious agent | INV-1 | `test_mandate_vectors.py` |
| `mandate_expired` | mandate_expired | malicious agent | INV-10 | `test_merchant_verify.py` |
| `merchant_authorization_strip` | merchant_authorization_strip | network attacker | INV-1 | `test_merchant_verify.py` |
| `duplicate_json_keys` | duplicate_json_keys | malicious agent | INV-8 | `test_canonical_jsonstrict.py`, `test_acp.py` |
| `decimal_ambiguity` | decimal_ambiguity | malicious agent | INV-8, INV-9 | `test_canonical_jsonstrict.py` |
| `webhook_spoof` | webhook_spoof | network attacker | INV-4, INV-7, INV-10 | `test_webhooks.py` |
| `double_complete_retry` | double_complete_retry | malicious agent | INV-6, INV-11 | `test_ucp_complete_gate.py`, `test_complete_race.py` |

Notes on what the cases do and do not cover:

- `consent_missing` is defined as "a well formed mandate chain whose issuer link is not signed by the
  trusted platform key", because the platform signs only after the customer's device key signed consent
  ([PROTOCOL.md](PROTOCOL.md) Decision 5). The device consent signature itself belongs to the Trusted
  Surface (P3) and is not verified yet, so that half is untested.
- `category_escape` tests the mandate level `checkout.line_items` constraint. A merchant level category
  policy (Decision 3) is not built, so it has no case yet.
- `webhook_spoof` runs against the simulator's verification verdict. Live delivery is not confirmed
  ([LIMITATIONS.md](LIMITATIONS.md) L26).
- A concurrent burst of `complete` calls can void the winner's own authorization
  ([LIMITATIONS.md](LIMITATIONS.md) L28); it is a liveness defect, not a money one, and it is outside
  the deterministic suite.


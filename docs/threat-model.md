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
| `double_complete_retry` | double_complete_retry | malicious agent | INV-6, INV-11 | `test_complete_ownership.py`, `test_complete_stress.py` |
| `cancel_during_completion` | cancel_during_completion | malicious agent | INV-4, INV-10, INV-12 | `test_cancel_during_completion.py` |

Notes on what the cases do and do not cover:

- `consent_missing` is defined as "a well formed mandate chain whose issuer link is not signed by the
  trusted platform key", because the platform signs only after the customer's device key signed consent
  ([PROTOCOL.md](PROTOCOL.md) Decisions 5 and 81). The device consent signature is verified at issuance
  (`tests/integration/test_consent.py`); a chain verifier never sees it, so the case tests the platform
  key and the issuance tests test the consent.
- `category_escape` tests the mandate level `checkout.line_items` constraint. A merchant level category
  policy (Decision 3) is not built, so it has no case yet.
- `webhook_spoof` runs against the simulator's verification verdict. Live delivery is not confirmed
  ([LIMITATIONS.md](LIMITATIONS.md) L26).
- A concurrent burst of `complete` calls used to be able to void the winner's own authorization; that was
  fixed by the ownership rule ([PROTOCOL.md](PROTOCOL.md) Decision 67, [LIMITATIONS.md](LIMITATIONS.md)
  L28) and `double_complete_retry` is a real concurrent burst again.

## Cancel while completing

- **Fact.** Before P2.12 a cancel was accepted in every non-final status and the gate never re-read the
  checkout ([LIMITATIONS.md](LIMITATIONS.md) L30).
- **Who can do it.** Anyone who knows a checkout id: the agent, a platform retrying, a third party that
  saw the id. It moves no money by itself; the harm is a trail that contradicts itself (canceled with a
  capture, no receipts), which is the evidence a dispute depends on.
- **Defense.** Entry guard: cancel is refused once a payment attempt exists or the checkout is completing
  ([PROTOCOL.md](PROTOCOL.md) Decision 70, one function for UCP and ACP, `full` and `baseline`). Gate:
  G-CHECKOUT re-reads the checkout `FOR SHARE` in the transaction that moves the attempt to `capturing`
  (Decision 71). Baseline ACP claims the session before it can pay (Decision 72).
- **Attack case.** `cancel_during_completion` (blocked in both modes, because both share the entry guard).
  The gate re-check is covered by a test that cancels straight in the store, a lock-wait test, and
  forced interleavings; `tests/integration/test_cancel_during_completion.py`.
- **Not defended.** An expiry that cancels a completing checkout is caught by the gate only if it runs;
  otherwise `recover` voids the authorization (P5.1 schedules it).

## Device key enrolment

The Trusted Surface key is the root of "the customer approved this" ([PROTOCOL.md](PROTOCOL.md) Decision 5), so
enrolment is where a false customer would be created. Code: `src/countersign/trusted_surface/`, tests
`tests/integration/test_trusted_surface.py`, `tests/unit/test_trusted_surface_keys.py`,
`tests/unit/test_approve_static.py` and the browser tests in `web/approve/test/`.

| Attack | Actor | Defense | Code |
| --- | --- | --- | --- |
| Register a key with a private part or extra members, a weak curve or an off-curve point | malicious client | strict JWK validation, thumbprint computed on the server | `jwk_*` |
| Register a key the caller does not hold | malicious client | proof of possession over a server-rebuilt record | `proof_invalid` |
| Replay a captured registration | network attacker | single use challenge (INSERT with a unique key), 5 minute expiry from the issue time | `challenge_used`, `challenge_expired` |
| Use a challenge for another purpose, key, customer or origin | malicious client or page | all of them are inside the signed record | `proof_invalid`, `challenge_purpose_mismatch` |
| Enrol from a look-alike page on another origin | phishing page | the signed record names the page origin, and the server compares it to the configured origin and the `Origin` header | `origin_mismatch` |
| Add the attacker's key to a victim's customer id | malicious client | the same record must be signed by a current, non-revoked key of that customer | `authorizer_*` |
| Claim a key that belongs to another customer | malicious client | thumbprint is the primary key; a different customer is a conflict | `key_conflict` |
| Race many registrations on one challenge | malicious client | exactly one INSERT on the challenge id commits | `challenge_used` |
| Rewrite or delete a registered key | compromised application | no UPDATE or DELETE grant; an immutability trigger | database error |
| Steal the private key from the page | cross-site script | the key is non-extractable; a strict CSP with no inline script and no other origin; no model text | n/a |
| Make the page show attacker text | malicious service answer | fixed templates; the only dynamic text is a code that matches a plain pattern | n/a |

Invariants: INV-1 (all checks deterministic), INV-2 (non-agentic page, non-extractable key), INV-8 (strict JSON
before anything else), INV-10 (fail closed, including a log failure), INV-12 (log before answer).

- **Not defended.** Creating a new customer is unauthenticated, so an attacker can enrol their own key and
  get a customer id of their own ([LIMITATIONS.md](LIMITATIONS.md) L35); they cannot take over another
  customer's id. A compromised browser or device can use the key it holds. Challenges and refusals are not
  rate limited (L37).

## Consent, mandate issuance and revocation

Where "the customer approved this" becomes a signed mandate. Code: `src/countersign/trusted_surface/`
(`consent.py`, `service.py`, `issuer.py`), tests `tests/integration/test_consent.py`,
`tests/integration/test_trusted_surface.py`, `tests/unit/test_mandates_subject.py`, the shared mandate
vectors and the browser tests in `web/approve/test/`.

| Attack | Actor | Defense | Code |
| --- | --- | --- | --- |
| Get mandates issued with no consent | malicious agent or client | the platform signs only inside a verified consent; there is no other issuing path | `consent_*` |
| Change the terms after the person looked (ceiling, item, merchant, expiry, agent key) | page script, proxy, malicious agent | the device signs the JCS bytes of the record the page rendered; any change breaks the signature | `consent_signature_invalid` |
| A signed record whose claims say more than its terms | compromised or buggy page | the backend rebuilds the mandate contents from the terms and compares the JCS bytes | `consent_claims_mismatch` |
| Terms that are signed but not honest (another store, an item as titled by the agent, a huge ceiling, a long expiry) | malicious agent | the terms are checked against this store's merchant record and catalog and fixed limits | `consent_terms_invalid` |
| Replay a consent or reuse its nonce | network attacker | single use nonce (INSERT), 5 minutes, record expiry | `challenge_used`, `challenge_expired`, `consent_expired` |
| Consent from a look-alike origin | phishing page | the signed record names the origin; the server compares it and the `Origin` header | `origin_mismatch` |
| Consent with an unregistered, revoked or another customer's key | malicious client | the stored key of that customer is the only verifier; revoked keys are refused | `device_key_*` |
| Consent racing a revocation | malicious client | one per-customer lock serializes them; the second one sees the first | `device_key_revoked` |
| Put agent-written text on the approval page | malicious agent (an LLM) | the proposal carries only ids, numbers and a key; store name and item titles come from the store; fixed templates | `intent_invalid` |
| Hide or reorder parts of an issued mandate | malicious agent | the issuer never makes a constraint element selectively disclosable; one disclosure; unreferenced disclosures are refused | `constraint_element_disclosure` |
| Use a mandate that names no customer | malicious agent, compromised issuer | `sub` is mandatory and read from the signed payload | `subject_missing` |
| Make a revoked key valid again, or revoke another customer's key | malicious client | revocations are insert only; the signer must be a live key of the same customer | `key_revoked`, `signer_*`, `key_unknown` |
| Two keys revoking each other so nobody can speak for a customer | malicious client | per-customer lock: exactly one revocation wins | `signer_revoked` |
| Present a used open mandate again, rewritten (new nonce, checkout, key binding or `(r, n - s)` signature) | malicious agent | single use, the budget row and revocation key on the issuer-signed identity (Decision 86) | `open_mandate_in_use`, `mandate_scope_mismatch` |
| Buy after the customer revoked, or revoke racing the capture | malicious agent, customer | revocation checked at reservation, before authorizing and at the claim under the open mandate's row lock; a started capture answers `in_flight` and nothing is written | `mandate_revoked`, `in_flight` |
| Collect another agent's mandates, or consent on its behalf | stolen proposal id, other agent | the agent key stored with the proposal must sign a fresh single use challenge; the id is only an address | `proof_invalid`, `challenge_used` |
| Sign a checkout that differs from the merchant's | page script, proxy | terms come from the VERIFIED merchant JWT; the backend rebuilds terms and mandates and compares bytes; changed, expired or unready checkouts yield nothing | `consent_claims_mismatch`, `checkout_changed` |
| Read or revoke another customer's approvals, or revoke with a stolen token | malicious client, token thief | reading needs a device-key proof (5 minute token, hash stored); revoking needs its own signature naming the mandate; other customers' mandates look nonexistent | `session_*`, `proof_invalid`, `open_mandate_unknown` |

Invariants: INV-1 (all checks deterministic, no model input), INV-2 (non-agentic page, non-extractable key, no
agent text), INV-6 (single use nonce and open mandate identity), INV-8 (strict JSON and JCS), INV-9 (integer minor units), INV-10 (fail
closed, including a log failure), INV-12 (log before answer).

- **Not defended.** A person who is shown a faithful request can still approve a bad one; the page shows
  exactly what will be signed, no more. The platform key is the one trusted issuer, and the same entity plays
  Merchant, Credential Provider and processor ([LIMITATIONS.md](LIMITATIONS.md)); the device signature is the
  independent check on a rogue platform key. A compromised device can sign what its key holds. Creating a
  customer is unauthenticated (L35).

## Shopping agent and evidence bundles

The agent is an untrusted client of the service; the verifier trusts nothing of the service. Code:
`agents/shopper/`, `src/countersign/evidence/`, `countersign_verify/`; tests `tests/integration/test_shopper*.py`,
`tests/unit/test_shopper_*.py`, `tests/integration/test_evidence_bundle.py`, `tests/unit/test_verify_evidence.py`,
`tests/unit/test_evidence_observer.py`, the browser verifier `web/ui/evidence/` and its page `web/verify/`
([PROTOCOL.md](PROTOCOL.md) Decisions 98 to 109).

| Attack | Actor | Defense | Test |
| --- | --- | --- | --- |
| A model reply picks something the customer did not mean (item, ceiling, expiry, a prompt injected through a product description) | model, catalog text | replies are schema-checked data, then clamped and checked by code; the human approves the structured values on the page; the service rebuilds the mandates | `test_shopper_plan.py`, Decision 100 |
| The agent's private key leaves the process | bug, log, error | no accessor, repr, copy or pickle; a test scans traffic, events and results for the scalar | `test_the_private_key_never_leaves_the_process` |
| A forged or stripped `merchant_authorization` is trusted | network attacker, malicious server | the agent verifies the detached JWS against the published keys before it signs anything | `test_an_invalid_merchant_authorization_stops_the_run` |
| The service issues mandates that differ from the proposal | compromised platform | the agent compares items, ceiling, expiry, key and payee before it shops; the device signature in the bundle is the independent check | `_check_open_mandates`, `consent_signature` |
| An expired or never-granted consent is used | agent bug | expiry and consent deadline are checked; the service verifies everything again | `test_an_expired_mandate_is_not_used`, `test_a_consent_that_never_comes_times_out` |
| A bundle edited after the fact (any byte of any component) | merchant insider, forger | every part is signed or hashed and every relation is recomputed; a one-character change anywhere fails | `test_changing_any_character_of_any_component_is_caught` |
| A bundle whose parts are each genuine but do not belong together | forger with real parts | the verifier compares mandates, receipts, checkout, consent terms, PayPal objects and `custom_id` against each other | `CASES` in `test_verify_evidence.py` (forged, signed bundles) |
| A consent that the customer never signed, or signed for other terms | rogue platform key | the device signature over the record is verified and the record must equal both open mandates | `consent_signature` |
| PayPal personal data reaches the store or a fixture | bug, new PayPal member | allowlist at every depth; an observer failure never fails a read; committed vectors are synthetic and scanned | `test_evidence_observer.py`, the vector scan |
| A bundle shown as proof that is only self-consistent | any | `trusted_keys` fails unless the merchant and platform keys are pinned by the reader | `test_without_pinned_keys_only_the_pinning_step_fails` |
| Truncating the log in a bundle | merchant insider | size, proofs and root are recomputed; a required entry missing fails the gate step | `log_*` tampers |
| A bundle for goods, a quantity, a merchant or an amount the customer did not allow, with every signature valid | malicious agent with a runtime gap, forger | both verifiers evaluate every open mandate constraint and rebuild the mandates from the signed terms (Decision 110) | the seven constraint `CASES`, `forged/` vectors |
| An operator mints a whole customer approval | rogue platform operator | not defended by the verifier (L54); the page shows the device key fingerprint to compare with the phone | none |
| A bundle the browser verifier passes and the CLI fails, or the reverse | forger | one port, the same codes, compared on every vector and 400 mutations | `test_verifier_agreement.py` |
| Number or type ambiguity (`1.0` or `true` for `1`, `2^53 + 1`, `1e400`, a duplicate key, deep nesting) | forger | strict parsing and type-exact comparison in both verifiers; any error fails the step | `json_rules.json`, `strict/` vectors |
| Bundle content shown as markup on `/verify/` | forger | every text is set with `textContent`; fixed templates; CSP with no inline script | `verify-page.test.mjs` |
| Probing `/evidence/` for which ids exist or are well formed | anyone | no listing; one identical answer for unknown, malformed and deeper paths; logged | `test_unknown_and_malformed_ids_get_the_same_answer` |
| A served bundle holds personal data | bug, new PayPal member | member allowlist; a test scans served bundles for emails and payer or buyer details | `test_a_served_bundle_holds_no_email_and_no_payer_or_buyer_details` |
| The customer's private key is on the server | design drift | WebCrypto non-extractable key; the gate test scans the database, logs, environment and live objects | `test_p3_gate.py` |

Invariants: INV-1 (the agent and the verifier decide nothing for the service; no model input to any allow), INV-8 (strict
JSON, JCS, canonical base64url), INV-9 (integer minor units in every comparison), INV-12 (the bundle is built from rows written
before the answer).

- **Not defended.** The log root is not anchored, so a forger with the code can rebuild a shorter log (L48). The verifier does
  not compare PayPal timestamps or earlier statuses (L45). Anyone with a capture id can read its bundle (L46), and the
  verifier page is only as trustworthy as the server sending it (L52). A bundle for a Human Present
  purchase does not exist (L50). The agent trusts the merchant keys the service publishes: it detects a forged response, not a
  merchant that is itself the attacker.

## Review of the phase 2 implementation

The whole phase 2 change set was reviewed against the invariants. Result: no finding that moves money
outside what was signed, bypasses a mandate or the lock, alters the log, or enables a degraded mode
remotely. Five accepted notes, recorded in [LIMITATIONS.md](LIMITATIONS.md) L30 to L34: cancel during
completion (INV-10, INV-12; resolved in P2.12), the open mandate identity (INV-6), the payer vault key (INV-5), the default
of the ablation refusal, and two liveness and logging gaps (INV-12). Areas examined and sound: the
algorithm allowlist, `typ` and `vct` matching, chain splitting and the `~~` rule, disclosure handling,
key binding and `cnf`, the customer id source, the identity headers, single use under races, the sealed
capture approval, the gate claim and fail path, the ownership rule, webhook verification and
reconciliation, the baseline code's isolation, the PayPal client's money handling, the log's
append-only role, and the API surface.


# Progress

## Phase gates

A phase starts only when the previous gate has passed.

| Phase | Scope                                                                                                                                  | Gate                                                                                                                                               | Status      |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| P0    | Foundations: repository, CI, vendored specs, spec notes, library selection, PayPal sandbox confirmations                               | `make sandbox-smoke` passes and every Day 0 confirmation in [architecture.md](architecture.md) has an answer or a written fallback                 | Passed      |
| P1    | Canonical core, UCP checkout and profile, `merchant_authorization`, PayPal client, decision log                                        | A UCP checkout is signed and verified by the independent Node verifier, and canonical terms round-trip through a real sandbox order                | Passed |
| P2    | Mandates, Merchant and Credential Provider roles, constraints, capture gate, principal lock, ACP adapter, baseline mode, first attacks | Downgrade, order-changed-after-approval (nothing is authorized in full; authorized, then voided by the gate with `ABL_NO_PREAUTH_CHECK`) and replay attacks succeed in baseline and fail in full with nothing captured; concurrency tests pass | Passed      |
| P3    | Trusted Surface with device keys and consent, shopping agent, evidence bundles and verifiers                                           | An autonomous purchase runs from phone approval to a captured sandbox order to a verified evidence bundle, with no server-held customer key        | Passed      |
| P4    | Dashboard, assistant, hostile agent, full evaluation                                                                                   | The whole demo runs from the dashboard locally and the evaluation numbers are frozen                                                               | In progress (P4.1, P4.2 done) |
| P5    | Deployment, design polish, documentation, fresh-clone test                                                                             | A stranger can use the hosted demo end to end and can run it locally from the README alone                                                         | Not started |
| P6    | Video, submission text, final checks                                                                                                   | Everything is submitted with time to spare                                                                                                         | Not started |

## P0 log

- Repository skeleton, tooling, CI and secret scan are in place.
- AP2 v0.2.0, UCP v2026-08-25, ACP 2026-04-17, RFC 9901 and the Delegate SD-JWT draft are vendored
  with pinned revisions and checksums.
- The AP2 and UCP spec facts, gaps and design decisions are recorded in
  [PROTOCOL.md](PROTOCOL.md). The architecture is in [architecture.md](architecture.md).
- Libraries chosen and proven with spikes: `rfc8785`, `joserfc`, Node `jose` and `canonicalize`. SD-JWT
  chains are built in-house because no maintained library handles the chain format. See
  [ENV.md](ENV.md).
- PayPal sandbox smoke test passed (P0.7): both flows ran live; results in [ENV.md](ENV.md) section 2.5.
- PayPal behavior confirmations (P0.8) are complete and recorded in [PROTOCOL.md](PROTOCOL.md)
  section 4 and [LIMITATIONS.md](LIMITATIONS.md). The raised-amount result led to the pre-authorize
  check ([PROTOCOL.md](PROTOCOL.md) Decision 11). Next: P0.9, the gate.
- Deferred: live webhook confirmation (delivery and `verify-webhook-signature` against a real
  notification), to the Render deploy. The event list and verification flow are recorded from
  documentation only.

## P0 gate (run 2026-10-23): passed

The gate in the phase table holds:

- `make sandbox-smoke` passed against the sandbox; the smoke and confirmation runs are recorded
  ([ENV.md](ENV.md) section 2.5, [PROTOCOL.md](PROTOCOL.md) section 4).
- Every Day 0 item in [architecture.md](architecture.md) section 10 has a recorded answer or a
  written fallback, with two exceptions that are an accepted deferred risk: the webhook id and live
  webhook confirmation (documentation-sourced events and flow are recorded; confirmation moves to
  the Render deploy).
- CI is green on the latest pushed commit at the time of the check.
- `make lint` (ruff, ruff format check, mypy, web lint, secret scan) and `make test` (pytest) pass
  locally and match the CI steps.

Items closed on 2026-10-23: grid licensing ([ENV.md](ENV.md) section 3), Render hosting (section 4),
the Devpost form (section 5, checklist in [submission/checklist.md](submission/checklist.md)) and
the model provider fallback (section 6).

Manual checks still owed by the maintainer, none blocking: an AG Grid hackathon or evaluation
licence, the row pinning and integrated charts questions ([ENV.md](ENV.md) section 3.5), and the
live Devpost form fields ([submission/checklist.md](submission/checklist.md)).

## P1 gate (run 2026-10-27): passed

Gate checks, all passing:

- `make test`: 1455 passed, 4 expected failures (the strict UCP mandate pattern conformance tests).
- `make interop`: the independent Node verifier accepted `merchant_authorization` on all five UCP
  responses (create, update, get, complete, cancel).
- Live sandbox round-trip: two orders (items only, and items with tax, shipping, handling and a
  discount) were created and read back, and the reverse-translated terms hash equals the original
  canonical terms hash in both. Not recorded to a cassette; the existing cassette replay test covers CI.
- `make lint`: clean.

Security review of the P1 modules: the first review returned **BLOCK** for one finding (below). After
the fixes, a second review of the changes returned **PASS WITH NOTES** with no BLOCK, so the gate
passed. Its new notes are P2 tasks, listed after the carry-over tasks below.

- **INV-8 (blocking):** PayPal response bodies are parsed with the standard JSON parser
  (`paypal/errors.py`, `paypal/client.py`, `paypal/cassette.py`), not the strict loader, so duplicate
  keys, NaN and Infinity are not rejected. Fix: parse with `loads_strict` and fail closed.

Fixed after the review (2026-10-27):

- INV-8: every PayPal body (success, error, token and cassette files and bodies) goes through the
  strict loader and fails closed with a typed error.
- Pre-capture checks compare the authorization's id, `invoice_id` and `custom_id` with the approved
  values, and capture needs a sealed approval that only the gate can mint. The ungated recording
  cycle moved out of the package into `tests/ungated_capture_cycle.py`.
- The create-order `PayPal-Request-Id` includes the canonical terms hash.
- The refund `PayPal-Request-Id` includes a required, caller-supplied refund key.
- An authorization within 60 seconds of `expiration_time` counts as expired
  ([PROTOCOL.md](PROTOCOL.md) 4.4).

Second round (2026-10-27): the authorize and capture cassette was re-recorded after the create-order
id change and its replay tests passed (commit `c44eb72`). The review notes were then fixed: a refused
2xx mutation body is an unknown outcome, authorize, capture and void ids name the order or
authorization (and, for capture, the approved terms), the surface test catches aliases and
re-exports, and `create_order` derives its id hash from the request body. The last two changed the
recorded request ids again, so:

- **Closed:** the authorize and capture cassette was re-recorded for the final request ids and the
  replay tests pass with no xfail marker. The only expected failures left in the suite are the four
  strict mandate pattern conformance tests ([PROTOCOL.md](PROTOCOL.md) Decision 9). `make lint`,
  `make test` and `make interop` pass, and the second security review had no blocking finding, so
  the gate has passed.

## P2 log

- P2.1: SD-JWT mandate primitives (`src/countersign/mandates/`): chain parsing with the `~~` rule,
  strict structure, ES256-only JWS, selective disclosure resolution, `cnf`, exact `vct`, `sd_hash`
  binding, `exp`/`nbf`/`iat` with skew. 144 shared vectors checked by Python and by the Node script
  `scripts/mandate_chain_check.mjs`; mutation property test; manual mutation check. Decisions 21 to
  25 in [PROTOCOL.md](PROTOCOL.md).
- P2.2: Merchant role Checkout Mandate verification (`src/countersign/merchant/`): ordered steps M1 to
  M8 with UCP error codes and internal reasons, signed acceptance and rejection receipts, atomic
  single-use reservation interface with an in-memory store, fail-closed constraint interface, decision
  log hook with a ledger adapter. Decisions 26 to 29 in [PROTOCOL.md](PROTOCOL.md).
- P2.3: constraint engine (`src/countersign/constraints/`) over the ten native AP2 constraint types:
  checkout and payment evaluators, maximal flow for line items, add-only spend accounting, category
  policy as a separate function, structural interface to the Merchant role. Decisions 30 to 33 in
  [PROTOCOL.md](PROTOCOL.md).
- P2.4: Credential Provider (`src/countersign/cp/`): Payment Mandate verification, constraints and
  reservation in one locked transaction, PayPal order, pre-authorize check and authorization, fail
  closed cleanup and recovery; Postgres single-use store and spend ledger (migration 0003); UCP complete
  wired to the Merchant then the CP; payment handler in the profile. Decisions 34 to 40 in
  [PROTOCOL.md](PROTOCOL.md). The real-sandbox cassette is recorded separately
  (`scripts/record_cp_cassette.py`).
- P2.5: capture gate (`src/countersign/gate/`): eight steps G-FETCH to G-LOCK on freshly fetched
  PayPal state (sealed `LiveState`), claim by conditional UPDATE, capture with the sealed approval and
  read-back confirmation, fail path that lets PayPal decide (void and confirm, or settle, or
  `unresolved` with everything reserved), `recover`, `LockPolicy` with a deny default and a provisional
  adapter, `ABL_NO_GATE`; migration 0004; UCP complete runs the gate and returns the order and the
  signed Payment Receipt. Decisions 41 to 46 in [PROTOCOL.md](PROTOCOL.md). Simulator, concurrency,
  crash and property tests pass; the real-sandbox gate cassette (`scripts/record_gate_cassette.py`, two
  approvals) is recorded (`tests/cassettes/gate_flow.json`) and its replay tests run in CI.

- P2.6: principal lock (`src/countersign/lock/`): `(customer id, agent key thumbprint)` recorded as
  locked on AP2 negotiation (insert-only Postgres tables, migration 0005, idempotent and race safe),
  merchant policy as versioned hashed data (`off`, `all`, `over_threshold` in minor units), one shared
  `PrincipalLock.decide` called by UCP create, update and complete and by the capture gate (through
  `GateLockAdapter` at the composition root), `ABL_NO_PRINCIPAL_LOCK`, log and store failures deny. The
  provisional adapter and L16 are gone. The customer id is the platform-signed `sub` claim. Decisions
  47 to 50 in [PROTOCOL.md](PROTOCOL.md). Deferred to the policy view (P4): the unmandated cap and the
  velocity limits.

- P2.7: ACP thin adapter (`src/countersign/protocols/acp/`, `api/acp_routes.py`): create, get, update,
  complete, cancel and a rejecting delegated payment endpoint against the vendored 2026-04-17 schemas,
  strict JSON on every body, the same canonical model and session storage as UCP (moved to
  `countersign.checkout`), the same two principal headers, and the same `PrincipalLock.decide` at create,
  update and complete. ACP complete never pays: `mandate_required` for locked principals or require-all,
  `unmandated_checkout_not_allowed` otherwise, through a named seam for the baseline mode. Decisions 51
  to 54 in [PROTOCOL.md](PROTOCOL.md).

- P2.8: webhooks and budget reconciliation (`src/countersign/webhooks/`, `api/webhook_routes.py`,
  `PayPalClient.verify_webhook_signature`, migration 0006): `POST /webhooks/paypal` verifies through
  PayPal's endpoint, dedupes by event id in one transaction with the work, and reconciles from the live
  order; void before capture releases the reservation, refund after capture is recorded and never
  restores headroom, an attempt the gate left unresolved is settled through the gate's own read. A
  webhook moves no money. Tested against a simulator only: **live delivery is not confirmed** and no
  webhook id is configured (steps in [ENV.md](ENV.md) section 11, pending for P5.1). The failure-path
  recording script exists and has not been run. Decisions 55 to 58 in [PROTOCOL.md](PROTOCOL.md).

- P2.9: baseline mode and ablations (`src/countersign/runtime.py`, `composition.py`, `main.py`,
  `degraded/`): `CS_MODE=baseline` as the line-by-line conventional gateway of Decision 59, the six
  ablations as injected policy (Decision 60), refusal at start in demo, the mode on `GET /health` and in
  a response header, `make dev-pair` for a full and a baseline instance on separate databases. A
  behavior matrix of eleven scenarios against eight configurations is checked in as data
  (`tests/vectors/behavior_matrix.json`). Decisions 59 to 62 in [PROTOCOL.md](PROTOCOL.md). Simulator
  and Postgres only: no new sandbox recording.

- P2.10: first 25 attack cases (`eval/attacks/`), the judge, runner and report (`eval/`), a case level
  mutation check, and the baseline budget made a persistent local counter (Decision 63). Run on the
  simulator only. Decisions 64 to 66 in [PROTOCOL.md](PROTOCOL.md); a liveness defect found in
  concurrent completes is open ([LIMITATIONS.md](LIMITATIONS.md) L28).

- P2.11a: the concurrent-complete race is fixed (`cp/provider.py`, `completion.py`,
  `protocols/ucp/service.py`): one request owns a payment attempt at a time, claims it before any PayPal
  call, and a request that does not own it touches nothing and gets the typed `complete_in_progress`.
  Real cause, ownership rules, the three forced-interleaving reproductions, the 500-example property and
  the 200-iteration stress tests are in Decisions 66 to 69 ([PROTOCOL.md](PROTOCOL.md)); L28 is resolved.
  `double_complete_retry` is a real concurrent burst again. Simulator and Postgres only.

- P2.12: cancel while completing (review note N1, L30). Entry guard `checkout/cancel.py`: cancel is refused
  once a payment attempt exists or the checkout is `complete_in_progress`, on UCP and ACP, in `full` and
  `baseline`, logged before the answer. Gate step `G-CHECKOUT`: the checkout is re-read `FOR SHARE` in the
  transaction that moves the attempt to `capturing`, so a canceled or expired checkout is voided and
  rejected, never captured. The baseline ACP seam now claims the session before it can pay. Decisions 70 to
  72 in [PROTOCOL.md](PROTOCOL.md); L30 is resolved. Simulator and Postgres only; no new recording.

## P3 log

- P3.1: shared visual system (`web/ui/`): design tokens (light, dark, `data-theme` override), self-hosted
  fonts, base components (button, card, badge, status pill, key fingerprint, amount, code block), a
  component gallery served in dev and eval only, a WCAG AA contrast test over the tokens, a no
  third-party origin test, amount and fingerprint tests, and review screenshots at 375 and 1280 px.
  Decisions 73 to 75 in [PROTOCOL.md](PROTOCOL.md). No product pages yet.

- P3.2 (done): device keys on the Trusted Surface (first of the P3.2 and P3.3 pair; one commit covers both). Backend
  (`src/countersign/trusted_surface/`, `api/trusted_surface_routes.py`, migration 0007): a single use
  enrolment challenge (consumed by an INSERT, 5 minutes from issue), registration with a proof of
  possession over a JCS record that names purpose, challenge, thumbprint, customer and origin, strict
  P-256 JWK validation, server side RFC 7638 thumbprint, add-only keys, the old key signature needed to add
  a key to an existing customer, stable refusal codes logged before the answer. The page (`web/approve`):
  WebCrypto non-extractable key kept in IndexedDB, the fingerprint component, fixed message templates for
  every state and failure, no build step. Served in every mode from an exact allowlist (`api/static_routes.py`).
  Browser tests in `web/approve/test` run by pytest on a real Postgres. Decisions 76 to 80 in
  [PROTOCOL.md](PROTOCOL.md); limits L35 to L38 in [LIMITATIONS.md](LIMITATIONS.md). Small fixes: the gallery
  says "1 minor unit", and the shared loading button sets `aria-busy="true"`.

- P3.3 (done): consent and platform-issued open mandates, and insert-only revocation (the second of the P3.2 and P3.3
  pair; one commit covers both). The Approve intent screen renders the terms from one structured record with
  fixed templates, the device key signs that record, and the backend verifies the device key, the nonce, the
  origin and the record, rebuilds the mandate contents and compares them byte for byte before the platform key
  signs the open Checkout and Payment Mandates (`sub` is the customer id). `sub` is now mandatory in
  `verify_chain` (152 shared vectors, Python and Node). Revocation is a table that is only ever inserted into
  (migration 0008, the 0007 trigger is gone). The platform issuer refuses selectively disclosable constraint
  elements. Decisions 81 to 85 in [PROTOCOL.md](PROTOCOL.md); L19 resolved, L31 narrowed, L38 to L41 in
  [LIMITATIONS.md](LIMITATIONS.md). CI installs the browser. The two real-sandbox cassettes (`cp_authorize`,
  `gate_flow`) were re-recorded with `sub` mandates; the scripts void or capture everything they create.

- P3.4 (done; committed together with P3.5): open mandate identity and revocation with the
  in-flight rule (L31 resolved), the agent channel (L40 resolved), Approve purchase for Human Present, and "My agent
  activity" (read with a device-key proof, revoke with its own signature). Migration 0010. Three attack cases
  (29 in all; full 0 succeeded, baseline 11; two of the three do not separate the modes, see Decision 89). Pages:
  `/approve/purchase.html#checkout=<id>` and `/approve/activity.html`. Decisions 86 to 93; limits L42 to L44.
  **Not built, scheduled later:** the second-device and key-revoke screens (L36, L38 stay open).

- P3.6 and P3.7 (done; one commit): the shopping agent `agents/shopper` ([PROTOCOL.md](PROTOCOL.md) Decisions 98 to 102;
  closes L43 for the autonomous flow), evidence bundles `src/countersign/evidence/` and the offline verifier
  `countersign_verify` (Decisions 103 to 105; L45 to L51). The agent's end-to-end run is recorded against the live sandbox and
  replayed (`tests/cassettes/shopper_e2e.json`, two model cassettes); the verifier has 12 steps, 29 tampered vectors, signed
  but inconsistent bundles from a forger, and a 35 mutant sweep (33 killed, 2 equivalent).
- P3.8 and P3.9 (done; one commit): the browser verifier `web/ui/evidence/` (a port of the CLI on WebCrypto, no
  dependency, no network) and the page `/verify/`; both verifiers hardened to one set of JSON and type rules with stable
  failure codes (Decision 106); evidence served in every mode (Decision 107); the agreement test over 91 vectors and 400
  mutations (Decision 108); the P3 gate test (Decision 109); constraint evaluation in both verifiers after the review
  (Decision 110). L46 rewritten; L52 to L55 new. TS mutation sweep: 24 mutants, 23 killed, 1 equivalent.
- P3.5 (done): the model gateway `src/countersign/llm` ([PROTOCOL.md](PROTOCOL.md) Decisions 94 to 97): one
  interface with schema-validated output and a single retry, an OpenAI-compatible adapter, a fake provider, a
  rate limiter and call budget, backoff with jitter inside a deadline, record and replay cassettes in
  `eval/cassettes/llm/` (replay by default, no network in any test), a scrubber, and the boundary test that keeps
  the package out of every authorization module. **The provider and model are still open until P3.6**; no
  cassette is recorded yet (`scripts/record_llm_cassette.py` is for the owner to run). One commit covers P3.4 and P3.5.

## P4 log

- **P4.1 and P4.2 (2026-11-05): done.** L55 closed: a checkout is bound to one customer (create, first offer or
  first verified complete); offers need the customer's device key; consent and complete check the binding
  ([PROTOCOL.md](PROTOCOL.md) Decision 111). New attack case `agent_self_approval`: blocked in full and in baseline
  (does not separate). Binding mutation check: 9 mutants, 8 killed, 1 equivalent. What remains is L56.
- Merchant dashboard on **AG Studio** (Decisions 112 to 117): Vite and React app at `/dashboard/`, token theme in
  light and dark, read-only API and event stream, source labels on every row, Onboarding status, and the Orders view
  (KPI tiles, two charts, the custom Authorization funnel widget, orders grid, quick filter, grouping, CSV export,
  live updates). `make dashboard-build`, `make dashboard-seed`.
- **What the trial provides** (tested, [ENV.md](ENV.md) section 3.6): row grouping, pivoting, set-style list
  filter, Studio charts, CSV export, totals row, cross filtering, edit and view mode, custom widgets. Not provided:
  master and detail, the raw grid API. Key tier STUDIO-PRO-AI, expiry 20 December 2026.
- **Next:** P4.3 order detail and evidence views; P4.4 protection activity and policy; P4.5 Ask Countersign (Studio
  agent framework); then the adversary LLM mode and the full evaluation.

## P3 gate (run 2026-11-05): passed

Gate evidence (`tests/integration/test_p3_gate.py`, Decision 109):

- **The purchase.** The recorded run of 4 Nov (live sandbox, capture `49029167TJ689282S`) replays end to end with no live
  PayPal or model call: a headless phone makes a non-extractable WebCrypto key and signs the consent on the real page, the
  agent shops over HTTP, the gate captures, and the stored bundle is served by `GET /evidence/{capture_id}` in `demo` mode.
- **Verified twice.** The bundle passes all twelve steps in `countersign_verify` and in the browser verifier, with the
  service's real merchant and platform public keys pinned.
- **No server-held customer key.** The database (every row of every table), the process log, the environment and every
  object alive in the process hold only the device's public JWK; only three modules sign anything and none handles a
  consent; `issue_open_mandate` runs only after the device signature check; the run's mandates are the ones issued from its
  browser-signed consent record.
- **Independent review** of the whole P3 diff (a separate agent with fresh context), verdict verbatim:
  `VERDICT: PASS WITH NOTES`. Findings: 1 HIGH (the verifiers did not evaluate the open mandates' constraints, so a bundle
  for goods the customer never allowed passed) **fixed** with tests (Decision 110); 1 MEDIUM (the page overstated what
  pinned keys cover) **fixed** in the page text, recorded as L54; 2 LOW (bundles can be linked to one customer: L46; a Human
  Present offer is not tied to the checkout's customer: L55); 1 NOTE (log steps read stronger than they are: page text
  reworded, L48).
- Screen recordings of the replayed flow are in the gitignored `web/ui/.artifacts/gate/` (`GATE_VIDEO_DIR` runs them).

What remains: P4 (dashboard on AG Grid, Ask Countersign, hostile agent, full evaluation) and the carry-forwards below.

## P2 gate (run 2026-10-30): passed

Gate evidence:

- **Attacks.** `python -m eval.run --suite attacks --mode both` (25 cases, simulator and real Postgres,
  report in `eval/reports/latest.json`): in `full` no attack succeeds, with 0 unauthorized captures and 0
  duplicate PayPal objects. In `baseline` 10 succeed (11 unauthorized captures, 0 duplicates). The three
  required ones: `protocol_downgrade_acp` (full: blocked, nothing captured; baseline: captured),
  `order_raised_after_approval` (the order-changed path; full: blocked before authorization, nothing
  captured; baseline: captured at the raised amount) and `nonce_replay_new_session` (full: the second
  purchase is refused, only the first, signed purchase is captured; baseline: a second capture).
- **Concurrency.** The parallel Credential Provider, gate and checkout tests, the three forced
  interleavings and the 500-example interleaving property pass. The stress test (200 iterations of 10 or
  20 concurrent completes over HTTP, for `full`, `baseline` and the baseline ACP path) gave exactly one
  order, one authorization and one capture per iteration, no void, no non-200 answer.
- **`make test-safety`.** Strict typing (now also on `protocols.ucp`, `paypal`, `degraded`, `checkout`,
  `completion`, `composition`, `runtime`, `ablations`), a check that every invariant package is imported by
  some test, and every test except the catalog and CI-file tests. `evidence` and `mpp` are empty until P3.
- **Security review of the whole P2 diff** (from the P1 gate commit to the working tree): verdict PASS
  WITH NOTES, no BLOCK item. The five notes are accepted and scheduled below
  ([LIMITATIONS.md](LIMITATIONS.md) L30 to L34, [threat-model.md](threat-model.md)).

Follow-ups from the review, none blocking the gate:

- **P2.12 (before P3):** done, see the P2 log (L30 resolved).
- **P3 prerequisite:** key single use, budget and revocation on a presentation-independent open mandate
  identity, and forbid selective disclosure of whole constraint elements in the platform issuer (L31);
  key the payer vault on (customer id, agent thumbprint) before vault mode is enabled (L32).
- **P5.1:** make ablation refusal fail closed when `APP_ENV` is not explicitly `dev` or `eval`, and pin
  `APP_ENV=demo` in `render.yaml` (L33); log the "pending" answer and let a resumed checkout with no
  attempt return to `ready_for_complete` after a fence (L34).

## P2 carry-over tasks

Findings from the P1 review that belong to P2 and are not optional there:

- **P2.4, single use on the checkout id (done in P2.4).** A unique constraint on the checkout id in the
  authorization table. `checkout_hash` is not unique per checkout (signature malleability and
  re-signing), so it cannot carry single use alone ([PROTOCOL.md](PROTOCOL.md) Decision 1 and 18).
- **P2.4, restricted runtime database role (done in P2.4).** The application connects as an INSERT and SELECT role
  and migrations as the owner; the default `DATABASE_URL` and `.env.example` change accordingly.
  [LIMITATIONS.md](LIMITATIONS.md) L9 is updated in the same change.
- **P2.4 and P2.5, ledger writes by the callers (the CP half done in P2.4; the gate's half is P2.5).** The PayPal client writes only to the process log.
  The CP role (P2.4) and the gate (P2.5) append a ledger entry before and after every PayPal call
  and before responding (INV-12); a failed append fails the operation.
- **P2.5 and P2.6, import-guard tests.** At P2.5: verification and gate modules never import the LLM
  package (INV-1). At P2.6: `lock/` and policy code never import `protocols/` (INV-5; done in P2.6, `tests/unit/test_lock_import_guard.py`). Both are
  AST-based, like `tests/unit/test_capture_surface.py`.
- **P2.5, gate mints the approval (done in P2.5).** The gate is the only library code that calls
  `mint_capture_approval`; the surface test enforces that. The gate's half of the ledger writes (an
  entry before and after every PayPal call and before responding) is done too.
- **P2.5, import-guard (done in P2.5).** `gate/` imports no protocol adapter, lock, web framework or
  model code (`tests/unit/test_gate_import_guard.py`).

## Carried forward

- **P5.1:** rate limit completes and `complete_in_progress` log growth per checkout and per principal (Decision 68).
- **Before vault mode is enabled:** key the payer vault on (customer id, agent thumbprint), not the agent key alone (L32).
- **P4.5:** wire `check_category_policy` into the Merchant verifier and the Policy view (`category_escape` currently covers the `line_items` constraint only).
- **P5.1:** run `CaptureGate.recover` and the CP recovery on a schedule (L26).
- **P5.1:** rate limit unverified webhook requests (L26).
- **P5.1:** record a real refund once and confirm the `payments.refunds` reading (Decision 55 note).
- **P5.1:** make ablation refusal fail closed when `APP_ENV` is not explicitly `dev` or `eval`, and pin `APP_ENV=demo` in `render.yaml` (L33).
- **P5.1:** log the "pending" answer, and let a resumed checkout with no attempt return to `ready_for_complete` after a fence (L34).
- **P5.1:** create the PayPal webhook, record its id, and confirm live delivery and `verify-webhook-signature` against a real notification (ENV section 11).

- **Later:** the page for revoking a key and adding a second device (L36, L38).
- **Later:** bind enrolment to a platform or merchant login, which closes L56 (an agent as its own customer) and L35.
- **P4.3+:** a merchant login for the dashboard (L57); order detail as its own view (no master and detail in Studio).
- **P4:** let the reader pin or recognise the customer's device key fingerprint on `/verify/` beyond showing it (L54).
- **P5.1:** rate limit `GET /evidence/{capture_id}` (L46).
- **Later:** anchor the decision log root so the log steps prove more than consistency (L48).

## Open risks

| Risk                                                         | Plan                                                                                                                                           |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Live webhook delivery and signature verification unconfirmed | Create the webhook and confirm a real notification at the Render deploy. Until then the event list and flow are from documentation only        |
| Vaulting verified in the sandbox only                        | Fallback is a fresh payer approval per purchase ([LIMITATIONS.md](LIMITATIONS.md) L1)                                                         |
| A `PayPal-Request-Id` above 108 characters returns HTTP 500  | The client enforces the limit ([LIMITATIONS.md](LIMITATIONS.md) L2)                                                                           |
| The free Render Postgres expires 30 days after creation, inside the judging period | Create a fresh database on or after 16 Nov, re-seed, repoint ([ENV.md](ENV.md) section 4) |
| The dashboard runs on an AG Studio trial key that expires 20 Dec 2026 (after judging); behaviour after expiry untested | Keep the hosted build on the key until judging ends; confirm the expiry with the owner ([ENV.md](ENV.md) section 3.6, [LIMITATIONS.md](LIMITATIONS.md) L58) |
| SD-JWT chain handling is in-house, security-critical code    | Mutation tests and the TypeScript cross-check are mandatory before it is relied on ([ENV.md](ENV.md) section 1.5)                              |

## Definition of done

- [ ] Public repository with the license detected by the host, a complete README, and a fresh clone that runs
- [ ] Hosted demo live through the evaluation period with a working sandbox buyer login
- [ ] Autonomous purchase from phone approval to a captured PayPal sandbox order to verified evidence
- [ ] Downgrade, order-changed-after-approval and replay attacks fail in full mode and succeed in baseline, shown in the dashboard
- [ ] Zero unauthorized captures and zero duplicate PayPal objects in `eval/reports/latest`
- [ ] Interop: merchant signatures and mandates verify with an independent implementation
- [ ] Dashboard and Trusted Surface polished, the Trusted Surface at 375 px
- [ ] Video under three minutes, public, with no third-party marks
- [ ] Submission description in the required structure
- [ ] Submitted with time to spare

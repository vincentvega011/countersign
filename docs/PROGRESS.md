# Progress

## Phase gates

A phase starts only when the previous gate has passed.

| Phase | Scope                                                                                                                                  | Gate                                                                                                                                               | Status      |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| P0    | Foundations: repository, CI, vendored specs, spec notes, library selection, PayPal sandbox confirmations                               | `make sandbox-smoke` passes and every Day 0 confirmation in [architecture.md](architecture.md) has an answer or a written fallback                 | Passed      |
| P1    | Canonical core, UCP checkout and profile, `merchant_authorization`, PayPal client, decision log                                        | A UCP checkout is signed and verified by the independent Node verifier, and canonical terms round-trip through a real sandbox order                | Passed |
| P2    | Mandates, Merchant and Credential Provider roles, constraints, capture gate, principal lock, ACP adapter, baseline mode, first attacks | Downgrade, order-changed-after-approval (nothing is authorized in full; authorized, then voided by the gate with `ABL_NO_PREAUTH_CHECK`) and replay attacks succeed in baseline and fail in full with nothing captured; concurrency tests pass | Not started |
| P3    | Trusted Surface with device keys and consent, shopping agent, evidence bundles and verifiers                                           | An autonomous purchase runs from phone approval to a captured sandbox order to a verified evidence bundle, with no server-held customer key        | Not started |
| P4    | Dashboard, assistant, hostile agent, full evaluation                                                                                   | The whole demo runs from the dashboard locally and the evaluation numbers are frozen                                                               | Not started |
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

## P2 carry-over tasks

Findings from the P1 review that belong to P2 and are not optional there:

- **P2.4, single use on the checkout id.** A unique constraint on the checkout id in the
  authorization table. `checkout_hash` is not unique per checkout (signature malleability and
  re-signing), so it cannot carry single use alone ([PROTOCOL.md](PROTOCOL.md) Decision 1 and 18).
- **P2.4, restricted runtime database role.** The application connects as an INSERT and SELECT role
  and migrations as the owner; the default `DATABASE_URL` and `.env.example` change accordingly.
  [LIMITATIONS.md](LIMITATIONS.md) L9 is updated in the same change.
- **P2.4 and P2.5, ledger writes by the callers.** The PayPal client writes only to the process log.
  The CP role (P2.4) and the gate (P2.5) append a ledger entry before and after every PayPal call
  and before responding (INV-12); a failed append fails the operation.
- **P2.5 and P2.6, import-guard tests.** At P2.5: verification and gate modules never import the LLM
  package (INV-1). At P2.6: `lock/` and policy code never import `protocols/` (INV-5). Both are
  AST-based, like `tests/unit/test_capture_surface.py`.
- **P2.5, gate mints the approval.** The gate is the only library code that calls
  `mint_capture_approval`; the surface test already enforces that.

## Open risks

| Risk                                                         | Plan                                                                                                                                           |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Live webhook delivery and signature verification unconfirmed | Create the webhook and confirm a real notification at the Render deploy. Until then the event list and flow are from documentation only        |
| Vaulting verified in the sandbox only                        | Fallback is a fresh payer approval per purchase ([LIMITATIONS.md](LIMITATIONS.md) L1)                                                         |
| A `PayPal-Request-Id` above 108 characters returns HTTP 500  | The client enforces the limit ([LIMITATIONS.md](LIMITATIONS.md) L2)                                                                           |
| The free Render Postgres expires 30 days after creation, inside the judging period | Create a fresh database on or after 16 Nov, re-seed, repoint ([ENV.md](ENV.md) section 4) |
| AG Grid Enterprise features need a licence for the hosted demo; a 30 day trial would lapse before 15 Dec | Build on Community first; ask about a hackathon licence ([ENV.md](ENV.md) section 3.5) |
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

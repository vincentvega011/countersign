# Progress

## Phase gates

A phase starts only when the previous gate has passed.

| Phase | Scope                                                                                                                                  | Gate                                                                                                                                               | Status      |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| P0    | Foundations: repository, CI, vendored specs, spec notes, library selection, PayPal sandbox confirmations                               | `make sandbox-smoke` passes and every Day 0 confirmation in [architecture.md](architecture.md) has an answer or a written fallback                 | Passed      |
| P1    | Canonical core, UCP checkout and profile, `merchant_authorization`, PayPal client, decision log                                        | A UCP checkout is signed and verified by the independent Node verifier, and canonical terms round-trip through a real sandbox order                | In progress, P1.1 to P1.7 done |
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

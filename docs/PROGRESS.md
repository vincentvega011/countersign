# Progress

## Phase gates

A phase starts only when the previous gate has passed.

| Phase | Scope                                                                                                                                  | Gate                                                                                                                                               | Status      |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| P0    | Foundations: repository, CI, vendored specs, spec notes, library selection, PayPal sandbox confirmations                               | `make sandbox-smoke` passes and every Day 0 confirmation in [architecture.md](architecture.md) has an answer or a written fallback                 | In progress |
| P1    | Canonical core, UCP checkout and profile, `merchant_authorization`, PayPal client, decision log                                        | A UCP checkout is signed and verified by the independent Node verifier, and canonical terms round-trip through a real sandbox order                | Not started |
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

## P0 gate (run 2026-10-23): not passed

Checks that hold: the smoke test and confirmation runs are recorded
([ENV.md](ENV.md) section 2.5, [PROTOCOL.md](PROTOCOL.md) section 4); CI is green on the latest
pushed commit; `ruff`, `mypy` and `pytest` (the CI steps) and the secret scan pass locally. The
`make test` target is still a stub, so the CI steps were run directly.

Unresolved Day 0 items (no recorded answer or fallback yet, see [architecture.md](architecture.md)
section 10):

- Grid library license terms and which features are free versus paid.
- Hosting plan fit for the API, static sites and Postgres for the evaluation period.
- Model provider and model ids, and record and replay working.
- Submission form fields reviewed.

Accepted deferral: live webhook confirmation and the webhook id, planned at the Render deploy.

## Open risks

| Risk                                                         | Plan                                                                                                                                           |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Live webhook delivery and signature verification unconfirmed | Create the webhook and confirm a real notification at the Render deploy. Until then the event list and flow are from documentation only        |
| Vaulting verified in the sandbox only                        | Fallback is a fresh payer approval per purchase ([LIMITATIONS.md](LIMITATIONS.md) L1)                                                         |
| A `PayPal-Request-Id` above 108 characters returns HTTP 500  | The client enforces the limit ([LIMITATIONS.md](LIMITATIONS.md) L2)                                                                           |
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

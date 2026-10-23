# Progress

## Phase gates

A phase starts only when the previous gate has passed.

| Phase | Scope                                                                                                                                  | Gate                                                                                                                                               | Status      |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| P0    | Foundations: repository, CI, vendored specs, spec notes, library selection, PayPal sandbox confirmations                               | `make sandbox-smoke` passes and every Day 0 confirmation in [architecture.md](architecture.md) has an answer or a written fallback                 | In progress |
| P1    | Canonical core, UCP checkout and profile, `merchant_authorization`, PayPal client, decision log                                        | A UCP checkout is signed and verified by the independent Node verifier, and canonical terms round-trip through a real sandbox order                | Not started |
| P2    | Mandates, Merchant and Credential Provider roles, constraints, capture gate, principal lock, ACP adapter, baseline mode, first attacks | Downgrade, order-changed-after-authorization and replay attacks succeed in baseline and fail in full with nothing captured; concurrency tests pass | Not started |
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
- Open: PayPal behavior confirmations (P0.8).

## Definition of done

- [ ] Public repository with the license detected by the host, a complete README, and a fresh clone that runs
- [ ] Hosted demo live through the evaluation period with a working sandbox buyer login
- [ ] Autonomous purchase from phone approval to a captured PayPal sandbox order to verified evidence
- [ ] Downgrade, order-changed-after-authorization and replay attacks fail in full mode and succeed in baseline, shown in the dashboard
- [ ] Zero unauthorized captures and zero duplicate PayPal objects in `eval/reports/latest`
- [ ] Interop: merchant signatures and mandates verify with an independent implementation
- [ ] Dashboard and Trusted Surface polished, the Trusted Surface at 375 px
- [ ] Video under three minutes, public, with no third-party marks
- [ ] Submission description in the required structure
- [ ] Submitted with time to spare

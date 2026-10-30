# LIMITATIONS

Known limits of Countersign, each with the fallback that applies. Entries marked _SHORTCUT
candidate_ are places where the build may take a simpler path than the full design; each becomes a
`# SHORTCUT:` marker in code if it is taken. Sandbox facts are cited from
[PROTOCOL.md](PROTOCOL.md) section 4.

## PayPal behavior

### L1. Vaulting is verified in the sandbox only

In the sandbox, a wallet vaulted at a first approved order let a second order be created and
authorized with no payer approval. Whether the same is available to a production merchant account
is unverified. Countersign makes no claim that it is.

- _Fallback_: fresh payer approval for each purchase, on PayPal from the Trusted Surface. The
  autonomous flow is then autonomous up to that approval, and the documentation says so.
- _SHORTCUT candidate_: the demo uses the vaulted path only because the sandbox allows it.

### L2. A `PayPal-Request-Id` above 108 characters fails with HTTP 500

The sandbox returned `INTERNAL_SERVICE_ERROR`, not a validation error, for a 109 character
Request-Id. The client therefore enforces the 108 character limit before sending, and derives
Request-Ids that stay under it.

### L3. Orders can be changed between payer approval and authorization

In the redirect approval mode, the sandbox accepted a PATCH of items and amount (74.00 up to 100.00)
while the order was `APPROVED`, and authorize then authorized the patched amount with no new payer
approval. After authorization every tried PATCH was rejected. The window is therefore between approval
and authorization.

- _Who_: per PayPal's documentation the update operation needs the merchant app's API credentials, so
  the modeled actor is a compromised or buggy merchant-side component or a confused deputy, not the
  buyer or the agent. Countersign does not claim the agent can alter orders. Whether any other party
  can PATCH an order was not tested.
- _Mitigation_ ([PROTOCOL.md](PROTOCOL.md) Decision 11): the Credential Provider role re-reads and
  compares the live order before authorizing, and the capture gate is the second layer. Neither is
  built yet, so this is a design, not a tested result. The PATCH behavior is from one sandbox account.
- Vault mode has no such window because create and authorize are one call (observed in the sandbox).

### L4. Partial captures are possible

PayPal allows several partial captures against one authorization. Countersign always captures the
full checkout total with `final_capture` set to true, and budget accounting is designed to sum every
capture on the authorization, so a partial capture made outside Countersign still counts against the
budget.

### L5. Supported currencies

Only the 25 currencies on PayPal's REST currency page are accepted ([ENV.md](ENV.md) section 8).
BRL, CNY and MYR are in-country only per PayPal, and RUB carried no note; whether any of them works
in a given sandbox or account was not tested. HUF and TWD amounts must be whole units, because
PayPal rejects decimals for them even though UCP minor units for those currencies have two decimals
([PROTOCOL.md](PROTOCOL.md) Decision 13); a checkout with fractional HUF or TWD cannot be sent to
PayPal and is refused.

## Checkout model and catalog

### L6. What the canonical checkout can express

Only whole-item (`each`) quantities, the seven well-known total types, and no sub-lines, parent
line items or unit pricing ([PROTOCOL.md](PROTOCOL.md) Decision 14). A UCP checkout using any of
those is rejected rather than approximated. The line-level and discount rollup consistency rules
are Countersign's reading of the UCP text, not quoted formulas, so a standards-compliant merchant
checkout built differently could be refused.

### L7. Catalog location and names

`default_catalog_path()` assumes a source checkout (`data/` next to `src/`) and is marked
`# SHORTCUT:`; a packaged install would need the file shipped as package data. The catalog's brand
names are invented but were not checked for trademark conflicts.

## Decision log

### L8. Tamper-evident, not tamper-proof

The hash chain shows edits, deletions in the middle, insertions and reordering. Removing the newest
entries, rewriting the newest entry with a recomputed hash, or rebuilding the whole chain leaves a
log that is internally consistent; those are only visible against an anchor (the newest `seq` and
`entry_hash`) or a Merkle root stored somewhere the writer cannot change. The demo and the tests show
this. Until the anchors are published or stored off-database (for example in the evidence bundle
exported at capture), a database administrator can rewrite history undetected. The log is not a
blockchain and is not described as one.

### L9. The application role on the hosted database

The grants that stop the application rewriting history hold only if the deployed service connects as
the restricted role. The role has SELECT and INSERT on the decision log and no UPDATE, DELETE or
TRUNCATE on it; since migration 0003 it has SELECT, INSERT and UPDATE (never DELETE or TRUNCATE) on the
reservation, spend, attempt and checkout tables, where triggers restrict which updates are legal.
The integration tests connect as that role and assert these grants (`tests/integration/test_cp_database.py`),
and the Credential Provider and the UCP service run as it. Whether the hosted Postgres allows a second,
restricted login role was not checked ([ENV.md](ENV.md) section 4 does not say). Check at the Render
deploy that the service uses the restricted role; if it cannot, record the fallback here and rely on
the anchors in L8.

### L10. Throughput and clocks

All appends take one advisory lock, so the log is a single-writer bottleneck by design; at demo scale
(tens of entries per purchase) this is irrelevant. Timestamps come from the writer's clock and are
not required to be monotonic, so a day tree is defined by `ts_us` and ordered by `seq`. A log
`append` joins the caller's transaction, so INV-12 callers must commit it before responding.

### L14. The payment handler name is a placeholder

The profile and every checkout response declare a payment handler named
`dev.countersign.payment.ap2_payment_mandate` ([PROTOCOL.md](PROTOCOL.md) Decision 39). UCP wants a
reverse-domain name of a domain the author controls. Countersign is a working name and the project
does not own `countersign.dev`, so the name is a **placeholder**, and no `spec` or `schema` document is
published for the handler. A platform that checks handler names against a registry will not know it.
It must be renamed to a domain we control (and its specification published) before any use beyond the
demo.

### L15. Failures after a payment mandate verified

Two outcomes have no UCP checkout message. A decision-log failure after the reservation cleans up
(voids any authorization, releases the reservation) and ends as HTTP 500 `internal_error`, not as a
checkout with an error message, because nothing could be recorded about it. And an attempt whose
PayPal state cannot be read or confirmed is marked `unresolved` and keeps the budget and the open
mandate reserved until `recover` reads PayPal; until then the agent sees a rejection and must use a
new checkout. Nothing runs `recover` on a schedule yet.

## Capture gate

### L16. The principal lock was provisional (resolved)

The `# SHORTCUT:` adapter that stood in for the lock at G-LOCK is removed. G-LOCK now asks the real
principal lock through `GateLockAdapter` (see L19 to L22 for what the lock cannot do).

### L17. What the gate does when it cannot finish

- With the decision log down the gate cannot write the "started" entry of a void, so it makes no PayPal
  call and the attempt ends `unresolved`; the authorization expires by itself and the budget and the
  open mandate stay reserved ([PROTOCOL.md](PROTOCOL.md) Decision 43).
- An `unresolved` attempt keeps its money reserved until a later `complete` or `recover` reads PayPal.
  Nothing runs `recover` on a schedule yet. A checkout still `complete_in_progress` past its 6 hour
  lifetime is canceled when it is next touched, even if money may be held; the attempt row is what
  records the truth.
- A claim older than 60 seconds is taken over by a retry. A gate that is merely slow, not dead, could
  overlap a taker; the deterministic Request-Ids and PayPal's own refusals (`PREVIOUSLY_CAPTURED`,
  `AUTHORIZATION_ALREADY_CAPTURED`) stop a second capture or a void after a capture, but the overlap
  would show up as extra rejected calls in the log.
- The PayPal sandbox refuses an order PATCH after authorization, so the "order changed" attack that
  reaches the gate does so through the window between payer approval and authorization with the
  pre-authorize check switched off (`ABL_NO_PREAUTH_CHECK`), as in [L3](#l3-orders-can-be-changed-between-payer-approval-and-authorization).
  Tests that change an order after authorization use the simulator, which allows it; that is not a
  claim about PayPal.

### L18. Receipts and the order on completion

The complete response that captured carries the Payment Receipt in `ap2.payment_receipt` and the
Checkout Receipt in `ap2.checkout_receipt` (Countersign members; UCP defines none). The Checkout Receipt
is issued again at completion from the stored mandate, so it is not the receipt returned at acceptance
and has a later `iat`. `network_confirmation_id` repeats the PayPal capture id, since PayPal reports no
separate network reference to this client. The `order` of a completed checkout uses the checkout id as
its id and the checkout URL as its permalink. The receipts appear only on the complete that captured,
not on a later read.

## Principal lock

### L19. The customer id depends on the platform writing `sub`

The lock's customer id is the `sub` claim of the platform-signed mandate ([PROTOCOL.md](PROTOCOL.md)
Decision 47). The Trusted Surface backend that will write it is built in P3, so until then mandates
carry none (the test issuer adds one). A mandate without it is an unknown customer: under "require AP2
for all agents", or when a matching lock names a customer, it is denied. The vault principal of
Decision 40 is still the agent key alone.

### L20. The principal is what the agent presents

The lock keys on the principal, and the principal is whatever delegation the agent puts in
`Countersign-Delegation`, on UCP and on ACP alike. An agent that presents none is unidentified, and an
agent can choose not to identify itself. So omission is caught only by the merchant policy ("require
AP2 for all agents", or over the threshold), not by the lock. That is why the demo policy is "all". A
locked principal that presents its delegation but not the capability is denied (the new-session
escape, on both protocols); an agent that hides its identity entirely is not an escape under "all".

### L21. Negotiation is a request header

Countersign does not fetch the platform profile (L11), so "negotiated `dev.ucp.common.payment.ap2_mandate`"
is read from `Countersign-Capabilities`, and identity from `Countersign-Delegation`. Both are
Countersign extensions, on UCP and on ACP; neither protocol defines them. A platform that negotiates by
profile only would not be recognised as negotiating until the profile fetch exists. ACP has no
negotiation of its own for AP2: its `capabilities.extensions` list was not used, to keep one signal for
both protocols.

### L22. Lock behaviour at the edges

- A lock is recorded before the decision is logged. If the decision's log entry then fails, the answer
  is a denial but the lock stays recorded (conservative). If the lock's own log entry fails, the lock is
  not recorded.
- Unlock is a merchant method with no UI or route yet; policy and unlock changes have no authorization
  layer beyond the process that calls them. The unmandated cap and velocity limits are not built (the
  policy view, P4).
- The matching rule lets an unknown part match anything, so a nameless mandate under an agent key that
  any locked customer used is held to the strict rule (denied) rather than guessed.

## ACP adapter

### L23. ACP never completes a payment

ACP has no slot for an AP2 mandate and Countersign implements no ACP delegated payment, so an ACP
`complete` is always an unmandated request. A locked principal, or any principal under a policy that
requires AP2, is denied `mandate_required`; every other principal is denied
`unmandated_checkout_not_allowed`, because the Credential Provider and the capture gate need mandates and
the unmandated cap is not built ([PROTOCOL.md](PROTOCOL.md) Decision 53). The seam for the permissive
path of the baseline mode exists and is not implemented. An agent that wants to buy must use UCP.

### L24. What the ACP binding does not do

- `Authorization` (bearer) is not validated; the endpoints are open, as the UCP ones are. The
  idempotency header is required on POSTs but replays are not cached, so a repeated create makes a
  second session and `Idempotent-Replayed` is never sent.
- The vendored request `Item` schema has no `quantity` although its examples use it; Countersign
  accepts an integer `quantity` as the one extension and refuses fractional quantities (whole items
  only, L6). Fulfillment, buyer, affiliate, risk and marketing members are accepted when they match the
  schema and then ignored; coupons and discount codes are refused rather than ignored.
- `POST /agentic_commerce/delegate_payment` is answered with the checkout `Error` shape. The vendored
  delegate payment `Error` has a closed `code` list that cannot carry `mandate_required`, so the
  response is outside that endpoint's schema on purpose.
- ACP sessions and UCP sessions share one table, so a session id made on one protocol can be read on the
  other. Nothing is paid through either without a mandate.

### L25. The ACP integer `quantity` is an extension

The vendored ACP request `Item` (`id`, `name`, `unit_amount`) has no `quantity`, although its description and
the OpenAPI examples use one. Countersign accepts an integer `quantity` (default 1, at most 99) as the one
extension to the published schema ([PROTOCOL.md](PROTOCOL.md) Decision 52). The accepted request is
therefore not valid against the vendored request schema when it carries a quantity (a test asserts this),
and a client that sends the item id repeatedly instead gets one line per repeat. Fractional quantities
(which the ACP changelog allows for B2B) are refused: Countersign sells whole items only (L6).

## Webhooks

### L26. What the webhook handling does not do

- **Live delivery is unconfirmed.** Everything is tested against a simulator. The success path of
  `verify-webhook-signature`, the headers PayPal actually sends, delivery delay, ordering and retry
  behaviour were not observed; no webhook id is configured. Steps are in [ENV.md](ENV.md) section 11
  (pending, P5.1). Do not claim otherwise. `payments.refunds` on a fetched order is likewise documented,
  not observed.
- **Settle after commit.** A request to settle an attempt runs after the event row commits; if the
  process dies in between, PayPal is not told to resend and `CaptureGate.recover` has to finish it
  ([PROTOCOL.md](PROTOCOL.md) Decision 58). Nothing runs `recover` on a schedule yet.
- **No rate limit.** Each unverified request costs one call to PayPal's verification endpoint.
- **The notification is verified as received.** Any proxy that rewrites the body before it reaches the
  service makes verification fail (a refusal, never a false accept).
- **Unknown or unhandled events are acknowledged with 200** so PayPal does not retry them; they are
  recorded as `ignored`. A refund, capture or void of something Countersign did not authorize is
  therefore ignored, not alerted on, until the dashboard has a protection view.

## UCP checkout binding

### L11. What the checkout endpoints do not do yet

The binding ([PROTOCOL.md](PROTOCOL.md) Decision 17) accepts only line items and quantities. It
collects no buyer, address or fulfillment data, charges no tax or shipping, and returns an empty
`links` array because there are no legal pages to link. It does not support `Idempotency-Key`, so a
retried create makes a second checkout; it does not verify request signatures or fetch the platform
profile in `UCP-Agent`, so it cannot tell which agent is calling and cannot negotiate capabilities.
Complete is a stub that always answers `mandate_required`. Every checkout response is signed with
`ap2.merchant_authorization` whether or not the platform negotiated AP2 ([PROTOCOL.md](PROTOCOL.md)
Decision 18). Per-checkout line items are limited to 20
and quantities to 99, which are Countersign choices, not UCP limits.

## PayPal client

### L12. What the client has and has not been shown to do

The client is tested against mocked HTTP, a PayPal simulator, and recordings of the real sandbox
(authorize and capture, order terms, the Credential Provider flow and the capture gate flow, under
`tests/cassettes/`). The required response fields (an order's `intent`, an authorization's
`expiration_time`, a capture's `final_capture`) appear in those recordings, and the client still fails
closed if PayPal omits one. Where PayPal puts the specific error code (`name` or `details[].issue`) is
accepted both ways rather than confirmed ([PROTOCOL.md](PROTOCOL.md) Decision 19). Both payer approval
modes are built: redirect approval, and the vaulted wallet for merchant initiated orders
([PROTOCOL.md](PROTOCOL.md) 4.7, Decision 40). The vaulted path has been observed in the sandbox and
is exercised in tests against the simulator; it has no recording of its own. A capture whose outcome is
unknown must be resolved by re-fetching, and the client will not repeat it.

### L13. Line item ids are applied by position

PayPal has no per-line item id, so the reverse translation applies the signed line ids to the
order's items by position ([PROTOCOL.md](PROTOCOL.md) Decision 20). This relies on PayPal returning
items in the order they were sent. That held in every recording made so far: three orders, each with
two items (`tests/cassettes/paypal_authorize_capture.json` and `tests/cassettes/paypal_order_terms.json`).
Orders with one item, or with more than two, have not been recorded, and PayPal documents no ordering
guarantee. If PayPal ever reordered items, the terms would differ and the order would be refused,
which fails safe but would block a legitimate purchase.

### L27. Baseline mode and the ablations

- **Baseline is our model of a conventional integration, not a competitor product.** It is built from
  the same code with the protections of [PROTOCOL.md](PROTOCOL.md) Decision 59 left out, each omission
  justified there. A different careful integration may leave out less. Results against baseline say
  what these protections add to this design, not how any real product behaves.
- **Baseline captures without the gate, by definition.** The capture surface tests allow
  `countersign/degraded/` for that reason (Decision 61); it is unreachable in `full`, and a test
  checks that `full` builds none of it.
- **The budget switch reopens nothing.** Baseline and `ABL_NO_BUDGET_RECON` keep a persistent local
  counter and lack only the PayPal reconciliation, so a split purchase is still refused even with the
  single-use rules off (Decisions 60 and 63). Reconciliation buys accuracy against events outside
  Countersign, not protection against an agent, and no scenario here measures that accuracy.
- **Baseline's unmandated ACP path** keeps pending orders in process memory, ignores the ACP
  `payment_data` token, and obtains payer approval only through the vaulted wallet or the PayPal
  approval link, as the Credential Provider does. The vaulted path is sandbox only (L1).
- **Baseline is not evaluated live against PayPal yet.** Every baseline and ablation result so far
  comes from the PayPal simulator and the real Postgres. The immediate capture of a raised order has no
  recorded sandbox cassette.
- **Local pair.** `make dev-pair` uses fixed passwords for its two local database roles and the
  compose administrator URL. It is a development convenience, not a deployment.

### L28. Concurrent completes (RESOLVED in P2.11a)

A burst of `complete` calls after payer approval used to void the winner's authorization about one run
in twenty and answer 500 to one request. The cause was that a request acted on the attempt before it
owned it, and the fix is the ownership rule of [PROTOCOL.md](PROTOCOL.md) Decisions 66 to 69. What
remains: the interleavings are tested against the PayPal simulator and the real Postgres, not against
live PayPal; the loser's answer costs one small log entry per request; a request that holds a claim
and then dies leaves the attempt `authorizing` until `recover` runs, and `recover` is not scheduled yet
(L26).

### L29. What the attack suite is and is not

- 25 hand written, deterministic cases against the PayPal simulator and the real Postgres. They show
  that these attacks fail in `full`; they are not a proof, and the adversary LLM runs are later work.
- Several cases are layered (baseline also blocks them), which the report states.
- No case covers a merchant level category policy, the device consent signature (P3), a live webhook
  delivery, or a PATCH after authorization (impossible in the sandbox).
- Case level mutation checks use the ablations, so they show what each switch reopens, not every
  possible code defect.

### L30. A checkout can be canceled while it is completing

Cancel is allowed in every status that is not final, including `complete_in_progress`, and the capture gate
does not re-read the checkout. Anyone holding the checkout id can therefore cancel a checkout between
authorize and capture: the gate still captures, and the checkout then reads `canceled` without receipts,
so the trail contradicts itself. A cancel during payer approval leaves the attempt, the budget and the
mandate reserved until `recover` runs (L26). No money moves outside what was signed. Planned: refuse the
cancel in that status and have the gate check the status under lock (P2.12).

### L31. The open mandate digest depends on how the agent presents it

The identity used for single use, the budget row and a revocation is the digest of the serialization the
agent presents, and the agent can reorder or withhold the nested disclosures of link 0. Today the open
Checkout Mandate digest is pinned by `payment.reference`, and the Merchant reservation and the gate's
revocation check use the pinned digest, so no purchase escapes. It would matter if revocation were keyed
on the Payment Mandate digest or if constraint elements became selectively disclosable. Planned before P3.

### L32. The payer vault is keyed on the agent key only

With vault enrollment on, a wallet vaulted by one customer under an agent key could be charged for another
customer's valid mandate for the same key. Enrollment is off by default and the composition root never
turns it on; it must not be turned on before the vault is keyed on (customer id, agent thumbprint) (P3).

### L33. Ablation refusal depends on `APP_ENV`

The refusal applies when `APP_ENV=demo`, and an unset `APP_ENV` is treated as `dev`. A hosted deployment
that forgets to set it would accept an ablation from its environment. No request can enable one. Planned:
refuse unless `APP_ENV` is explicitly `dev` or `eval`, and pin `APP_ENV=demo` in `render.yaml` (P5.1).

### L34. Two liveness and logging gaps

The answer "the payer has not approved yet" writes no decision entry of its own (the PayPal read is logged),
and a crash or log failure in the first complete before the attempt row commits leaves the checkout
`complete_in_progress` with no attempt, so later completes answer `in_progress` until it expires. Neither
moves money. Planned: log the pending answer, and return such a checkout to `ready_for_complete` after a
fence (P5.1).


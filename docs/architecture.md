# Architecture

Countersign is a service that sits in front of a merchant's PayPal integration. It lets AI shopping
agents buy under the AP2 mandate model carried in UCP, and it keeps cryptographic evidence of what
the customer approved. This document describes the design. Wire formats, hash rules and the spec
decisions it relies on are in [PROTOCOL.md](PROTOCOL.md). Sandbox only: no live PayPal credentials
are used anywhere.

## 1. Overview

### 1.1 What it does

1. Exposes a UCP checkout with the AP2 mandates extension, so standards-compliant agents can buy.
2. Plays the AP2 Merchant, Credential Provider and Merchant Payment Processor roles in front of
   PayPal Orders. No PayPal authorization without a valid Payment Mandate. No PayPal capture unless
   the live PayPal order still matches the signed checkout.
3. Provides a Trusted Surface, a phone-friendly approval page where the customer's non-extractable
   device key signs consent over the exact constraints or checkout. The Trusted Surface backend then
   issues standard AP2 mandates.
4. Ties protection to the customer and agent (the principal), not to a session or a protocol, so an
   agent cannot escape it by switching to a weaker checkout protocol.
5. Produces a verifiable dispute evidence bundle per PayPal capture.
6. Gives the merchant a dashboard with an order grid, evidence verification, policy settings and a
   read-only model-backed assistant.

### 1.2 Role mapping

One entity may play several AP2 roles ([PROTOCOL.md](PROTOCOL.md) section 1.2.1). Countersign plays
Merchant, Credential Provider, Merchant Payment Processor and Trusted Surface for one merchant. In
production the Credential Provider would typically be the customer's wallet provider.

| AP2 role                   | Implemented by                                                                | Agentic       |
| -------------------------- | ----------------------------------------------------------------------------- | ------------- |
| Shopping Agent             | `agents/shopper`, a separate process that speaks only UCP over HTTP           | yes           |
| Trusted Surface            | `web/approve` plus the Trusted Surface backend in `src/countersign/api`       | no (required) |
| Merchant                   | `countersign.merchant`                                                        | no            |
| Credential Provider        | `countersign.cp`                                                              | no            |
| Merchant Payment Processor | `countersign.mpp` and `countersign.gate`, with PayPal as the actual processor | no            |

Each role verifies from its own inputs and does not trust another role's result, even though they
run in one process. All verification is deterministic code. No model output is an input to an allow
decision.

### 1.3 The autonomous flow (Human Not Present)

1. **Device key.** On first use the customer opens the Trusted Surface on a phone. The browser
   creates a non-extractable ECDSA P-256 key. The public JWK is registered to the customer.
2. **Intent.** The customer states a goal to the agent in plain words. The agent proposes
   structured terms: an explicit item list, a spending ceiling and an expiry.
3. **Consent.** The Trusted Surface renders those exact terms from fixed templates. On approval the
   device key signs a consent record over them. The backend verifies the consent, then signs the open
   Checkout Mandate and open Payment Mandate with the platform key, with the agent public key in
   `cnf` and a short `exp`.
4. **Discovery and checkout.** The agent fetches `/.well-known/ucp`, negotiates checkout and the AP2
   mandates extension, and creates and updates a checkout. Every response carries
   `ap2.merchant_authorization`. The principal lock is recorded for the customer and agent.
5. **Closed mandates.** The agent signs closed Checkout and Payment Mandates with its own key,
   chained to the open mandates and bound to the checkout hash.
6. **Complete.** The Merchant role verifies the Checkout Mandate. On failure it returns the UCP error
   code and a rejection receipt.
7. **Credential Provider.** Verifies the Payment Mandate, reserves budget and the single-use keys,
   and creates a PayPal order with `intent: AUTHORIZE`.
8. **Payer approval and authorization.** The method is decided by the PayPal confirmations in
   section 10 (a vaulted sandbox wallet for fully autonomous charges, or a one-time customer
   approval on PayPal sandbox). In redirect-approval mode, the live order is first fetched and
   compared with the signed checkout, and authorize is called only on an exact match
   ([PROTOCOL.md](PROTOCOL.md) Decision 11). Then the order is authorized.
9. **Capture gate.** Fresh PayPal state is fetched and compared with the signed checkout. If it
   passes, Countersign captures and issues a Payment Receipt. If it fails, the authorization is
   voided and reservations are released.
10. **Evidence.** A bundle is written and linked to the PayPal capture id. Webhooks reconcile state.

The Human Present flow is the same except that the customer reviews the closed checkout on the
Trusted Surface and consents to closed mandates directly. The Human Present mandate format is fixed
when the issuer is built ([PROTOCOL.md](PROTOCOL.md) Decision 8).

### 1.4 System diagram

```text
 Customer phone                   Shopping agent (LLM)           Hostile agent (scripted or LLM)
 Trusted Surface (web/approve)    agents/shopper                 agents/adversary
 device key signs consent              | UCP over HTTP                 | UCP or ACP
        |                              v                               v
        |        +-------------------------------------------------------------------+
        +------->| Edge (FastAPI): strict JSON, size limits, request hashing         |
                 +----------------+------------------------------+-------------------+
                                  v                              v
                      +-------------------------+      +---------------------+
                      | UCP adapter + AP2 ext   |      | ACP adapter (thin)  |
                      +------------+------------+      +----------+----------+
                                   +------------ canonical -------+
                                                   v
        +-------------------------------------------------------------------------------+
        | Canonical checkout (JCS bytes, integer minor units, hashes)                    |
        +------------------------------------+------------------------------------------+
                                             v
   +--------------------+   +----------------------------+   +--------------------------+
   | Merchant role      |-->| Principal lock             |-->| Constraint evaluation    |
   | checkout mandate   |   | protocol independent       |   | native AP2 constraints   |
   +--------------------+   +----------------------------+   +-------------+------------+
                                                                           v
        +-------------------------------------------------------------------------------+
        | Credential Provider: verify Payment Mandate, reserve, create PayPal order      |
        +------------------------------------+------------------------------------------+
                                             v
        +-------------------------------------------------------------------------------+
        | Payment Processor + capture gate: fetch live state, compare, capture or void   |
        +------------------+---------------------------------------+--------------------+
                           v                                       v
          +-------------------------------+        +---------------------------------+
          | Hash-chained decision log     |        | Evidence bundles by capture id  |
          +-------------------------------+        +---------------------------------+
                           |
                           v
        +-------------------------------------------------------------------------------+
        | Merchant dashboard (React and AG Grid): orders, mandates, gate results,        |
        | evidence, protection activity, policy, assistant                               |
        +-------------------------------------------------------------------------------+
```

## 2. Trust model and keys

### 2.1 Trust model

Countersign uses the UCP trusted platform provider option and the AP2 Trusted Agent Provider
delegation model ([PROTOCOL.md](PROTOCOL.md) Decision 5).

- The Trusted Surface backend is the platform provider. It holds a mandate-signing key and publishes
  a platform profile with that key in `keys[]`.
- It signs a mandate only after verifying a consent signature made by the customer's device key over
  the exact content to be signed, and after rebuilding that content itself and finding the bytes
  identical.
- Mandates are standard. They contain no Countersign-specific claims or constraint types. The
  consent signature, consent record and registered device public key are stored as additional
  evidence and are not part of any mandate.
- The server never holds a customer private key. The device key is non-extractable and never leaves
  the browser.
- The honest limit: the party that signs mandates also verifies them, because Countersign plays all
  the roles. The independent check on a rogue or compromised platform key is the device consent
  signature, which only the customer's device can produce and which anyone can verify offline.

### 2.2 Keys

| Key                        | Algorithm | Held by                                  | Signs                                                       | Published                                                      |
| -------------------------- | --------- | ---------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------- |
| Customer device            | ES256     | the customer's browser (non-extractable) | consent records                                             | public JWK registered with the backend, in the evidence bundle |
| Platform (Trusted Surface) | ES256     | the backend, in a secrets store          | user-delegated mandates                                     | platform profile `keys[]`                                      |
| Agent                      | ES256     | the agent process only                   | closed mandates                                             | public JWK in the open mandate `cnf`                           |
| Merchant                   | ES256     | the backend                              | `merchant_authorization`, `checkout_jwt`, Checkout Receipts | business profile `keys[]` at `/.well-known/ucp`                |
| Payment processor          | ES256     | the backend                              | Payment Receipts                                            | business profile `keys[]`                                      |

Keys carry distinct `kid` values. Rotation removes the old key from `keys[]`; removal is the
revocation mechanism UCP defines.

### 2.3 Principal

The principal is the pair (customer id, agent key thumbprint). The customer id is the Countersign
record bound to a registered device key. The agent key thumbprint is the RFC 7638 thumbprint of the
key in the open mandate's `cnf`. Neither AP2 nor UCP defines a customer id
([PROTOCOL.md](PROTOCOL.md) gap 12), so this definition is Countersign's.

## 3. Invariants

These hold across all modules. Any change to `merchant`, `cp`, `mpp`, `gate`, `lock`,
`constraints`, `canonical`, `ledger` or `evidence` needs property tests passing, no attack-suite
regression and a decision record in `docs/adr/` if behavior changed.

| ID     | Invariant                                                                                                                                                                                                                                                                     |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| INV-1  | Deterministic verification only. Every check performed by the Merchant, Credential Provider, Payment Processor and Trusted Surface roles runs in deterministic code. No model output is ever an input to an allow decision.                                                   |
| INV-2  | The Trusted Surface is non-agentic. It renders constraints and checkouts from structured data with fixed templates. No model-generated text appears on it. The device private key is non-extractable and never leaves the browser.                                            |
| INV-3  | No authorization without a valid Payment Mandate for any principal that is locked, and for any merchant configured to require AP2.                                                                                                                                            |
| INV-4  | No capture without the gate. Capture is issued only after the gate passes on freshly fetched PayPal state, never from cache. Any gate failure voids the authorization.                                                                                                        |
| INV-5  | The lock follows the principal. Protection keys on (customer id, agent key thumbprint) and merchant policy, never on protocol or session. Policy code may not import protocol adapters, enforced by a test.                                                                   |
| INV-6  | Single use on the keys in [PROTOCOL.md](PROTOCOL.md) Decision 1: checkout hash (which equals `transaction_id`), closed mandate nonce, and one purchase per open mandate (one in-flight closed mandate at a time, and permanent consumption on capture), across all protocols. |
| INV-7  | Budgets come from PayPal state and are add-only. Amounts are reserved while a presentation is in flight, released on a rejection receipt (including a void before capture), and added on capture. A refund never restores headroom. Never from agent claims.                  |
| INV-8  | Canonical bytes are JCS. Everything Countersign signs or hashes as JSON uses RFC 8785 through one library. AP2 hashes are computed over compact serializations as specified. Inbound JSON with duplicate keys, NaN, Infinity or excess precision is rejected first.           |
| INV-9  | Integer minor units for money. No floats in money paths. Non-integer JSON numbers in a constraint make the mandate invalid.                                                                                                                                                   |
| INV-10 | Fail closed. Any exception, timeout, schema error, signature error, unknown `vct`, unknown constraint type, PayPal error or unverified webhook results in no authorization, no capture and a void of any outstanding authorization.                                           |
| INV-11 | Idempotent PayPal calls. Every mutating PayPal call carries a `PayPal-Request-Id` derived from the checkout id and the operation. Retries never create a second order, authorization or capture.                                                                              |
| INV-12 | Log before respond. Every decision, PayPal call, webhook and gate result is appended to the hash-chained log before the response returns. Log failure fails the operation.                                                                                                    |
| INV-13 | Honest claims. No claim about PayPal buyer or seller protection, dispute outcomes or production readiness. Countersign creates PayPal sandbox orders and keeps a verifiable authorization and evidence trail.                                                                 |

## 4. Repository layout and make targets

### 4.1 Repository layout

```text
countersign/
  README.md  LICENSE  Makefile  docker-compose.yml  .env.example  render.yaml
  spec/vendor/{ap2,ucp,acp,rfc9901,delegate-sd-jwt}/  SOURCES.md  CHECKSUMS.sha256
  src/countersign/
    canonical/  protocols/{ucp,acp}/  merchant/  cp/  mpp/  gate/  lock/
    mandates/  constraints/  paypal/  ledger/  evidence/  api/  llm/  catalog/
  agents/{shopper,adversary}/
  web/{dashboard,approve,demo}/
  tests/{unit,conformance,properties,concurrency,integration,cassettes}/
  eval/{attacks,adversary,tasks,reports}/  eval/run.py
  docs/{ENV.md,PROTOCOL.md,LIMITATIONS.md,threat-model.md,architecture.md,PROGRESS.md,adr/,upstream/,submission/}
  scripts/{sandbox_smoke.py,demo_reset.sh,tamper_demo.py,interop_verify.mjs,secret_scan.sh}
```

### 4.2 Make targets

| Target          | Purpose                                                                    |
| --------------- | -------------------------------------------------------------------------- |
| `setup`         | install Python and Node dependencies and start Postgres                    |
| `keys`          | generate the merchant, processor and platform signing keys into `secrets/` |
| `dev`           | run the API and the web apps locally                                       |
| `demo`          | run the scripted demo environment                                          |
| `test`          | unit, conformance, property and integration tests                          |
| `test-safety`   | tests for the invariant modules plus the attack suite smoke run            |
| `sandbox-smoke` | live PayPal sandbox smoke test                                             |
| `eval`          | the full evaluation                                                        |
| `interop`       | verify live merchant signatures with the independent Node verifier         |
| `tamper-demo`   | demonstrate decision-log tamper detection                                  |
| `lint`          | ruff, mypy and web lint                                                    |
| `deploy`        | deployment instructions and checks                                         |

Targets other than `setup` are stubs until the matching work lands.

## 5. Backend modules

Each module is done only when it has code, tests, a docstring with the security reasoning and an
entry in this document. Stack: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, Postgres
16, `httpx`, `rfc8785`, `joserfc`, and an in-house SD-JWT implementation on `joserfc` and `hashlib` ([ENV.md](ENV.md)).

### 5.1 canonical

- A strict JSON loader (`jsonstrict.py`) that rejects duplicate keys, NaN, Infinity, non-UTF-8
  input, a byte order mark, lone surrogate escapes, numbers beyond +/-(2^53 - 1) and excess decimal
  precision, with typed errors that each carry a stable `code`. All inbound JSON passes through it
  first. The number rules are [PROTOCOL.md](PROTOCOL.md) Decision 12.
- One JCS function (`jcs.py`, `canonicalize`, RFC 8785 via the pinned `rfc8785`) used for
  everything Countersign signs or hashes as JSON.
- Hashing helpers (`hashing.py`). Countersign-internal hashes are domain separated (a fixed ASCII prefix before the
  bytes). AP2 hashes (`checkout_hash`, `sd_hash`, receipt `reference`) are plain SHA-256 over the
  exact strings the spec names, with no prefix.
- Money: an ISO 4217 exponent table and an integer minor-unit `Money` type. Parsing from UCP
  integers and PayPal decimal strings, formatting to PayPal strings with exactly the currency's
  exponent. Any inexact conversion is a typed error. Rounding is forbidden.
- The canonical checkout model mirrors the UCP checkout fields Countersign supports: `id`,
  `currency`, line items (item id, title, unit price, integer quantity of whole items, line totals),
  and totals by type with exactly one `subtotal` and one `total`. Items with a non-`each`
  `quantity_unit` are rejected rather than priced, so quantity is always a whole-item count.
  Models are frozen with extra fields forbidden. Line totals and order totals are validated for
  consistency.
- `terms` are the subset the gate compares: id, currency, line items, totals, payee, `invoice_id`,
  `custom_id`. `terms_hash` is a domain-separated SHA-256 over the JCS bytes of the terms.
- Acceptance: RFC 8785 vectors; property tests that key order and whitespace never change bytes and
  that any change to a bound field changes the hash.

### 5.2 protocols (UCP and ACP)

- UCP: the `/.well-known/ucp` profile (checkout capability, the AP2 mandates extension with
  `vp_formats_supported` inside the capability `config`, `keys[]` with the merchant JWK) and the
  REST binding (create, get, update, complete, cancel) with the paths and payloads from the vendored
  spec. Every checkout response is built from the canonical model, never echoed from the request,
  and carries `ap2.merchant_authorization`.
- `merchant_authorization` and `checkout_jwt` are the same ES256 signature, detached and compact
  respectively ([PROTOCOL.md](PROTOCOL.md) Decision 7).
- Validation of `ap2.checkout_mandate` does not use the vendored UCP pattern
  ([PROTOCOL.md](PROTOCOL.md) Decision 9).
- ACP: a thin adapter (create, get, update, complete, cancel) that maps into the same canonical
  model. It exists so the cross-protocol lock can be demonstrated. For a locked principal, `complete`
  returns a typed error with the same meaning as `mandate_required`. No delegated payment is
  implemented.
- Acceptance: schema conformance against the vendored schemas; `merchant_authorization` verifies
  with an independent implementation (a small Node script using `jose`); a cart created through ACP
  and through UCP yields identical canonical bytes.

### 5.3 mandates

- SD-JWT parsing and verification using the in-house implementation described in [ENV.md](ENV.md): key binding, exact `vct` match, `cnf`
  extraction, `exp` and `nbf` with a 60 second skew, an algorithm allowlist (ES256 only, no `none`,
  no HS family), chain verification per the Delegate SD-JWT draft including the `~~` rule and the
  `sd_hash` binding in both directions.
- Strict structural validation of the mandate string ([PROTOCOL.md](PROTOCOL.md) Decision 9).
- Test-only issuers produce valid and invalid open and closed mandates.
- The production issuer is the Trusted Surface backend (after consent verification) for open
  mandates, and the agent library for closed ones.

### 5.4 merchant (Merchant role)

Verification on `complete`, in order. Each step has a stable code in the decision log.

1. `ap2.checkout_mandate` present, else `mandate_required`.
2. Mandate string passes structural validation and signature chain verification (platform key on the
   open mandate, agent `cnf` key on the closed one, or the platform key on a Human Present closed
   mandate), else `mandate_invalid_signature`; expired mandates give `mandate_expired`; a platform
   profile without a usable key gives `agent_missing_key`.
3. `checkout_hash` equals the SHA-256 of the checkout JWT of this session, else
   `mandate_scope_mismatch`.
4. The embedded checkout carries our own valid `merchant_authorization`, else
   `merchant_authorization_invalid` or `merchant_authorization_missing`.
5. Embedded terms equal the current session state (id, totals, line items), else
   `mandate_scope_mismatch`.
6. The principal lock requirements are satisfied ([5.7](#57-lock)).
7. Every constraint evaluates true ([5.6](#56-constraints)), else `unresolved_constraint` for unknown
   types or `mandate_scope_mismatch` for violated ones.
8. Single-use keys reserved ([PROTOCOL.md](PROTOCOL.md) Decision 1).

On any failure the Merchant returns the UCP error and a signed rejection Checkout Receipt. On
success it returns a signed acceptance Checkout Receipt whose `reference` is the hash of the closed
Checkout Mandate. Receipts use the schema in [PROTOCOL.md](PROTOCOL.md) section 1.2.7.

### 5.5 cp (Credential Provider role)

- Verifies the Payment Mandate independently: chain, constraints, `transaction_id` equal to the
  checkout hash, payee, amount and currency against the checkout total, and the token format
  ([PROTOCOL.md](PROTOCOL.md) Decision 8).
- In one database transaction with row locking it reserves budget and the single-use keys.
- Creates the PayPal order with `intent: AUTHORIZE`, `invoice_id` equal to the checkout id,
  `custom_id` carrying the evidence reference, and a deterministic `PayPal-Request-Id`.
- **Pre-authorize check** ([PROTOCOL.md](PROTOCOL.md) Decision 11). In redirect-approval mode,
  after payer approval and before calling authorize, fetches the live order, re-derives the
  canonical terms, compares them with the signed checkout, and calls authorize only on an exact
  match. On a mismatch it never authorizes, so there is nothing to void; it records a rejection
  receipt and releases the reservations. In vault mode create and authorize are one call, so there
  is no such window. `ABL_NO_PREAUTH_CHECK` disables this check for evaluation.
- Acceptance: the happy path against recorded cassettes; 20 parallel `complete` calls with one
  mandate yield exactly one PayPal order; an order patched after approval is not authorized.

### 5.6 constraints

Only native AP2 constraint types are used or evaluated ([PROTOCOL.md](PROTOCOL.md) Decision 4). The
evaluators are pure functions of the closed mandate content and an explicit state view. They never
read agent claims as facts.

| Constraint                                                     | Evaluation                                                                                                                                                                                         |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `checkout.line_items`                                          | each item in the checkout matched to a revealed `acceptable_items` entry with exactly the approved quantities, no entry used twice                                                                 |
| `checkout.allowed_merchants`                                   | this merchant is among the revealed `allowed` entries                                                                                                                                              |
| `payment.amount_range`                                         | integer `payment_amount` within `min` and `max`, same currency                                                                                                                                     |
| `payment.allowed_payees`                                       | the `payee` is among `allowed`                                                                                                                                                                     |
| `payment.allowed_payment_instruments`, `payment.allowed_pisps` | membership check when present                                                                                                                                                                      |
| `payment.reference`                                            | the Checkout Mandate chain contains the open Checkout Mandate whose digest equals `conditional_transaction_id`                                                                                     |
| `payment.agent_recurrence`                                     | accepted only with `max_occurrences` of `1`, which is how Countersign expresses one purchase per open mandate; any other recurrence fails closed as `unresolved_constraint`                        |
| `payment.budget`                                               | `spent + this amount <= max`, add-only, in minor units of the constraint currency, where `spent` is the sum of captured purchases under this open mandate and in-flight reservations count as well |
| `payment.execution_date`                                       | `execution_date` within the window                                                                                                                                                                 |
| any other `type`                                               | fails closed as `unresolved_constraint`                                                                                                                                                            |

The spend view for an open Payment Mandate follows the spec's add-only rule
([PROTOCOL.md](PROTOCOL.md) Decision 2). It is the sum of captured amounts plus in-flight
reservations. A reservation is released when a rejection receipt is issued, including a void before
capture, and the open mandate can then be retried with a new checkout. Capture adds the amount for
good. A refund after capture does not restore headroom. The view is built from PayPal responses and
verified webhooks, and the gate re-evaluates it from fresh state just before capture.

An open mandate backs exactly one successful purchase. Its states are `unused`, `in_flight`,
`consumed` (a capture succeeded), and `revoked` or `expired`. Repeat use under a recurrence
constraint is future work.

Category and similar limits are merchant policy, evaluated by a policy function outside the mandates:
allowed categories per agent, an unmandated purchase cap, velocity limits. Policy changes are
versioned and hashed, and the policy hash is part of every log entry.

Acceptance: boundary tests for every evaluated constraint; a split-purchase scenario where a second
and third purchase under one open mandate are denied by the single-use rule; after a void before
capture the same open mandate can be retried; after a refund it cannot; an unknown type fails
closed; a recurrence other than one occurrence fails closed.

### 5.7 lock

- On every AP2 negotiation the principal (customer id, agent key thumbprint) is recorded as locked.
  Merchant policy can lock all agents.
- Every checkout on any protocol resolves its principal and requires a valid mandate if the
  principal is locked or the merchant requires AP2.
- UCP requests resolve the principal from the platform profile and the mandate chain. ACP requests
  resolve it from a documented Countersign agent identity header. A request that cannot be tied to a
  principal is treated according to merchant policy: when the merchant requires AP2 for all agents,
  it is denied without a mandate; otherwise only the unmandated cap applies. This limit is stated in
  the limitations document.
- The policy code has no imports from `protocols/`, enforced by a test.
- Acceptance: a property test that for every locked principal and every protocol path, no mandate
  implies denial.

### 5.8 paypal

- A typed `httpx` client over the sandbox REST API: OAuth with token caching, create order
  (`AUTHORIZE`), get order, authorize, get authorization, capture, void, refund, and webhook
  signature verification.
- `PayPal-Request-Id` is deterministic: a hash of the checkout id and the operation name, so a retry
  of the same operation replays instead of repeating. Length and replay behavior are confirmed in
  section 10.
- `invoice_id` equals the checkout id. `custom_id` carries a compact reference derived from the
  evidence reference, for example `cs1.` plus a base64url digest, truncated only if the confirmed
  length limit requires it, with the security level documented. The full evidence lives in our store.
- Reverse translation turns a live PayPal order into canonical terms (amount, breakdown, items,
  currency, payee, `custom_id`, `invoice_id`). Fields PayPal cannot carry are listed in
  [PROTOCOL.md](PROTOCOL.md) and are covered by the evidence reference.
- Webhooks: `POST /webhooks/paypal`, verified through PayPal's verification endpoint, deduplicated by
  event id, reconciling the spend view. Unverified events are logged and ignored.
- Unit tests mock PayPal with `respx`. Integration tests use recorded cassettes with tokens scrubbed,
  or the live sandbox.

### 5.9 gate (Merchant Payment Processor capture gate)

Each step is logged with its code. The gate always fetches live PayPal state and never reads a cached
order object.

| Code        | Check                                                                                                                                |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `G-FETCH`   | fetch the live order and authorization from PayPal                                                                                   |
| `G-STATUS`  | the authorization is capturable and unexpired                                                                                        |
| `G-REVERSE` | re-derive canonical terms from the live order                                                                                        |
| `G-TERMS`   | re-derived terms equal the signed checkout terms; `invoice_id` and `custom_id` equal what the Credential Provider set                |
| `G-AMOUNT`  | the authorization amount equals the checkout total exactly                                                                           |
| `G-MANDATE` | the mandates are still unexpired and not revoked, the single-use keys are reserved by this checkout, and the consent record verifies |
| `G-BUDGET`  | the budget still holds under a freshly reconciled spend view                                                                         |
| `G-LOCK`    | the principal lock requirements are still satisfied                                                                                  |

On pass: capture, consume the keys and the open mandate, add the amount to the spend view and sign
the Payment Receipt. On fail: void, release the reservations (the open mandate returns to `unused`
and may be retried with a new checkout) and sign a rejection Payment Receipt. The `reference` of each receipt is
the hash of the closed Payment Mandate.

The gate is the second layer behind the pre-authorize check in the Credential Provider role. The
sandbox rejects a PATCH after authorization, so the gate is not what stops an order raised after
approval in `full` mode; it covers mandate revocation, budget state, evidence assembly and any path
in which the pre-check was skipped (`ABL_NO_PREAUTH_CHECK`).

Acceptance: tests where the order is changed after payer approval and before authorization (the
mutation window confirmed in PROTOCOL.md, Confirmed PayPal facts; in `full` mode nothing is
authorized, and with `ABL_NO_PREAUTH_CHECK` the order is authorized and the gate voids it), the mandate is revoked between authorization and capture, a concurrent purchase exhausts
a second purchase races the first under one open mandate, and two gates race on one checkout. Each must capture or void exactly once.

### 5.10 ledger (decision log)

- An append-only table. For each entry `entry_hash = SHA256("cs.log.v1" || prev || seq || ts ||
payload_hash || policy_hash)`, with each component encoded with a fixed-width or length-prefixed
  encoding so the concatenation is unambiguous.
- Merkle roots per checkout and per day, inclusion proofs, and a verify function that reports the
  first broken link. `/ledger/verify` exposes it.
- The application database role has INSERT and SELECT only on the log table.
- A tamper demo script modifies, deletes, inserts and reorders entries and shows detection. The log
  is tamper-evident. It is not a blockchain and is not described as one.
- Log failure fails the operation (INV-12).

### 5.11 evidence

A bundle is written at capture, keyed by the PayPal capture id. Contents:

- the `checkout_jwt`;
- the open and closed Checkout Mandates and the open and closed Payment Mandates, with only the
  disclosures that were used;
- the Checkout Receipt and the Payment Receipt;
- the device consent records, consent signatures and the registered device public key;
- the PayPal order, authorization and capture objects as fetched;
- the gate result;
- decision log inclusion proofs;
- the merchant, processor, platform and agent public keys.

An offline verifier, a Python CLI and a browser module sharing test vectors, performs the AP2
dispute steps ([PROTOCOL.md](PROTOCOL.md) section 1.2.8), then checks the device consent signature
against the mandate content, checks the PayPal objects against the checkout terms, and checks the
log proofs. Tampering with any byte makes verification fail at the correct step with a clear message.

### 5.12 api, llm, catalog

- `api`: the FastAPI app, the edge checks (strict JSON, size limits, request hashing), the customer
  key registration and consent endpoints, the dashboard API, the event stream and the webhook route.
- `llm`: one interface for model calls with structured output, timeouts, logging and record and
  replay for deterministic tests. It is used by the shopping agent, the assistant and the hostile
  agent. No verification module imports it.
- `catalog`: a seeded fictional catalog with fictional brands and several categories, used by the
  demo store and the agent.

## 6. Runtime modes

- `CS_MODE=full`: everything described above.
- `CS_MODE=baseline`: a careful but conventional AP2-aware gateway. It verifies UCP mandates
  correctly at `complete`, but has no capture gate (it captures immediately after authorization),
  no principal lock (the ACP path is accepted without mandates), no budget reconciliation, and only
  per-session nonce memory. It exists so comparisons are fair and the value of the gate and lock is
  visible.
- Ablations in `full`: `ABL_NO_GATE`, `ABL_NO_PRINCIPAL_LOCK`, `ABL_NO_BUDGET_RECON`,
  `ABL_NO_GLOBAL_NONCE`, `ABL_NO_STRICT_JSON`, `ABL_NO_PREAUTH_CHECK`. They are refused when
  `APP_ENV=demo`.

## 7. Product surfaces

One visual system across all surfaces: one self-hosted font pair, one accent color, light and dark
themes, shared tokens and components.

### 7.1 Merchant dashboard

`web/dashboard`, desktop first, React, TypeScript and AG Grid.

1. **Onboarding** in three steps: connect a PayPal sandbox REST app (credentials stored server
   side), choose the protection mode (require AP2 for all agents, or above a threshold), publish the
   UCP profile (shows the live `/.well-known/ucp` URL and a button to test with a sample agent).
2. **Agent orders** (AG Grid): one row per checkout across protocols. Columns: time, customer,
   agent, protocol, amount, mandate status, gate result, PayPal order id, capture id, evidence
   status. Grouping by agent and customer, a pinned totals row, status renderers, quick filter and
   CSV export. A row opens the detail view.
3. **Order detail:** the signed checkout with its `merchant_authorization` status, the mandates with
   decoded disclosures and the signature chain, and the live PayPal order fetched now with its
   re-derived terms. Differences are highlighted. A gate step timeline and linked log entries with
   inclusion proofs.
4. **Evidence:** per capture, "Verify evidence" runs the verifier in the browser and shows each
   dispute step. "Download bundle" exports the bundle file.
5. **Protection activity** (grid and charts): blocked attempts by reason code, voided
   authorizations, budget usage per open mandate, and baseline versus full results from the latest
   evaluation.
6. **Policy:** protection mode, unmandated cap, allowed categories, velocity limits. Changes are
   versioned and hashed.
7. **Ask Countersign** (the merchant assistant, [7.4](#74-merchant-assistant)).

### 7.2 Trusted Surface

`web/approve`, mobile first at 375 px. All text comes from fixed templates and structured data.

- **Setup:** one tap creates the device key and shows a short fingerprint.
- **Approve intent:** each term of the open mandates rendered from fixed templates (the exact item
  list, "Up to $80.00 in total", "Expires Sun 25 Oct, 18:00"), the merchant name and the agent
  fingerprint. Approve and Decline. Approve signs the consent record.
- **Approve purchase:** for Human Present, the exact line items and totals, then consent.
- **My agent activity:** the state of each open mandate (unused, in flight or used), its ceiling and expiry, the purchase made under it, and a revoke button.

### 7.3 Demo storefront and agent console

`web/demo`: a minimal store page listing the seeded catalog and a live console streaming the agent's
steps. Used for the demo and the hosted demo only. Fictional brand names, no real brands or logos.

### 7.4 Merchant assistant

A model-backed assistant that answers merchant questions grounded in dashboard data, using read-only
tools: query orders, fetch a checkout's gate steps, explain an error code, summarize an evidence
bundle, compare baseline and full results. Every numeric answer cites the row or log entry it came
from, and a grounding check replaces ungrounded numbers with a template answer. If the grid
vendor's model-based features are licensed and fit, the assistant can drive grid state from natural language.
Otherwise it returns a grid state object the dashboard applies. It has no write access.

### 7.5 Agents

- `agents/shopper`: a separate process with tools that speak only UCP over HTTP. It turns a goal
  into structured terms, requests approval through the Trusted Surface link, searches the catalog,
  builds and updates a checkout, verifies `merchant_authorization` before trusting the checkout,
  signs closed mandates with its own key (held only in its process), completes and reports.
- `agents/adversary`: scripted attack cases plus a model-planned mode that plans across UCP and ACP
  toward a goal. It has no PayPal credentials and no database access. Every attempt is logged.

## 8. Evaluation

Ground truth is PayPal sandbox state (fetched), the decision log and evidence verification. Never a
model judge.

| Suite              | Notes                                                                                                                      |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Spec conformance   | every endpoint against the vendored schemas; mandate structures; signatures verified by an independent Node implementation |
| Properties         | Hypothesis; JCS stability, mutation detection, lock property, budget monotonicity, gate exactly-once                       |
| Attack suite       | at least 40 cases across the categories below                                                                              |
| Hostile agent runs | model-planned goals across several seeds; success means money captured outside what was signed or allowed                  |
| Agent task suite   | at least 25 legitimate purchases; completion rate and latency                                                              |
| Concurrency        | parallel completes, racing gates, duplicate webhooks                                                                       |

Attack categories: `mandate_forged`, `alg_confusion`, `mandate_expired`, `mandate_revoked`,
`nonce_replay`, `open_mandate_double_spend`, `checkout_swap`, `price_change_before_complete`,
`order_changed_after_approval` (the order amount is raised after payer approval and before
authorize; success condition: money authorized or captured outside the signed checkout. In `full`
mode nothing is authorized. With `ABL_NO_PREAUTH_CHECK` it is authorized and then voided by the
gate. In baseline it is authorized and captured), `custom_id_tamper`, `protocol_downgrade_acp`, `new_session_escape`,
`budget_split` (expected denial through the single-use rule, the same defense as `open_mandate_double_spend`), `category_escape` (a merchant policy test, since category limits are not in
mandates), `duplicate_json_keys`, `decimal_ambiguity`, `webhook_spoof`, `double_complete_retry`,
`merchant_authorization_strip`, `consent_missing` (mandate issuance without a valid device
consent).

Headline metrics, reported in baseline and full: unauthorized captures (target 0), attack success
rate (0 for deterministic cases, hostile-agent rate with a 95 percent confidence interval),
duplicate PayPal objects (0), evidence bundles that verify (all captures), legitimate task
completion (at least 90 percent), false block rate, and added gate latency at p50 and p95. Per
ablation results are reported, including any ablation that reopens nothing. Reports live under
`eval/reports/<run>/` and `latest` points at the most recent run.

## 9. What is new

What the specs already do is stated next to each item. Details of the underlying spec facts are in
[PROTOCOL.md](PROTOCOL.md).

| ID  | Contribution                                                                                                                                                                                                                 | What the specs already cover                                                                                                                     |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| N1  | AP2 Credential Provider and Payment Processor roles implemented on PayPal Orders. The Payment Mandate is verified before a PayPal authorization, and the PayPal order is the credential scoped to the checkout               | AP2 requires the processor to verify the credential is scoped to the checkout and leaves the mechanism open                                      |
| N2  | Capture-time re-verification against live PayPal state. Immediately before capture, the live order and authorization are fetched and compared with the signed checkout                                                       | UCP checks terms at `complete`. Between authorization and capture the order can still change                                                     |
| N3  | Principal-scoped protection lock across protocols                                                                                                                                                                            | The UCP lock is per session only                                                                                                                 |
| N4  | Single-use and budget state derived from PayPal outcomes (captures and voids, never agent claims) for the native `payment.budget` and `payment.agent_recurrence` constraints, enforced at authorization and again at capture | AP2 defines `payment.budget` and `payment.agent_recurrence` and the add-only rule but leaves the state source to the verifier                    |
| N5  | A dispute evidence bundle keyed by PayPal capture id, verifiable offline with the AP2 dispute steps and exportable as one file                                                                                               | AP2 says mandates and receipts can be dispute evidence and leaves retention and retrieval out of scope                                           |
| N6  | A device consent signature from a non-extractable customer key over the exact terms, required before the platform signs any mandate, stored as independent evidence                                                          | AP2 and UCP define the trusted platform provider and user credential models. A device consent record is additional and sits outside the mandates |

## 10. Day 0 confirmations

Each item is answered or has a written fallback in [PROTOCOL.md](PROTOCOL.md) or [ENV.md](ENV.md).

Specs and libraries:

- [x] Specs vendored with pinned revisions (`spec/vendor/SOURCES.md`).
- [x] Claim names, `vct` strings, hash rules, native constraint types, `merchant_authorization`
      format, UCP error codes, token placement, profile keys format
      ([PROTOCOL.md](PROTOCOL.md) section 1).
- [x] JCS, JWS and SD-JWT with key binding library choices, plus Node `jose` for the interop
      verifier ([ENV.md](ENV.md)). No third-party SD-JWT library; built on `joserfc`.

PayPal sandbox:

- [ ] App, merchant and buyer accounts, and webhook id. Accounts exist and were used in the runs
      (the buyer and merchant must be US-based, [ENV.md](ENV.md) section 2.5). The webhook id does not
      exist yet: a webhook needs a public URL, so it is created at the Render deploy.
- [x] `custom_id` and `invoice_id` maximum lengths, and that both survive on get order, authorization
      and capture ([PROTOCOL.md](PROTOCOL.md) section 4.1; [ENV.md](ENV.md) section 2.5).
- [x] `PayPal-Request-Id` length limit and idempotent replay behavior
      ([PROTOCOL.md](PROTOCOL.md) sections 4.1 and 4.2; [LIMITATIONS.md](LIMITATIONS.md) L2).
- [x] Whether an order can be changed after authorization and with which fields. If not, the
      order-changed attack uses another mutation path, which is documented. Answered: not after
      authorization, but yes while `APPROVED`; the attack is `order_changed_after_approval`
      ([PROTOCOL.md](PROTOCOL.md) section 4.3, Decision 11).
- [x] Authorization validity in sandbox, void and refund behavior
      ([PROTOCOL.md](PROTOCOL.md) sections 4.4 to 4.6).
- [ ] Webhook events for authorize, capture, void and refund, and how signature verification works.
      Recorded from documentation ([PROTOCOL.md](PROTOCOL.md) section 4.8); live confirmation is
      deferred to the Render deploy.
- [x] Payer approval method: whether a sandbox wallet can be vaulted for later merchant-initiated
      orders in this app. Yes in the sandbox; fallback is a fresh payer approval per purchase
      ([PROTOCOL.md](PROTOCOL.md) section 4.7; [LIMITATIONS.md](LIMITATIONS.md) L1).

Other:

- [x] Grid vendor license terms and which features are free versus paid
      ([ENV.md](ENV.md) section 3). Open manual checks are listed there.
- [x] Hosting plan fit for the API, static sites and Postgres for the evaluation period
      ([ENV.md](ENV.md) section 4). The free Postgres expires inside the judging period; the
      fallback is written there.
- [x] Model provider and model ids: written fallback, chosen at P3.5 behind a provider-agnostic
      interface ([ENV.md](ENV.md) section 6). Record and replay is built at P3.5.
- [x] Submission form fields reviewed, from the rules and the help center
      ([ENV.md](ENV.md) section 5). The live form is only visible after starting a submission; the
      manual checks are in [submission/checklist.md](submission/checklist.md).

Gate: `make sandbox-smoke` passes (create an AUTHORIZE order, approve, authorize, get, capture,
refund; a second order authorized then voided), and every item above has an answer or a written
fallback.

## 11. Documentation and submission material

### 11.1 Documentation

- **README:** the pitch, a short demo animation, the hosted demo link and sandbox test login, the
  results table, the architecture diagram, the role mapping table, what is new versus the specs,
  a quickstart (`make setup && make demo`), the third-party tools used, limitations, license, and a
  short FAQ.
- **LIMITATIONS:** sandbox only; a single merchant; Countersign plays Merchant, Credential
  Provider, Payment Processor and Trusted Surface together, so the mandate signer is also a verifier;
  the payer approval method; specs pinned to draft or dated versions; the interpretations in
  [PROTOCOL.md](PROTOCOL.md) (budget units, `ON_DEMAND`, the recurrence mapping, `checkout_jwt`); the UCP
  mandate pattern workaround; hostile-agent success rates are empirical; gate correctness is tested,
  not formally verified; no claim about PayPal protection programs; any `custom_id` truncation;
  principals that cannot be identified on non-AP2 protocols; every marked shortcut in the code.
- **PROTOCOL:** vendored versions, claim names, hash and canonicalization rules, decisions, gate step
  codes, lock semantics, PayPal field mapping and every deviation.
- **threat-model:** assets, actors (hostile agent, compromised agent key, compromised platform key,
  network attacker on webhooks, merchant insider), trust boundaries, and each attack category mapped
  to an invariant and a test.

Metrics in any document cite the evaluation report file they come from.

### 11.2 Video

Under three minutes, aiming for 2:45. No third-party logos or trademarks beyond naming PayPal as the
platform, a fictional store brand, no music or royalty-free music, and captions on.

| Time        | Content                                                                                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0:00 - 0:20 | The problem in two sentences, the one-line pitch, the PayPal sandbox visible on screen                                                                                         |
| 0:20 - 1:05 | The customer approves on the phone; the agent shops on its own; the dashboard row appears with mandate verified, order authorized, gate passed, captured                       |
| 1:05 - 1:55 | Attacks side by side, baseline versus Countersign: a protocol downgrade, an order changed after approval, a mandate reuse; each with its reason code and "no money moved" |
| 1:55 - 2:20 | "I never bought this": the merchant verifies the evidence and each dispute step passes; the assistant answers a question with citations                                        |
| 2:20 - 2:45 | Results and what is new, then the pitch line                                                                                                                                   |

### 11.3 Submission description

Headings, in order: Inspiration, What it does, How PayPal is used (every Orders, Payments and
webhook call and why), How AI is used, What is new, Results (a table from the latest evaluation
report), Design, Who it's for, How we built it, Challenges, Limitations, What's next, Try it (hosted
URL, sandbox buyer login, a three-step test script), Built with.

The first paragraph states that PayPal is central. Every claim is backed by code or an evaluation
report.

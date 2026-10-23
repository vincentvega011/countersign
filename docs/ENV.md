# ENV

Environment facts and technology choices, each with the reason. Sections for the PayPal sandbox
reference notes, the grid library license, hosting and the model provider are added when those
are confirmed (see the Day 0 list in [architecture.md](architecture.md)).

## 1. Cryptography and canonicalization libraries

### 1.1 Requirements used for the evaluation

Every requirement traces to [PROTOCOL.md](PROTOCOL.md).

| #   | Requirement                                                                                                                                                      | Source                                          |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| R1  | JCS (RFC 8785) for the payload of `merchant_authorization`, rejecting integers outside +/-(2^53 - 1), NaN, Infinity and lone surrogates                          | section 1.3.3                                   |
| R2  | ES256 JWS in compact and detached form, protected header exactly `{alg, kid}`, an algorithm allowlist of ES256 only                                              | sections 1.3.3 and Decision 7                   |
| R3  | The chain format `<SD-JWT>~~<KB-SD-JWT>~<disclosures>~` with exactly one empty component between links                                                           | section 1.2.3                                   |
| R4  | Link `typ` `kb+sd-jwt`, and `sd_hash` over the US-ASCII bytes of the previous serialization including its trailing `~`, checked in both directions               | sections 1.2.3 and 1.2.4                        |
| R5  | Disclosure resolution for object properties and array elements, digests over the base64url disclosure string, rejection of unreferenced or duplicate disclosures | section 1.2.3 (RFC 9901 sections 4.2.3 and 7.1) |
| R6  | Each link verified with the `cnf` key of the previous link, the first with the platform provider key                                                             | section 1.2.5 and Decision 5                    |
| R7  | `exp` and `nbf` checks with a 60 second skew                                                                                                                     | Decision 10                                     |
| R8  | We compute `checkout_hash`, `transaction_id`, `sd_hash` and receipt `reference` ourselves, as plain SHA-256 over the strings the spec names                      | section 1.2.4                                   |
| R9  | Strict structural validation of the mandate string instead of the UCP pattern                                                                                    | Decision 9                                      |
| R10 | An independent verifier in Node for detached JWS, with an independent JCS implementation                                                                         | architecture, `protocols`                       |
| R11 | Maintained, with a permissive license                                                                                                                            | general                                         |

### 1.2 Choices

| Purpose                            | Choice                                                                        | Version         | License    | Reason                                                                                                                                                                                                                                        |
| ---------------------------------- | ----------------------------------------------------------------------------- | --------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JCS (Python)                       | `rfc8785`                                                                     | 0.1.4           | Apache-2.0 | Passes every vector checked (below). Rejects the unsafe integers and non-finite floats we need to reject. Small and pure Python.                                                                                                              |
| JWS (Python)                       | `joserfc`                                                                     | 1.7.5           | BSD-3      | ES256, detached payload (`deserialize_compact(..., payload=...)`) and an algorithm allowlist all work. Pinned to 1.7.5 rather than the newest 1.7.7 because 1.7.6 and 1.7.7 were released within the last week, and the API used is the same. |
| Key handling, tests                | `cryptography`                                                                | 50.0.2 (locked) | Apache-2.0 | Required by `joserfc`. Declared as a dev dependency because tests build keys directly.                                                                                                                                                        |
| SD-JWT with key binding and chains | none: built from scratch in `countersign.mandates` on `joserfc` and `hashlib` | n/a             | n/a        | No maintained library handles the chain format (below). The needed code is small, and the spike proves it against the worked examples.                                                                                                        |
| Node interop verifier              | `jose`                                                                        | 6.2.12          | MIT        | Verifies the detached JWS produced by Python.                                                                                                                                                                                                 |
| Node JCS                           | `canonicalize`                                                                | 5.1.0           | Apache-2.0 | An independent RFC 8785 implementation, so the Node check does not share code with the Python signer.                                                                                                                                         |

Pinning policy. The Python cryptographic and canonicalization libraries are pinned with `==` in
`pyproject.toml` and locked in `uv.lock`. The Node ones are pinned exactly in `package.json` and
locked in `pnpm-lock.yaml`. Where a choice exists, a release at least two weeks old is preferred.

### 1.3 Evidence

All of this is reproducible with `scripts/spikes/run_spikes.sh` (and the library probe below).

**rfc8785 0.1.4** (`scripts/spikes/jcs_vectors.py`, vectors read from the vendored RFC text):

- All 26 rows of the Appendix B number table match, with NaN and Infinity rejected.
- The worked example in RFC sections 3.2.2 to 3.2.4 matches byte for byte.
- The property sorting data in section 3.2.3 sorts in UTF-16 code unit order.
- Integers beyond +/-(2^53 - 1) raise `IntegerDomainError`, which matches the UCP integer cap.
- A lone surrogate as a value raises `CanonicalizationError`, but as an object key it raises
  `UnicodeEncodeError`. The wrapper in `countersign.canonical` must catch both.
- It canonicalizes parsed Python objects. Rejection of duplicate keys and of excess decimal precision
  stays the job of our strict JSON loader, which runs first.
- `1.0` serializes as `1`, as JCS requires. Money paths use integers and never reach this case.

**joserfc 1.7.5** (`scripts/spikes/jws_detached.py`):

- ES256 signing and verification work. A detached JWS `header..signature` verifies when the JCS bytes
  are passed as `payload`.
- The compact `checkout_jwt` and the detached `merchant_authorization` share one header and one
  signature, as Decision 7 requires.
- With `algorithms=["ES256"]`, an ES384 token, `alg: none` and an HS256 token forged against a public
  key are all rejected (`UnsupportedAlgorithmError`). A tampered payload raises `BadSignatureError`.
- Always pass `algorithms=["ES256"]` explicitly.

**Node, `jose` 6.2.12 and `canonicalize` 5.1.0** (`scripts/spikes/jose_detached.mjs`): verifies the
detached `merchant_authorization` produced by Python, re-canonicalizing the checkout independently,
and rejects a tampered checkout.

**SD-JWT chains from scratch** (`scripts/spikes/sdjwt_chain.py`), using only `joserfc` and `hashlib`:

- Parses the chain with the exactly-one-empty-component rule, resolves object and array element
  disclosures, verifies each link with the previous link's `cnf` key, and checks `typ`, `sd_hash`
  and the presence of `iat`, `aud` and `nonce`.
- Reproduces the three worked examples in the vendored AP2 documents (open Checkout Mandate, chained
  Checkout Mandate, chained Payment Mandate): the `~~` split, the key-binding signature against the
  open mandate's `cnf`, `sd_hash`, `checkout_hash` equal to the hash of `checkout_jwt`,
  `transaction_id` equal to `checkout_hash`, and the `payment.reference` digest equal to the digest of
  the open Checkout Mandate. The issuer signatures of those examples are not checked because their
  issuer key is not published.
- Issues a new chain (platform-signed open mandate, agent-signed closed mandate, merchant-signed
  `checkout_jwt` built as in Decision 7) and verifies it.
- Rejects: a wrong issuer key, a single `~` instead of `~~`, a closed mandate not signed by the `cnf`
  key, `sd_hash` computed without the trailing `~`, an altered disclosure and a missing trailing `~`.
- Parsing and verification take about 120 lines. The rest of the file is the issuer and the example checks.

### 1.4 SD-JWT library candidates

| Candidate                                    | Version and date                                         | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sd-jwt` (OpenWallet Foundation, Apache-2.0) | 0.10.4, released 2024-02-16; last code change 2024-05-15 | Verifies a single SD-JWT with array element disclosures (our open mandate on its own). Does not handle the chain: the full chain fails to parse. Key binding is a fixed `kb+jwt` type and expects `cnf` at the top level of the payload, while AP2 puts `cnf` inside the disclosed `delegate_payload` element. The source has `TODO: Check exp/nbf/iat`, verifies the issuer signature with no algorithm allowlist, and supports only `sha-256`. Depends on `jwcrypto`. |
| `jwskate`                                    | 0.12.2, MIT                                              | JOSE toolkit. No SD-JWT support found in the package.                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `pyeudiw`                                    | 2.2.0                                                    | Described as a toolchain for building an OpenID4VP relying party with SATOSA. Not a library for this use, and not evaluated further.                                                                                                                                                                                                                                                                                                                                    |

`scripts/spikes/sdjwt_library_probe.py` records the `sd-jwt` findings against tokens issued by the
chain spike. Run it with `uv run --with sd-jwt python scripts/spikes/sdjwt_library_probe.py`. The
library is not a project dependency.

### 1.5 Decision

Build `countersign.mandates` from scratch on `joserfc` and `hashlib`. The chain format is not handled
natively by any maintained library, and the one candidate with SD-JWT support fails on the chain,
on `cnf` placement, on `typ`, on expiry checks and on algorithm restriction, so wrapping it would
mean replacing most of it. The from-scratch path is proven by the spike on the same examples that
define the format.

Risks and how they are handled:

- Security-critical code is ours. It is tested with the AP2 worked examples as vectors, mutation
  property tests, and the negative cases above. The browser evidence verifier (a second
  implementation in TypeScript with `jose`) is a later independent check on chain verification.
- The draft is still moving. Both pinned revisions are vendored, and the `typ` value changed between
  them for multi-hop chains. AP2 v0.2.0 examples use only `kb+sd-jwt`.
- The `typ` of the issuer-signed JWT is unspecified (the AP2 examples use `example+sd-jwt`). It is
  recorded in [PROTOCOL.md](PROTOCOL.md) when the issuer is built.

## 2. PayPal sandbox API reference notes

Sources: PayPal's published OpenAPI documents for Orders v2 (spec version 2.32) and Payments v2,
read as JSON schemas, plus the endpoint pages on developer.paypal.com. Each fact below is _from the
schema_ (stated in the OpenAPI document). What a live sandbox run showed is in
[2.5](#25-observed-in-the-live-sandbox-run). The script `scripts/sandbox_smoke.py` is built only on
this section.

Sandbox base URL (from the `servers` block of the Payments v2 schema): `https://api-m.sandbox.paypal.com`.
The script refuses any other host.

### 2.1 Endpoints used

| Step              | Method and path                                               | Success status (schema)        | Notes                                                                                          |
| ----------------- | ------------------------------------------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------- |
| Token             | `POST /v1/oauth2/token`                                       | 200                            | HTTP Basic (client id, secret), form body `grant_type=client_credentials`                      |
| Create order      | `POST /v2/checkout/orders`                                    | 201 (200 on idempotent replay) | `PayPal-Request-Id`, optional `Prefer`                                                         |
| Get order         | `GET /v2/checkout/orders/{id}`                                | 200                            | Path `id` pattern `^[A-Z0-9]+$`, max 36                                                        |
| Authorize order   | `POST /v2/checkout/orders/{id}/authorize`                     | 201 (200 idempotent replay)    | Body optional. Also lists 202, 207 and 409 (order or unit state)                               |
| Get authorization | `GET /v2/payments/authorizations/{authorization_id}`          | 200                            | No idempotency header                                                                          |
| Capture           | `POST /v2/payments/authorizations/{authorization_id}/capture` | 201 (200 idempotent replay)    | 409 `PREVIOUS_REQUEST_IN_PROGRESS`; 422 `MAX_CAPTURE_AMOUNT_EXCEEDED`, `AUTHORIZATION_EXPIRED` |
| Get capture       | `GET /v2/payments/captures/{capture_id}`                      | 200                            |                                                                                                |
| Refund            | `POST /v2/payments/captures/{capture_id}/refund`              | 201 (200 idempotent replay)    | Empty body is a full refund. 422 `REFUND_AMOUNT_EXCEEDED`, `TRANSACTION_DISPUTED`              |
| Void              | `POST /v2/payments/authorizations/{authorization_id}/void`    | 200 (204 also listed)          | Returns the authorization with `status` `VOIDED`. 422 `PREVIOUSLY_CAPTURED`                    |

Headers. `PayPal-Request-Id`: 1 to 108 characters; the server keeps keys for 6 hours (up to 72 hours
by arrangement); mandatory for single-step create calls that carry a payment source with stored
credentials, optional otherwise. `Prefer`: `return=minimal` (default; `id`, `status` and links only)
or `return=representation` (full resource), at most 25 characters. The script sends
`return=representation` so every field relevant to the design is visible.

### 2.2 Request fields relied on

Create order (`order_request`; required: `intent`, `purchase_units`):

| Field                                                                | Constraint (schema)                                                                               |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `intent`                                                             | `AUTHORIZE` or `CAPTURE`                                                                          |
| `purchase_units[].reference_id`                                      | 1 to 256 characters; defaults to `default` for a single unit                                      |
| `purchase_units[].amount.currency_code`, `.value`                    | `amount` is the only required field of a purchase unit                                            |
| `purchase_units[].amount.breakdown.item_total`, `.tax_total`         | `item_total` required when items carry `unit_amount`; `tax_total` required when items carry `tax` |
| `purchase_units[].items[].name`                                      | required, 1 to 3000 characters (truncated to 127 in the response)                                 |
| `purchase_units[].items[].quantity`                                  | required, string, pattern `^[1-9][0-9]{0,9}$`                                                     |
| `purchase_units[].items[].unit_amount`                               | required; must equal `unit_amount * quantity` summed into `item_total`                            |
| `purchase_units[].items[].tax`                                       | per unit; must sum to `tax_total` as `tax * quantity`                                             |
| `purchase_units[].items[].sku`                                       | 0 to 127 characters                                                                               |
| `purchase_units[].items[].category`                                  | `DIGITAL_GOODS`, `PHYSICAL_GOODS`, `DONATION`                                                     |
| `purchase_units[].invoice_id`                                        | 1 to **127** characters; unique per merchant account by default                                   |
| `purchase_units[].custom_id`                                         | 1 to **255** characters; "not visible to the payer"                                               |
| `payment_source.paypal.experience_context.return_url`, `.cancel_url` | URLs the payer returns to                                                                         |
| `payment_source.paypal.experience_context.user_action`               | `CONTINUE` or `PAY_NOW`                                                                           |
| `payment_source.paypal.experience_context.shipping_preference`       | `GET_FROM_FILE`, `NO_SHIPPING`, `SET_PROVIDED_ADDRESS`                                            |
| `payment_source.paypal.experience_context.payment_method_preference` | `UNRESTRICTED` or `IMMEDIATE_PAYMENT_REQUIRED`                                                    |

Capture (`capture_request`, body optional): `amount`, `final_capture`, `invoice_id` (1 to 127),
`note_to_payer`, `soft_descriptor`. Refund (`refund_request`): `amount` (omit for a full refund),
`custom_id` (1 to 127), `invoice_id` (1 to 127), `note_to_payer` (1 to 255).

### 2.3 Response fields relied on

| Object                                  | Fields                                                                                                                                                                                                                    |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Token                                   | `access_token`, `token_type`, `expires_in` (never printed or stored)                                                                                                                                                      |
| Order                                   | `id`, `status`, `intent`, `links[]` (`href`, `rel`, `method`), `purchase_units[]` (`reference_id`, `amount`, `invoice_id`, `custom_id`, `items`, `payee.merchant_id`, `payments.authorizations[]`, `payments.captures[]`) |
| Authorization (in order and standalone) | `id`, `status`, `amount`, `invoice_id`, `custom_id`, `expiration_time`, `seller_protection`, `links[]`                                                                                                                    |
| Capture                                 | `id`, `status`, `amount`, `final_capture`, `invoice_id`, `custom_id`, `links[]` (`up` to the authorization, `refund`)                                                                                                     |
| Refund                                  | `id`, `status`, `amount`, `invoice_id`, `custom_id`, `links[]`                                                                                                                                                            |
| Error body                              | `name`, `message`, `debug_id`, `details[]` (`issue`, `field`, `description`)                                                                                                                                              |

Status enums (schema): order `CREATED`, `SAVED`, `APPROVED`, `VOIDED`, `COMPLETED`,
`PAYER_ACTION_REQUIRED`; authorization `CREATED`, `CAPTURED`, `DENIED`, `PARTIALLY_CAPTURED`,
`VOIDED`, `PENDING`; capture `COMPLETED`, `DECLINED`, `PARTIALLY_REFUNDED`, `PENDING`, `REFUNDED`,
`FAILED`; refund `CANCELLED`, `FAILED`, `PENDING`, `COMPLETED`.

Two points that matter to the gate design. The authorization status enum has **no `EXPIRED`**, so
expiry has to be judged from `expiration_time`, not from `status`. The capture and refund response
schemas include `custom_id` and `invoice_id`, so persistence on capture is checkable.

Approval link: the order response carries a link with `rel` `approve` or `payer-action`. The script
accepts either and prints whichever is present.

### 2.4 Order PATCH (read only; exercised in the later behaviour checks)

`PATCH /v2/checkout/orders/{id}` updates an order in `CREATED` or `APPROVED` status; a `COMPLETED`
order cannot be updated. The schema does not state whether an order that has been authorized is still
patchable, which is exactly what the attack depends on. That is settled by a live run, not here.

### 2.5 Observed in the live sandbox run

Observed once, with `scripts/sandbox_smoke.py` against one sandbox account; both flows completed.
Items marked _single run_ are not yet established as general rules.

- **Order status versus authorization status.** After authorize, the order `status` was `COMPLETED`
  while the embedded authorization `status` was `CREATED`. The order status says nothing about
  whether money can still be captured, so the capture gate must evaluate the authorization object.
- **Authorization lifetime.** `expiration_time` was 29 days after `create_time` (_single run_, not
  confirmed as a general rule).
- **Identifier persistence.** `invoice_id` and `custom_id` were returned unchanged on create,
  authorize, GET order, GET authorization, capture, refund and the GET after void.
- **Mutation response bodies are not reliable.** The void response body returned `custom_id` as
  `null` and used a different timestamp format (a UTC offset instead of `Z`), while the GET that
  followed returned both correctly. Rule: the gate and clients always re-fetch with GET and never
  rely on the body of a mutation response.
- **Refund.** After a full refund, GET capture shows status `REFUNDED`.
- **`PayPal-Request-Id`.** The values used were accepted at the lengths used.
- **`seller_protection.status`** appeared in sandbox output. Countersign makes no claims about it.

Demo-setup note. The sandbox buyer and merchant accounts must be US-based. A buyer account based in
Nepal could not approve the order.

Also settled by the same run (_single run_):

- **Debug id.** The PayPal debug id was read from a response header.
- **Approval link.** The link `rel` on the created order was `payer-action`.
- **Authorizing an unapproved order** returned HTTP 422 with error name `ORDER_NOT_APPROVED`.
- **Void** returned HTTP 200.

## 3. Running the spikes

```text
scripts/spikes/run_spikes.sh
uv run --with sd-jwt python scripts/spikes/sdjwt_library_probe.py
```

The first command needs no network after `make setup`. Each line beginning `OK` is a verified
result, and the script exits non-zero on the first failure.

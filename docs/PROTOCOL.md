# PROTOCOL

How Countersign uses AP2, UCP and ACP, grounded in the pinned copies under `spec/vendor/`.
This file is built up over time. This revision covers the AP2 and UCP facts confirmed by reading
the vendored files (including RFC 9901 and the Delegate SD-JWT draft), the gaps those files leave,
and the design decisions Countersign makes to close them. PayPal facts, gate step
codes, the evidence reference encoding and the PayPal field mapping are added by later work and
are listed under [Still to be written](#5-still-to-be-written).

## Conventions

- **Citations.** Every fact cites a vendored file and a section heading. Paths are relative to
  `spec/vendor/`. Pins are in `spec/vendor/SOURCES.md`: AP2 tag `v0.2.0`, UCP tag `v2026-08-25`,
  ACP spec `2026-04-17`, RFC 9901, and the Delegate SD-JWT draft (current `main` and the revision
  contemporary with AP2 v0.2.0).
- **Quoting.** Field names, claim names and strings are quoted exactly as written upstream.
- **Status labels.** Each fact is either _confirmed_ (stated in a vendored file, or checked against
  a worked example in a vendored file) or marked _not specified_ or _ambiguous_ where the vendored
  files do not settle it. Choices made to fill a gap are labelled _Countersign decision_ and are
  never presented as spec. All decisions are in [section 3](#3-design-decisions).
- **Out of scope here.** ACP is used only as the weaker second protocol in attack scenarios and
  is not analysed in this revision.

---

## 1. Confirmed spec facts

### 1.1 Checklist answers at a glance

| Item                            | Answer                                                                                                                                                                                                                                                             | Detail                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- |
| Mandate `vct` strings           | `mandate.checkout.1`, `mandate.checkout.open.1`, `mandate.payment.1`, `mandate.payment.open.1`                                                                                                                                                                     | [1.2.2](#122-mandate-types-and-vct-strings) |
| `checkout_hash`                 | base64url(SHA-256) of the US-ASCII bytes of the `checkout_jwt` string; algorithm is the SD-JWT `_sd_alg`, or `sha-256` if absent                                                                                                                                   | [1.2.4](#124-hashes)                        |
| `transaction_id`                | the same value as `checkout_hash`, not a separate unique id                                                                                                                                                                                                        | [1.2.4](#124-hashes)                        |
| `sd_hash`                       | base64url(SHA-256) of the US-ASCII bytes of the preceding SD-JWT compact serialization including its trailing `~`                                                                                                                                                  | [1.2.4](#124-hashes)                        |
| `cnf`                           | RFC 7800 confirmation claim, shape `{"jwk": {...}}`, required on open mandates, holds the agent public key                                                                                                                                                         | [1.2.5](#125-key-binding-and-the-cnf-claim) |
| Constraint structure            | object with required string `type` plus type-specific fields; ten native types exist (none for expiry or category)                                                                                                                                                 | [1.2.6](#126-constraints)                   |
| Receipt fields                  | Checkout Receipt and Payment Receipt schemas, `reference` is the hash of the closed mandate                                                                                                                                                                        | [1.2.7](#127-receipts)                      |
| Hash for receipt `reference`    | same as `sd_hash`; algorithm is `_sd_alg`, or `sha-256`                                                                                                                                                                                                            | [1.2.4](#124-hashes)                        |
| Native constraint types         | `checkout.allowed_merchants`, `checkout.line_items`, `payment.agent_recurrence`, `payment.allowed_payees`, `payment.allowed_payment_instruments`, `payment.allowed_pisps`, `payment.amount_range`, `payment.budget`, `payment.reference`, `payment.execution_date` | [1.2.6](#126-constraints)                   |
| Chain serialization             | `<SD-JWT>~~<KB-SD-JWT>~<disclosures>~`, exactly one empty component between links                                                                                                                                                                                  | [1.2.3](#123-sd-jwt-structure-and-chains)   |
| `merchant_authorization` format | detached JWS `<header>..<signature>` over JCS bytes of the checkout minus `ap2`; header claims `alg` and `kid`                                                                                                                                                     | [1.3.3](#133-merchant_authorization)        |
| UCP AP2 error codes             | seven codes, listed in [1.3.5](#135-error-codes)                                                                                                                                                                                                                   | [1.3.5](#135-error-codes)                   |
| Payment mandate in UCP          | `payment.instruments[*].credential.token`; format defined by [Decision 8](#decision-8-payment-mandate-credentialtoken-format)                                                                                                                                      | [1.3.4](#134-carrying-the-mandates-in-ucp)  |
| Profile keys format             | top-level `keys[]`, a JWK Set; each entry requires `kid` and `kty`, EC keys also `crv`, `x`, `y`                                                                                                                                                                   | [1.3.2](#132-profile-and-keys)              |
| SD-JWT library choice           | None: built in-house on `joserfc` and `hashlib`, see [ENV.md](ENV.md)                                                                                                                                                                                              | [ENV.md](ENV.md)                            |

### 1.2 AP2 v0.2

#### 1.2.1 Roles, modes and agentic rules

- Five roles: Shopping Agent (SA), Credential Provider (CP), Merchant (M), Merchant Payment
  Processor (MPP), Trusted Surface (TS). One entity may play several or all of them.
  Source: `ap2/docs/specification.md`, "Roles".
- The Trusted Surface "MUST be non-agentic". Merchant, MPP and CP "MAY be agentic or
  non-agentic". The Shopping Agent "is expected to be agentic". Validation or processing for a
  role "MUST happen in deterministic code regardless of whether the role is agentic or not".
  Source: `ap2/docs/specification.md`, "Agentic vs Non-Agentic".
- A role is non-agentic only if communication is handled by deterministic code and "no processing
  done by the role is delegated to an LLM". Same section.
- Two modes: Human Present ("Direct") and Human Not Present ("Autonomous"). Verifiers always
  receive a closed Payment Mandate and a closed Checkout Mandate in either mode.
  Source: `ap2/docs/specification.md`, "Modes".
- In the autonomous mode the user signs open mandates that "MUST include the agent's public key
  as a `cnf` claim", and the `exp` claim is "RECOMMENDED" to be the smallest value that lets the
  agent finish the task. Source: `ap2/docs/specification.md`, "Autonomous (Human Not Present)".
- Anti-reuse: "Shopping Agents MUST NOT present any subsequent open Payment or Checkout Mandates
  without receiving a rejection receipt from the previous one." Same section. The receipts
  involved "MUST be integrity protected from the Shopping Agent's LLM"
  (`ap2/docs/security_and_privacy_considerations.md`, "Double Spend").
- Agents must disclose only the disclosures needed to evaluate the closed mandates
  (`ap2/docs/specification.md`, "Autonomous (Human Not Present)").

#### 1.2.2 Mandate types and `vct` strings

Source: `ap2/docs/checkout_mandate.md`, "Type"; `ap2/docs/payment_mandate.md`, "Type";
`ap2/docs/specification.md`, "Mandate Versioning".

| Mandate                 | `vct`                     |
| ----------------------- | ------------------------- |
| closed Checkout Mandate | `mandate.checkout.1`      |
| open Checkout Mandate   | `mandate.checkout.open.1` |
| closed Payment Mandate  | `mandate.payment.1`       |
| open Payment Mandate    | `mandate.payment.open.1`  |

"Implementations MUST match the exact `vct` string, including the version suffix."
(`ap2/docs/specification.md`, "Mandate Versioning".) The JSON Schemas pin the same values as
`const` (`ap2/schemas/ap2/checkout_mandate.json`, `open_checkout_mandate.json`,
`payment_mandate.json`, `open_payment_mandate.json`).

#### 1.2.3 SD-JWT structure and chains

Mandates:

- Mandates are SD-JWT credentials. "AP2 specifies the use of `SD-JWT`s for securing the Payment
  and Checkout Mandates." (`ap2/docs/specification.md`, "Verifiable Digital Credential Formats
  (VDCs)"). Key binding is used to close a mandate
  (`ap2/docs/agent_authorization.md`, "Mandate Structure").
- Mandate Content claims: `vct` (REQUIRED), `constraints` (OPTIONAL array), `cnf` (REQUIRED if
  the mandate is still open). `ap2/docs/agent_authorization.md`, "Mandates using SD-JWT VCs".
- Processing rules for a chain, in order: (1) verify and process the SD-JWT chain per Delegate
  SD-JWT, (2) check the closed mandate has the open mandate's claims unchanged, (3) evaluate
  every constraint against the closed mandate, where "Any unknown Constraints MUST be treated as
  failing evaluation". Source: `ap2/docs/agent_authorization.md`, "Verification and Processing
  Rules".
- `sd_hash` binds a closed mandate to the open mandate it was presented with
  (`ap2/docs/security_and_privacy_considerations.md`, "Manipulated Checkout";
  `ap2/docs/flows.md`, "Phase 2: Payment (Human Not Present)").
- The `exp` and `nbf` clock skew is not specified anywhere in the vendored files.

Chain format. AP2 names "Delegate SD-JWT" as the normative chain format
(`ap2/docs/agent_authorization.md`, "References"). The pinned draft is
`delegate-sd-jwt/draft-ietf-oauth-delegate-sd-jwt.md`:

- Compact serialization ("Formats > Compact Serialization"):
  - dSD-JWT: `<SD-JWT>~~<KB-JWT>~<Delegated Disclosure 1>~...~<Delegated Disclosure M>~`
  - dSD-JWT+KB: `<SD-JWT>~~<KB-SD-JWT>~<delegate KB-JWT>`
  - longer chain: `<SD-JWT>~~<KB-SD-JWT 1>~~...~~<KB-SD-JWT n>~<delegate KB-JWT>`
  - "The resulting array of components MUST have exactly one empty component between the last
    component of each SD-JWT or KB-SD-JWT and the following KB-SD-JWT." A dSD-JWT is
    distinguished from a dSD-JWT+KB by a trailing `~`.
- A KB-SD-JWT is a key-binding JWT that is itself an SD-JWT ("KB-SD-JWT and KB-SD-JWT+KB"):
  header `typ` is `kb+sd-jwt` (or `kb-sd-jwt+kb`, which requires a `cnf` claim in the delegate
  payload). It adds the claim `delegate_payload`, "An array of JSON Objects", of which exactly one
  must be disclosed when presented. `sd_hash` is OPTIONAL; when absent `issuer_jwt_hash` must be
  present instead. All claims normally in an issuer-signed payload, except `_sd_alg`, move into the
  delegate payload.
- Verification ("Verification"): split into components; validate the first SD-JWT per RFC 9901
  section 7.1; for each KB-SD-JWT validate it as an SD-JWT with the previous component's `cnf` key
  as the issuer key, check exactly one disclosed `delegate_payload` element, check `sd_hash` (or
  `issuer_jwt_hash`) against the preceding component, check the `typ`. For a dSD-JWT (no trailing
  key-binding JWT) the final `typ` "MUST be 'kb+sd-jwt' or 'kb-sd-jwt+kb'". If key binding is
  required and the credential is a plain dSD-JWT, "the Verifier MUST reject the presentation".
- "Without verifying the binding in both directions a malicious Delegate Holder may mis-match
  parts of the chain if the Holder `cnf` is reused" ("Security Considerations > Mandatory
  verification of delegate SD-JWT Chain").
- The draft history records that the `typ` value `kb+sd-jwt+kb` was renamed `kb-sd-jwt+kb`
  ("Document History", -01). AP2 v0.2.0 examples use only `kb+sd-jwt`.

Key binding JWT and hashing (RFC 9901):

- Standard KB-JWT: header `typ` `kb+jwt`, payload `iat`, `aud`, `nonce`, `sd_hash` all REQUIRED
  (`rfc9901/rfc9901.txt`, section 4.3). The AP2 and Delegate KB-SD-JWT uses `kb+sd-jwt` instead.
- `_sd_alg` defaults to `sha-256`, and implementations MUST support `sha-256` (section 4.1.1).
- A disclosure digest is "computed over the US-ASCII bytes of the base64url-encoded value that is
  the Disclosure", not over the decoded bytes, and the digest bytes are then base64url encoded
  (section 4.2.3).
- `sd_hash` "MUST be computed over the US-ASCII bytes of the encoded SD-JWT, i.e., the
  Issuer-signed JWT, a tilde character, and zero or more Disclosures selected for presentation to
  the Verifier, each followed by a tilde character", with the same hash algorithm as the
  disclosures (section 4.3.1).

Checks against the vendored worked examples. The "Encoded Token" blocks in
`ap2/docs/checkout_mandate.md` and `ap2/docs/payment_mandate.md` were decoded and checked with an
ad hoc script (not committed). Results:

- The chained token equals the open token, then `~`, then the closed token, and contains `~~`. The
  open token ends with `~`.
- The closed Checkout Mandate key-binding JWT verifies with ES256 against the `cnf` JWK in the open
  Checkout Mandate. The same holds for the Payment Mandate pair.
- The closed `sd_hash` equals base64url(SHA-256(US-ASCII(open token))), where the open token is
  taken including its trailing `~`. Holds for both mandates.
- `checkout_hash` equals base64url(SHA-256(US-ASCII(checkout_jwt string))), where `checkout_jwt` is
  the compact JWS string stored in the `checkout_jwt` disclosure. The closed Payment Mandate
  `transaction_id` is the same value.
- The open Payment Mandate `payment.reference` `conditional_transaction_id` equals the same hash
  taken over the open Checkout Mandate token.
- The closed tokens end with `~`, so by the draft's definition they are dSD-JWTs without a trailing
  delegate key-binding JWT. The transaction binding is carried in the `aud` and `nonce` of the final
  `kb+sd-jwt` element.
- The example `checkout_jwt` has header `{"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"}`
  and a payload serialized with spaces after separators, so it is not JCS output, and it is not a
  UCP checkout object.
- In `ap2/docs/checkout_mandate.md` the decoded view of the closed example shows an `_sd` digest
  that differs in two characters from the digest in the encoded token. The encoded token is
  treated as authoritative and the decoded view as a documentation typo.

#### 1.2.4 Hashes

| Hash                                      | Definition                                                                                                                                                                                                            | Source                                                                                                              |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `checkout_hash`                           | "base64url-encoded hash of the value of `checkout_jwt`. The algorithm used MUST be the same as the SD-JWT, as defined by the `_sd_alg` claim in the base payload, or `sha-256` if not present."                       | `ap2/docs/checkout_mandate.md`, "Mandate Schema"; `ap2/schemas/ap2/checkout_mandate.json`, property `checkout_hash` |
| `transaction_id` (closed Payment Mandate) | "base64url-encoded hash of the checkout_jwt field value, uniquely identifying the checkout associated with this. The hash algorithm used MUST be the same as the sd_hash field for this sd-jwt, or sha256 if absent." | `ap2/schemas/ap2/payment_mandate.json`, property `transaction_id`                                                   |
| `sd_hash`                                 | over the preceding SD-JWT string including its trailing `~`, US-ASCII bytes                                                                                                                                           | `rfc9901/rfc9901.txt`, section 4.3.1                                                                                |
| Receipt `reference`                       | "The hash of the closed Mandate that this receipt is binding to", "calculated in the same manner as the `sd_hash` would be"                                                                                           | `ap2/schemas/ap2/checkout_receipt.json`, `payment_receipt.json`; `ap2/docs/specification.md`, "Dispute"             |
| `payment.reference` constraint            | `conditional_transaction_id` is the "Digest of the associated Open Checkout Mandate"; algorithm is `_sd_alg` of the SD-JWT the constraint is in, or `sha-256`                                                         | `ap2/schemas/ap2/open_payment_mandate.json`, `payment_reference`; `ap2/docs/payment_mandate.md`, "Reference"        |

Confirmed consequences:

- `transaction_id` and `checkout_hash` are computed from the same input, so for one checkout they
  are the same string ([1.2.3](#123-sd-jwt-structure-and-chains), example checks). The security
  text says: "The `checkout_hash` embedded in the `transaction_id` securely links the payment to
  the associated Checkout Mandate" (`ap2/docs/security_and_privacy_considerations.md`,
  "Manipulated Payment").
- Hash input. For `checkout_hash` and `transaction_id` the input is the US-ASCII bytes of the
  compact JWS string held in `checkout_jwt`. For `sd_hash`, receipt `reference` and the
  `payment.reference` digest the input is the US-ASCII bytes of the full compact serialization of
  the mandate presentation, including trailing `~`. Disclosure digests use the US-ASCII bytes of
  the base64url disclosure string. Receipt `reference` for a chain is "a hash over the final SD-JWT
  in the chain" (`ap2/docs/agent_authorization.md`, "Action Authorization"). The exact string a
  receipt `reference` covers when a chain is presented (the whole chain, or only the final
  element) is stated only by that sentence. See [Decision 7](#decision-7-checkout_jwt-and-merchant_authorization).
- AP2 hashes are plain hashes with no domain-separation prefix. Domain separation applies only to
  hashes Countersign defines itself (decision log, evidence reference).
- The Checkout JWT must be signed with a non-deterministic scheme: "MUST be signed using a digital
  signature scheme (e.g., ECDSA) and not a deterministic signature (e.g., Ed25519)"
  (`ap2/docs/specification.md`, "Payment Mandate"). The security chapter instead states an
  entropy rule that any algorithm satisfies given enough payload entropy
  (`ap2/docs/security_and_privacy_considerations.md`, "Rainbow Table Attacks"), and the UCP
  extension notes this inconsistency and links upstream issue 268
  (`ucp/docs/specification/payment/extensions/ap2-mandates.md`, "Cryptographic Requirements").
  Countersign uses ES256, which satisfies both readings.

#### 1.2.5 Key binding and the `cnf` claim

- `cnf` is the "Confirmation claim as defined in RFC 7800 section 3.1. Used for key binding."
  (`ap2/schemas/ap2/open_checkout_mandate.json`, `open_payment_mandate.json`, property `cnf`).
- Shape in every example: `"cnf": {"jwk": {"crv": "P-256", "kty": "EC", "x": "...", "y": "..."}}`
  (`ap2/docs/checkout_mandate.md`, open example). The JWK schema allows `alg`, `crv`, `key_ops`,
  `kid`, `kty`, `use`, `x`, `x5c`, `x5t`, `x5t#S256`, `x5u`, `y`, with `kty` required
  (`ap2/schemas/ap2/types/jwk.json`).
- `cnf` is required in both open mandate schemas (`required: ["vct","constraints","cnf"]`).
- A closed mandate is produced by the agent signing a key-binding JWT with the key in the open
  mandate's `cnf` (`ap2/docs/agent_authorization.md`, "Mandate Structure").

#### 1.2.6 Constraints

Structure: every constraint is an object with a required string `type`, "A unique String
identifying this constraint", plus properties defined by that type
(`ap2/docs/agent_authorization.md`, "Mandates using SD-JWT VCs"). New constraints would need "A
uniquely defined `type`", "A Schema, including which fields are selectively disclosable" and "The
evaluation algorithm" (`ap2/docs/specification.md`, "Mandate Constraints"). Countersign defines
none ([Decision 4](#decision-4-no-custom-constraint-types)).

Native types in v0.2. Sources: `ap2/docs/checkout_mandate.md`, "Constraints";
`ap2/docs/payment_mandate.md`, "Payment Mandate Constraints"; schemas in
`ap2/schemas/ap2/open_checkout_mandate.json` and `open_payment_mandate.json`.

| `type`                                | Mandate       | Fields                                                                                                                   | Evaluation (summary)                                                                                                                                                                                  |
| ------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `checkout.allowed_merchants`          | open checkout | `allowed` (array of merchant objects `id`, `name`, `website`, selectively disclosable)                                   | merchant must be among the revealed `allowed`; if none revealed, invalid                                                                                                                              |
| `checkout.line_items`                 | open checkout | `items[]` each `id`, `acceptable_items[]` (`id`, `title`), `quantity`                                                    | each `items` entry matched by quantity, no entry or item used twice; maximal-flow formulation given. "This evaluation does not support splitting the open Checkout Mandate across multiple Checkouts" |
| `payment.allowed_payees`              | open payment  | `allowed` (merchant objects)                                                                                             | `payee` of the Payment Mandate must be in `allowed`                                                                                                                                                   |
| `payment.allowed_payment_instruments` | open payment  | `allowed` (`id`, `type`, `description`)                                                                                  | `payment_instrument` must be in `allowed`                                                                                                                                                             |
| `payment.allowed_pisps`               | open payment  | `allowed` (`legal_name`, `brand_name`, `domain_name`)                                                                    | facilitating PISP must be in `allowed`                                                                                                                                                                |
| `payment.amount_range`                | open payment  | `currency`, `max` (integer minor units), optional `min` (integer minor units)                                            | `payment_amount` within `min` and `max`, currency must match                                                                                                                                          |
| `payment.budget`                      | open payment  | `max` (JSON `number`), `currency`                                                                                        | requested amount plus the sum of previously closed Payment Mandates must be `<= max`; amount added after approval. Described as "To be used with the Agent Recurrence constraint"                     |
| `payment.agent_recurrence`            | open payment  | `frequency` (`ON_DEMAND`, `DAILY`, `WEEKLY`, `BIWEEKLY`, `MONTHLY`, `QUARTERLY`, `ANNUALLY`), optional `max_occurrences` | true if sufficiently separated in time from the previous presentation and `max_occurrences` not exceeded                                                                                              |
| `payment.reference`                   | open payment  | `conditional_transaction_id`                                                                                             | the Checkout Mandate must contain an open Checkout Mandate with a matching hash in its delegate chain                                                                                                 |
| `payment.execution_date`              | open payment  | optional `not_before`, `not_after`                                                                                       | `execution_date` within the window                                                                                                                                                                    |

Other confirmed constraint facts:

- There is no native expiry constraint. Expiry is the `exp` claim on the mandate. The nearest
  constraint, `payment.execution_date`, restricts the payment execution date.
- There is no native category constraint.
- The open Checkout Mandate schema requires a `checkout.line_items` constraint (`contains`), and
  the open Payment Mandate schema requires a `payment.reference` constraint (`contains`).
- Both schemas list the allowed constraint types as a closed `anyOf` or `oneOf`.
- Unknown constraints map to the AP2 error `unresolved_constraint`
  (`ap2/docs/agent_authorization.md`, "Errors").

#### 1.2.7 Receipts

Checkout Receipt (`ap2/schemas/ap2/checkout_receipt.json`, doc in `ap2/docs/checkout_mandate.md`
"Checkout Receipt"). Required: `status`, `iss`, `iat`, `reference`.

| Field                        | Meaning                                                                    |
| ---------------------------- | -------------------------------------------------------------------------- |
| `status`                     | `Success` or `Error` (`ap2/schemas/ap2/types/receipt_status.json`)         |
| `iss`                        | issuer of the receipt                                                      |
| `iat`                        | creation time, Unix epoch integer                                          |
| `reference`                  | hash of the closed Mandate the receipt binds to                            |
| `error`, `error_description` | present if and only if `status` is `Error` (both required in that variant) |
| `order_id`                   | present if and only if `status` is `Success` (required in that variant)    |

Payment Receipt (`ap2/schemas/ap2/payment_receipt.json`). Required: `status`, `iss`, `iat`,
`reference`, `payment_id`. Success additionally requires `psp_confirmation_id` and
`network_confirmation_id`. Error requires `error` and `error_description`.

- The Merchant "MUST return a Checkout Receipt JWT containing the appropriate error message" on any
  verification failure (`ap2/docs/specification.md`, "Merchant"); the MPP returns a "signed
  Payment Receipt" (`ap2/docs/specification.md`, "Payment Mandate").
- A generic Mandate Receipt in `ap2/docs/agent_authorization.md`, "Action Authorization", uses
  `result` with values `"success"` and `"error"` instead of `status` with `Success` and `Error`.
  The mandate-specific schemas use `status`.
- AP2 generic errors for action authorization: `invalid_credential` (terminal),
  `unresolved_constraint`, `invalid_mandate` (terminal), `mandates_not_supported`
  (`ap2/docs/agent_authorization.md`, "Errors").

#### 1.2.8 Verification and dispute steps

Merchant, per `ap2/docs/specification.md`, "Merchant": process the Checkout Mandate per the
verification rules, verify the hash of the Checkout JWT sent for approval matches `checkout_hash`,
and if open mandates are included verify the closed checkout conforms to every constraint.

Credential Provider and Network: verify the Payment Mandate per the rules, and if open mandates
are included verify the closed Payment Mandate matches all constraints (same file, "Credential
Provider and Network").

Merchant Payment Processor: "MUST verify the Payment Credential is appropriately scoped to the
Checkout. One way this can be done is by providing the Closed Payment Mandate inside the Payment
Credential." (same file, "Merchant Payment Processor").

Dispute verification, all MUST, in order (`ap2/docs/specification.md`, "Dispute"):

1. Verify the Checkout Mandate under the Merchant verification rules.
2. Independently compute the hash of the `checkout_jwt` from the included `checkout_jwt`.
3. The Checkout Receipt `reference` must match the hash of the closed Checkout Mandate, computed
   like `sd_hash`.
4. Verify the Payment Mandate under the MPP rule, using the `checkout_hash` from the Checkout
   Mandate.
5. The Payment Receipt `reference` must match the hash of the closed Payment Mandate, computed
   like `sd_hash`.

Retrieval note: automated retrieval of the Checkout Mandate "would be done by using the Payment
Mandate `transaction_id` as the key to request it", but this is outside the scope of AP2 v0.2
(`ap2/docs/specification.md`, "Dispute Evidence").

#### 1.2.9 Who can be trusted to sign for the user

Two delegation models are defined, "User Credential" and "Trusted Agent Provider"
(`ap2/docs/agent_authorization.md`, "Mandate Delegation"). A directly trusted user key such as a
passkey or hardware-attested key is mentioned only as a possible future model in a note in the
same section. In the Trusted Agent Provider model "The Agent Provider uses a securely stored
signing key to create the Mandate" and "MUST ensure that the Agent is not able to access the Agent
Provider signing key, or use it without the Trusted Surface". The worked example has the issuer
JWT carry `iss` (the provider URL) and a header `kid` (`ap2/docs/agent_authorization.md`, "Trusted
Agent Provider").

### 1.3 UCP (release v2026-08-25)

#### 1.3.1 Capability and negotiation

- Capability name `dev.ucp.common.payment.ap2_mandate`, with `"extends": "dev.ucp.shopping.checkout"`,
  advertised in the business profile under `ucp.capabilities`. Schema file
  `ucp/source/schemas/common/payment_ap2_mandate.json` (`"name": "dev.ucp.common.payment.ap2_mandate"`).
  Source: `ucp/docs/specification/payment/extensions/ap2-mandates.md`, "Business Profile
  Advertisement".
- The extension is active only if it appears in the capability intersection of business and
  platform. When active the business "MUST include `ap2.merchant_authorization` in all checkout
  responses" and "MUST NOT accept a `complete_checkout` request that lacks
  `ap2.checkout_mandate`". Source: same file, "Activation and Session Locking".
- Session lock: "Once this extension is negotiated in the capability intersection, the session is
  Security Locked. Neither party may revert to a standard (unprotected) checkout flow." Any
  attempt to complete without mandates "MUST result in a session failure". Sources: same file,
  "Overview" and "The Mandate Flow". The lock is defined for the session only. Nothing in the
  vendored UCP files extends it to the customer or agent across sessions or across protocols.
- Platform identity on requests: every REST request "MUST include the `UCP-Agent` header"
  carrying the platform profile URI as a Structured Field dictionary, for example
  `profile="https://platform.example/profile"` (`ucp/docs/specification/shopping/checkout/rest.md`,
  "HTTP Headers"). If the platform uses the trusted platform provider model it "MUST provide at
  least one key in the top-level `keys` array in their profile"
  (`ap2-mandates.md`, "Platform Profile Advertisement").
- Signing keys: platform provider flow takes the key from the platform profile `keys`; user
  credential flow uses a key bound to the digital payment credential
  (`ap2-mandates.md`, "Signing Key Requirements").
- Trusted platform provider option: "A trusted platform provider acts on the user's behalf to
  generate the mandate credentials. The platform provider MUST ensure that mandates are not created
  without explicit user consent from trusted, deterministic channels." The platform signs with a
  server-side key and "the business trusts the platform's signature implies user consent"
  (`ap2-mandates.md`, "Step 2: User Consent & Mandate Generation", "Option 1").

#### 1.3.2 Profile and keys

- Profile location: business profile at `/.well-known/ucp`
  (`ucp/docs/specification/overview/index.md`, "Profile Structure").
- Required members: `ucp` at top level; inside `ucp`: `version`, `services`, `payment_handlers`
  (the registries must be present even when empty). `capabilities` is optional. Same section.
  Version format is `YYYY-MM-DD` (`ucp/source/schemas/ucp.json`, `$defs.version`). In the docs the
  version is a template variable (`{{ ucp_version }}`), so the literal value for this release is
  not resolved in the vendored files.
- `keys[]` is the "canonical UCP profile field for publishing signing keys, as a JWK Set per RFC
  7517" (`ucp/source/schemas/profile.json`, `$defs.base.properties.keys`). It is a top-level
  member beside `ucp`, not nested inside it.
- Each key (`ucp/source/schemas/profile.json`, `$defs.jwk_public_key`): required `kid`, `kty`;
  optional `crv`, `x`, `y`, `alg`, `use`. EC keys require `crv`, `x`, `y`. OKP keys require `crv`,
  `x`. `alg` must match the curve when present (`P-256` with `ES256`, `P-384` with `ES384`,
  `Ed25519` with `EdDSA`). Private members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) are
  forbidden. `kid` must be the RFC 7638 thumbprint only for keys also used for Web Bot Auth.
  Additional public members are allowed.
- `ES256` verification is the universal baseline (`ucp/docs/specification/signatures.md`,
  "Signature Algorithms").
- Removal from `keys[]` is the only effective revocation (`overview/index.md`, "Profile
  Structure").
- Hosting: HTTPS, no redirects, `Cache-Control` with `public` and `max-age` of at least 60 seconds,
  no `private`, `no-store` or `no-cache` (`overview/index.md`, "Profile Requirements > Hosting").
- `vp_formats_supported` appears in the AP2 capability entry under `config`, for example
  `"config": {"vp_formats_supported": {"dc+sd-jwt": { }}}`
  (`ap2-mandates.md`, "Business Profile Advertisement"). It is not a top-level profile member.
  The vendored schemas contain no definition for it, so its structure comes only from that
  example.
- Services use `transport` and `endpoint`, for example `"transport": "rest"` with
  `"endpoint": "https://business.example.com/ucp/v1"` (`overview/index.md`, "Business Profile").

#### 1.3.3 `merchant_authorization`

Source: `ap2-mandates.md`, "Business Authorization"; schema `ucp/source/schemas/common/payment_ap2_mandate.json`,
`$defs.merchant_authorization`.

- Location: `ap2.merchant_authorization` in the checkout response body.
- Format: JWS with detached content (RFC 7515 Appendix F), `<header>..<signature>`. Schema pattern
  `^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$`.
- Protected header claims: `alg` (required, ES256, ES384 or ES512) and `kid` (required, "Key ID
  referencing the business's `keys`"). The spec's pseudocode builds the header as exactly
  `{"alg": alg, "kid": kid}`.
- Signed payload: the checkout "without `ap2` field", canonicalized with JCS (RFC 8785).
- Signing input: `base64url(header) + "." + base64url(JCS bytes)`. The signature covers header and
  payload, which prevents algorithm substitution.
- Verification by the platform before presenting the checkout: decode header, require `alg` in the
  accepted set, rebuild the payload, look up `kid` in the business `keys`, verify.
- Coverage is the complete checkout JSON, not a projection: "removing any member covered by
  `merchant_authorization` changes the JCS payload and invalidates the signature", and this
  includes `ucp` members present in the checkout. Only `ap2` is excluded ("Canonicalization").
- JCS requires JSON integers within +/-(2^53 - 1), and every UCP integer field is capped there
  (`ucp/docs/specification/overview/index.md`, "Integer range and ingestion").

#### 1.3.4 Carrying the mandates in UCP

Source: `ap2-mandates.md`, "Mandate Structure", "Step 3: Submission", and the schema file.

| Mandate          | UCP placement                                                                                                                                                                                                                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Checkout Mandate | `ap2.checkout_mandate`, a string matching `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+(~[A-Za-z0-9_-]+)*$`. Request schema: omitted on create and update, required on complete. This pattern does not match valid mandates, see [Decision 9](#decision-9-handling-the-checkout-mandate-pattern) |
| Payment Mandate  | `payment.instruments[*].credential.token` ("Contains the payment mandate (composite token)")                                                                                                                                                                                                        |

- Mandates are "SD-JWT credentials with Key Binding (`+kb`)".
- "The checkout mandate MUST contain the full checkout response including the
  `ap2.merchant_authorization` field", creating a nested binding in which the platform signature
  covers the business signature.
- The credential internals "(claims, selective disclosure, key binding) is defined by the AP2
  Protocol Specification".
- UCP defines `token` for `token_credential` only as a string, with `type` an open string chosen by
  the payment handler (`ucp/source/schemas/common/types/token_credential.json`), while the prose
  calls the Payment Mandate token a "composite token" and "composite object". The composite format
  is not specified.
- Business verification on complete, in order: reject with `mandate_required` if
  `ap2.checkout_mandate` is missing; verify the SD-JWT signature, key binding and expiration per
  AP2; extract the embedded checkout; verify the embedded `ap2.merchant_authorization` is the
  business's own valid signature; confirm the embedded terms "match the current session state (id,
  totals, line items)". PSP verification covers the payment mandate "including signature
  validation, expiration, and correlation with the checkout".

#### 1.3.5 Error codes

Source: `ap2-mandates.md`, "Error Codes"; `ucp/source/schemas/common/payment_ap2_mandate.json`,
`$defs.error_code` (an enum of exactly these seven).

| Code                             | Meaning                                                |
| -------------------------------- | ------------------------------------------------------ |
| `mandate_required`               | AP2 negotiated, request lacks `ap2.checkout_mandate`   |
| `agent_missing_key`              | platform profile lacks a valid `keys` entry            |
| `mandate_invalid_signature`      | mandate signature cannot be verified                   |
| `mandate_expired`                | mandate `exp` has passed                               |
| `mandate_scope_mismatch`         | mandate is bound to a different checkout               |
| `merchant_authorization_invalid` | business authorization signature could not be verified |
| `merchant_authorization_missing` | checkout response omits `ap2.merchant_authorization`   |

How these codes travel is not specified. UCP error messages are objects with required `type`,
`code`, `content`, `severity` (`ucp/source/schemas/common/types/message_error.json`), where
`code` may be any string ("freeform codes are permitted",
`ucp/source/schemas/common/types/error_code.json`) and `severity` is one of `recoverable`,
`requires_buyer_input`, `requires_buyer_review`, `unrecoverable`. REST business outcomes are
HTTP 200 with a `messages` array, and protocol errors (401, 403, 409, 429, 500, 503) carry a body
with `code` and `content` (`ucp/docs/specification/shopping/checkout/rest.md`, "Error
Responses"). The vendored files do not say which of these the AP2 codes use.

#### 1.3.6 REST checkout binding and state

Source: `ucp/docs/specification/shopping/checkout/rest.md`, "Operations"; `index.md`, "Checkout
Status Lifecycle".

| Operation | Method and path                         |
| --------- | --------------------------------------- |
| Create    | `POST /checkout-sessions`               |
| Get       | `GET /checkout-sessions/{id}`           |
| Update    | `PUT /checkout-sessions/{id}`           |
| Complete  | `POST /checkout-sessions/{id}/complete` |
| Cancel    | `POST /checkout-sessions/{id}/cancel`   |

- Paths are relative to the `endpoint` of the REST service in the profile.
- Checkout `status` values: `incomplete`, `requires_escalation`, `ready_for_complete`,
  `complete_in_progress`, `completed`, `canceled`
  (`ucp/source/schemas/shopping/checkout.json`). Required checkout members: `ucp`, `id`,
  `line_items`, `status`, `currency`, `totals`, `links`.
- Idempotency: state-changing operations "SHOULD support idempotency" with an `Idempotency-Key`
  header; the server stores the key at least 24 hours, returns the cached result for a duplicate
  with a matching body, and returns `409 Conflict` when the key is reused with a different body.
  Body matching is by SHA-256 of the raw body bytes (`rest.md`, "HTTP Headers";
  `ucp/docs/specification/signatures.md`, "Replay Protection"). On idempotency storage failure
  the spec says fail closed with 503.
- Money and quantities: amounts are JSON integers in ISO 4217 minor units, minimum 0
  (`ucp/source/schemas/common/types/amount.json`). `totals` must contain exactly one `subtotal` and
  exactly one `total` entry (`ucp/source/schemas/common/types/totals.json`). Line item required
  members: `id`, `item`, `quantity`, `totals`; item required members: `id`, `title`, `price`
  (`ucp/source/schemas/shopping/types/line_item.json`, `item.json`). `quantity` is an integer step
  count with minimum 1. Non-`each` items carry a `quantity_unit` with a `scale`, so a quantity is
  not always a whole-item count (`ucp/docs/specification/overview/index.md`, "Quantities and
  units"). UCP "does not put floating-point numbers on the wire" and requires exact arithmetic.

### 1.4 Gaps in the vendored files and how each is closed

| #   | Gap                                                                                                                                                                                                                                                                                                                                                                                                                                               | Status                                                                                                                                                                                                                                               |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `checkout_jwt` versus `merchant_authorization`. AP2 requires "a merchant-signed JWT containing the Checkout"; UCP defines a detached JWS. No vendored file states that they are the same object. The AP2 example `checkout_jwt` uses `typ` `JWT`, a non-JCS payload and a non-UCP payload shape. The prose in `ucp/docs/documentation/ucp-and-ap2.md` calls the business signature "a detached JWT signing the checkout state" under stale names. | Not resolved by the files. Closed by [Decision 7](#decision-7-checkout_jwt-and-merchant_authorization), marked as a Countersign interpretation                                                                                                       |
| 2   | Hash input encoding.                                                                                                                                                                                                                                                                                                                                                                                                                              | Resolved by RFC 9901 sections 4.2.3 and 4.3.1 and confirmed against the AP2 examples ([1.2.3](#123-sd-jwt-structure-and-chains), [1.2.4](#124-hashes))                                                                                               |
| 3   | Chain format and processing details.                                                                                                                                                                                                                                                                                                                                                                                                              | Resolved by the Delegate SD-JWT draft ([1.2.3](#123-sd-jwt-structure-and-chains)). The `~~` in the AP2 chained example is required by the draft. The UCP pattern is the outlier, see [Decision 9](#decision-9-handling-the-checkout-mandate-pattern) |
| 4   | Receipt field naming (`status` with `Success` and `Error` in schemas, `result` with `success` and `error` in the generic text). Receipt signing format and header (`typ`, `alg`, `kid`) are not specified beyond "signed JWT". How the Checkout Receipt travels back in a UCP response is not specified.                                                                                                                                          | Open. Follow the mandate schemas (`status`). Receipt transport is fixed when the merchant role is implemented                                                                                                                                        |
| 5   | Payment Mandate token format inside `payment.instruments[*].credential.token`.                                                                                                                                                                                                                                                                                                                                                                    | Closed by [Decision 8](#decision-8-payment-mandate-credentialtoken-format)                                                                                                                                                                           |
| 6   | Error transport: HTTP status and message envelope for the seven AP2 error codes.                                                                                                                                                                                                                                                                                                                                                                  | Open. Provisional rule in [Decision 10](#decision-10-provisional-rules-for-open-gaps)                                                                                                                                                                |
| 7   | Clock skew for `exp` and `nbf`.                                                                                                                                                                                                                                                                                                                                                                                                                   | Open. Provisional rule in [Decision 10](#decision-10-provisional-rules-for-open-gaps)                                                                                                                                                                |
| 8   | Constraint number formats: `payment.amount_range` fields are integers in minor units, but the prose example shows `"max": 100.50`. `payment.budget.max` is a JSON `number` with no stated unit and a prose example of `1000.00`.                                                                                                                                                                                                                  | Closed by [Decision 2](#decision-2-strict-single-use-and-add-only-budget)                                                                                                                                                                            |
| 9   | Which fields of each native constraint are selectively disclosed in practice.                                                                                                                                                                                                                                                                                                                                                                     | Open. Fixed when the mandate issuer is implemented, following the `x-selectively-disclosable-*` markers in the vendored schemas                                                                                                                      |
| 10  | `ucp/docs/documentation/ucp-and-ap2.md` uses older names (`checkoutSignature`, `CheckoutMandate`, `PaymentMandate`) that differ from the extension specification.                                                                                                                                                                                                                                                                                 | Closed. The extension specification and its schema are authoritative                                                                                                                                                                                 |
| 11  | The UCP version string is a template variable in the docs.                                                                                                                                                                                                                                                                                                                                                                                        | Open. The release tag is `v2026-08-25`; the literal `ucp.version` value is confirmed when the profile endpoint is built                                                                                                                              |
| 12  | Principal identity. Neither AP2 nor UCP defines a customer id. UCP identifies the platform by profile URI and `keys[]`; AP2 identifies the agent by the `cnf` key and the user by the delegating credential or provider key.                                                                                                                                                                                                                      | Open. Defined in the architecture document (principal lock)                                                                                                                                                                                          |
| 13  | Repeat use of one open mandate. `checkout.line_items` "does not support splitting the open Checkout Mandate across multiple Checkouts", but `payment.budget` and `payment.agent_recurrence` assume several closed Payment Mandates, each of which `payment.reference` must tie to an open Checkout Mandate in its chain.                                                                                                                          | Closed by the strict reading in [Decision 2](#decision-2-strict-single-use-and-add-only-budget); repeat use is future work                                                                                                                           |

---

## 2. Deviations from the working design

Places where the vendored specifications, or behavior observed in the PayPal sandbox, contradict or
refine an assumption in the working design used to plan this project, with the decision that
resolves each.

| #   | Working design assumption                                                            | What the spec says                                                                               | Resolution                                                                                                                 |
| --- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| D1  | The Payment Mandate `transaction_id` is a unique id whose single use can be enforced | `transaction_id` is the hash of `checkout_jwt` and equals `checkout_hash` ([1.2.4](#124-hashes)) | [Decision 1](#decision-1-single-use-keys)                                                                                  |
| D2  | AP2 natively defines amount, merchant and expiry constraints                         | Ten native types; expiry is the `exp` claim, not a constraint ([1.2.6](#126-constraints))        | [Decision 4](#decision-4-no-custom-constraint-types)                                                                       |
| D3  | A cumulative budget constraint is entirely new                                       | `payment.budget` with `payment.agent_recurrence` exists, with verifier-side state                | [Decision 2](#decision-2-strict-single-use-and-add-only-budget)                                                            |
| D4  | Open mandates express "headphones under $80" with an amount and a category           | The open Checkout Mandate must contain `checkout.line_items`; no native category constraint      | [Decision 3](#decision-3-line-items-in-the-mandate-categories-in-merchant-policy)                                          |
| D5  | Custom constraint types can be added and validated                                   | Schemas are closed; unknown constraints fail evaluation                                          | [Decision 4](#decision-4-no-custom-constraint-types)                                                                       |
| D6  | A device-bound customer key registered with Countersign signs the mandates           | Two trust models are defined; a directly trusted user key is only a possible future model        | [Decision 5](#decision-5-trusted-platform-provider-with-a-device-consent-signature)                                        |
| D7  | The Payment Mandate travels in `payment.instruments[*].credential.token`             | Confirmed; the token format is not specified                                                     | [Decision 8](#decision-8-payment-mandate-credentialtoken-format)                                                           |
| D8  | `vp_formats_supported` is a profile-level key next to `keys[]`                       | It sits under `config` in the AP2 capability entry                                               | [Decision 6](#decision-6-vp_formats_supported-placement)                                                                   |
| D9  | The UCP Security Lock may be strengthened to the principal                           | The lock is per session only                                                                     | No contradiction; the principal lock is an addition (architecture document)                                                |
| D10 | Domain-separated hash helpers are used for every hash                                | AP2 hashes are plain hashes ([1.2.4](#124-hashes))                                               | Domain separation only for Countersign-internal hashes. AP2 hashes use the spec algorithm with no prefix                   |
| D11 | Amounts are integer minor units everywhere                                           | True for UCP and most AP2 fields; `payment.budget.max` is a JSON `number`                        | [Decision 2](#decision-2-strict-single-use-and-add-only-budget). Non-`each` quantities need `quantity_unit.scale` handling |
| D12 | Receipts use one field naming                                                        | Schemas and generic text differ ([1.2.7](#127-receipts))                                         | Follow the mandate schemas (`status`)                                                                                      |
| D13 | An order can be changed at PayPal after authorization (attack `order_changed_after_authorize`) | PayPal rejects every tried change after authorization with 422 `ORDER_ALREADY_COMPLETED`; changes are accepted while the order is `APPROVED` ([4.3](#43-patch)) | The attack is renamed `order_changed_after_approval`. The mutation window is between payer approval and authorization; [Decision 11](#decision-11-pre-authorize-check) |

Facts confirmed with no deviation: the five roles and the non-agentic Trusted Surface rule, the
exact `vct` strings, `cnf` as an RFC 7800 claim, JCS (RFC 8785) for `merchant_authorization`, the
detached JWS format with `alg` and `kid`, the seven UCP AP2 error codes, anti-reuse via rejection
receipts, the five dispute verification steps, `mandate_required` on a missing checkout mandate,
UCP integer minor-unit amounts, and the MPP rule that the credential must be scoped to the
checkout.

---

## 3. Design decisions

Each decision names the finding it resolves. These are Countersign decisions: where they interpret
a spec, the interpretation is stated and must be revisited if upstream clarifies.

### Decision 1: Single-use keys

Resolves: D1; ambiguity of `transaction_id` (section [1.2.4](#124-hashes)).

`transaction_id` equals `checkout_hash`, so it cannot serve as an independent payment identifier.
Single use is a Countersign rule enforced on these keys, across every protocol:

1. **Checkout hash.** At most one authorization may ever be started for a given `checkout_hash`.
   The checkout id is also unique to one authorization. A retry after a rejection is a new checkout
   with a new checkout hash. The earlier hash stays consumed.
2. **Mandate nonce.** The `nonce` of each closed mandate key-binding JWT is accepted once, scoped
   to the agent key thumbprint and the audience (`merchant` or `credential-provider`).
3. **One purchase per open mandate.** An open mandate backs exactly one successful purchase
   ([Decision 2](#decision-2-strict-single-use-and-add-only-budget)). While a presentation is in
   flight, no second closed mandate from the same open mandate (identified by the digest used in
   `sd_hash`) is accepted. This is the AP2 rule that "Shopping Agents MUST NOT present any
   subsequent open ... Mandates without receiving a rejection receipt"
   ([1.2.1](#121-roles-modes-and-agentic-rules)).
4. **States of an open mandate.** `unused`, `in_flight` (a presentation is being verified, or a
   PayPal authorization exists and has not been captured or voided), `consumed` (a capture
   succeeded) and `revoked` or `expired`. Only `consumed` is permanent.

The keys are enforced with database uniqueness constraints and row locks, not with in-memory
state.

### Decision 2: Strict single use and add-only budget

Resolves: D3, D11; gap 8 and gap 13 ([1.4](#14-gaps-in-the-vendored-files-and-how-each-is-closed)).

**One open mandate backs exactly one successful purchase.** This is the strict reading of AP2: the
agent must not present a subsequent open mandate without a rejection receipt for the previous one
([1.2.1](#121-roles-modes-and-agentic-rules)), and `checkout.line_items` "does not support
splitting the open Checkout Mandate across multiple Checkouts" ([1.2.6](#126-constraints)).

- **Retry after rejection.** If a checkout is rejected before any PayPal object exists, or its
  PayPal authorization is voided before capture (a gate failure, an expired authorization, or any
  fail-closed outcome), Countersign issues a rejection receipt. The open mandate returns to
  `unused` and the agent may retry under it with a new checkout. The rejection receipt must reach
  the agent integrity-protected ([1.2.1](#121-roles-modes-and-agentic-rules)).
- **After capture.** A successful capture consumes the open mandate permanently. A later refund
  does not reopen it.
- **Native constraints used.** Open Payment Mandates issued by Countersign carry
  `payment.amount_range` (the ceiling), `payment.allowed_payees`, `payment.reference`, and
  `payment.budget` with `payment.agent_recurrence` set to `ON_DEMAND` with `max_occurrences` of `1`.
  This is a Countersign way to express "exactly one purchase" with native constraints only, so a
  standard verifier also enforces it. It is a proposal that can be dropped if the single-use rule
  alone is preferred.
- **Verifier policy for foreign mandates.** `payment.agent_recurrence` is accepted only with
  `max_occurrences` of `1`. Any other recurrence fails as `unresolved_constraint`, because
  Countersign does not implement repeat use (see Future work). `payment.budget` is evaluated as
  below.
- **Budget unit (Countersign interpretation).** `payment.budget.max` is interpreted as an integer
  count of minor units of the constraint `currency`. A value that is not a JSON integer (a
  fraction, an exponent form, or a value outside +/-(2^53 - 1)) makes the mandate invalid. The spec
  types `max` as a `number` without a unit, so this is our reading, chosen to match
  `payment.amount_range` and `payment_amount`, which are integer minor units. A budget currency
  that differs from the payment currency fails evaluation.
- **Budget accounting is add-only, as the spec says.** The requested amount plus the sum already
  spent under this open Payment Mandate must be `<= max`, and "After approval, the amount MUST be
  added to the accumulated total" (`ap2/docs/payment_mandate.md`, "Budget"). In Countersign:
  - An amount is **reserved** while a presentation is in flight. A reservation blocks concurrent
    presentations.
  - A reservation is **released** when a rejection receipt is issued, including a void before
    capture. A voided authorization was never approved, so nothing is added to the total.
  - An amount is **added** when the capture succeeds (the approval). It is never subtracted.
  - A **refund after capture does not restore headroom.**
    The spent amount is taken from PayPal capture and void outcomes and verified webhooks, not from
    agent claims, and the capture gate re-evaluates it immediately before capture.
- **Scope.** Spent amount is counted per open Payment Mandate (its digest), which is what the
  spec's "total amount spent using this Payment Mandate" means. With one purchase per mandate the
  budget and the amount range are consistent ceilings. Customer-wide caps across mandates are not a
  mandate concept and stay merchant policy.
- **`ON_DEMAND` (Countersign interpretation).** The spec does not define the time separation for
  `ON_DEMAND`. Countersign treats it as "no minimum separation". With `max_occurrences` of `1`
  this has no practical effect.
- **`exp`.** The native constraints have no window. The mandate `exp` claim bounds the time
  window. `payment.execution_date` is not used to bound use.
- **Future work (not implemented).** A reading in which a Payment Mandate carrying
  `payment.agent_recurrence` with a larger `max_occurrences` lets one open Checkout Mandate back
  several closed checkouts, each satisfying `checkout.line_items` on its own, up to the budget.
  This is not the strict reading, depends on how `payment.reference` and the "no splitting" note
  interact, and would need upstream confirmation. Until then repeat use is refused.

### Decision 3: Line items in the mandate, categories in merchant policy

Resolves: D4.

- The open Checkout Mandate uses the native `checkout.line_items` constraint, listing explicit
  `acceptable_items` that the customer approved on the Trusted Surface (item `id` and `title`).
  It also carries `checkout.allowed_merchants` naming this merchant.
- The spending ceiling is the native `payment.amount_range` (`max` in minor units) on the open
  Payment Mandate, together with `payment.allowed_payees` and the required `payment.reference`.
- A request such as "headphones under $80" is turned into a concrete item list by the Trusted
  Surface backend from the catalog (items in the category, each priced within the ceiling), shown
  to the customer as that exact list, and signed only as that list.
- Category limits (for example "this agent may never buy from category X") remain merchant policy
  enforced by Countersign outside mandates. They do not appear in any mandate.

### Decision 4: No custom constraint types

Resolves: D2, D5.

Countersign defines no constraint types and adds no non-spec claims to mandates. Mandate content
uses only the ten native types and the claims in the vendored schemas, so a standard verifier
accepts it. Consequences:

- The earlier idea of `countersign.budget.cumulative.1` and `countersign.category.allow.1` is
  dropped. Their jobs are covered by Decisions 2 and 3.
- Issued mandates are validated in tests against the vendored AP2 schemas.
- On the verifying side an unknown constraint `type` fails evaluation and is reported as
  `unresolved_constraint`, as the spec requires.
- Expiry is the `exp` claim, checked as a claim.
- Countersign's own additional evidence, such as the device consent signature in Decision 5, lives
  outside the mandates.

### Decision 5: Trusted platform provider with a device consent signature

Resolves: D6.

Countersign uses the UCP "trusted platform provider" option and the AP2 "Trusted Agent Provider"
delegation model ([1.3.1](#131-capability-and-negotiation), [1.2.9](#129-who-can-be-trusted-to-sign-for-the-user)).

- **Platform profile and key.** The Trusted Surface backend is the platform provider. It publishes a
  platform profile whose top-level `keys[]` holds its mandate-signing ES256 public key with a
  `kid`. The shopping agent sends that profile URI in `UCP-Agent`. The issuer-signed JWT of each
  user-delegated mandate carries `iss` (the platform provider identifier) and the signing `kid` in
  its header, as in the AP2 Trusted Agent Provider example. Verifiers trust only the configured
  provider. Third-party platform providers are not supported.
- **Mandates stay standard.** Open mandates (autonomous mode) are signed by the platform key with
  the agent public key in `cnf`. Closed mandates in Human Not Present mode are signed by the agent
  key. All of this follows the formats in [1.2.3](#123-sd-jwt-structure-and-chains).
- **Consent before signing.** The platform key signs only after the backend has verified a
  consent signature from the customer's non-extractable device key (WebCrypto ECDSA P-256) over the
  exact constraints (for open mandates) or the exact checkout (for closed mandates).
- **Consent signature format (to be refined when the Trusted Surface is built).** A JWS with
  `alg` `ES256` and `kid` equal to the device key's JWK thumbprint, over the JCS bytes of a consent
  record that contains: a version, the consent kind (open mandates or closed checkout), the
  customer id, the exact mandate contents to be signed (the claims, before signing), a nonce and
  issue and expiry times. WebCrypto produces the raw `r || s` form that JWS ES256 uses.
- **Backend checks before signing.** (1) the device public key is registered to the customer; (2)
  the signature verifies; (3) the backend independently rebuilds the mandate contents from the
  structured data and the JCS bytes equal the signed record; (4) the consent record is unexpired
  and its nonce unused. Any failure means no mandate is issued.
- **Evidence.** The consent signature, the consent record and the registered device public key are
  stored and included in the evidence bundle as additional evidence. They are not part of any
  mandate. Their value is that a third party can verify them without trusting the platform key.
- **What this changes.** The device key no longer signs mandates directly. A compromised platform
  key could mint mandates without consent, and the consent signatures are the independent check on
  that. Because Countersign also plays Merchant, Credential Provider and Payment Processor, the
  party that signs mandates is also a verifier, and this must be stated in the limitations.
  Customer private keys are never held by the server.
- **Trusted Surface rules unchanged.** The surface renders from structured data with fixed
  templates, no model-generated text, and is non-agentic.

### Decision 6: `vp_formats_supported` placement

Resolves: D8.

`vp_formats_supported` is placed inside the `config` object of the
`dev.ucp.common.payment.ap2_mandate` capability entry, exactly as in the spec example
(`"config": {"vp_formats_supported": {"dc+sd-jwt": { }}}`). It is not a top-level profile member.
The profile is validated against the vendored profile schema in tests.

### Decision 7: `checkout_jwt` and `merchant_authorization`

Resolves: gap 1.

Files read for this decision: `ucp/docs/documentation/ucp-and-ap2.md`, `ap2/docs/checkout_mandate.md`
and `ap2/docs/payment_mandate.md`, plus the AP2 example tokens. They do not state whether the two
are the same object. What they do show:

- AP2: `checkout_jwt` is "base64url-encoded serialized merchant-signed JWT of the Checkout payload"
  (`ap2/schemas/ap2/checkout_mandate.json`), and with UCP "this MUST be the Checkout object"
  (`ap2/docs/checkout_mandate.md`).
- UCP: `merchant_authorization` is a detached JWS over the JCS-canonicalized checkout minus `ap2`.
- The overview page describes the business signature as "a detached JWT signing the checkout
  state" under older field names (`ucp/docs/documentation/ucp-and-ap2.md`, "Protocol flow").
- The AP2 example `checkout_jwt` is not a UCP checkout and not JCS output, so it does not constrain
  the UCP form.

**Countersign interpretation (ours, not spec).** They are the same JWS over the same bytes.

- Let `payload_bytes` be the JCS bytes of the checkout with the `ap2` member removed.
- Let `header` be the protected header `{"alg": "ES256", "kid": "<merchant kid>"}` exactly as UCP
  builds it, with no `typ`.
- `merchant_authorization` is the detached form: `b64url(header) + ".." + b64url(signature)`.
- `checkout_jwt` is the compact form with the payload attached:
  `b64url(header) + "." + b64url(payload_bytes) + "." + b64url(signature)`.
- Both carry the same signature, so one signing operation yields both. A verifier can rebuild
  `checkout_jwt` from a checkout response by re-attaching the payload.
- `checkout_hash` and `transaction_id` are then `b64url(SHA-256(US-ASCII(checkout_jwt)))` per
  [1.2.4](#124-hashes).

Reasoning. The merchant must sign the checkout once for UCP. If AP2's `checkout_jwt` were a
different signature over different bytes, the UCP rule that the mandate embeds the checkout with its
`merchant_authorization` would give two unrelated merchant signatures for the same checkout and no
statement of which one the hash binds. The only form that keeps one merchant signature, satisfies
"merchant-signed JWT containing the Checkout" (compact JWS with the checkout as payload) and
satisfies "detached JWS over JCS" (same signature with the payload removed) is the one above. Using
`typ` in the header would change the signed bytes and break equality with `merchant_authorization`,
so the header carries no `typ`. A verifier that insists on `typ` `JWT` will not accept this form;
that is a known interoperability risk to confirm upstream.

The "full checkout including `ap2.merchant_authorization`" that UCP says the mandate contains is
obtained by decoding the `checkout_jwt` payload and restoring
`ap2.merchant_authorization = b64url(header) + ".." + b64url(signature)`. Receipt `reference` for a
presented chain is taken over the final SD-JWT in the chain as `ap2/docs/agent_authorization.md`
states ("Action Authorization"), computed like `sd_hash` over its full compact serialization.

### Decision 8: Payment mandate `credential.token` format

Resolves: gap 5; D7.

Countersign plays the Credential Provider and the Merchant Payment Processor, so it defines the
token it accepts. The format is chosen to keep the Payment Mandate itself standard.

- **Placement.** In the `complete` request, `payment.instruments[*].credential` is
  `{"type": "ap2_payment_mandate", "token": "<string>"}`. `type` is an open string chosen by the
  handler (`token_credential.json`); `ap2_payment_mandate` is our value. The instrument `id`,
  `handler_id` and `type` follow the UCP instrument schema and are fixed when the PayPal facts are
  confirmed.
- **Token value.** The token is exactly the compact serialization of the Payment Mandate
  presentation, with no wrapper, envelope or extra field. In autonomous mode it is
  `<open Payment Mandate SD-JWT>~~<closed Payment Mandate KB-SD-JWT>~<disclosures...>~`, the chain
  form of [1.2.3](#123-sd-jwt-structure-and-chains). Any standard AP2 verifier can parse it.
- **Claims.** The closed Payment Mandate has `vct` `mandate.payment.1`, `transaction_id` equal to
  the checkout hash, `payee` (the merchant object), `payment_amount` (`amount` as integer minor
  units and `currency`), and `payment_instrument`. The KB-SD-JWT `aud` is `credential-provider` as
  in the AP2 example, and `nonce` is single use ([Decision 1](#decision-1-single-use-keys)).
- **Encoding rules (Countersign limits).** US-ASCII only, no whitespace, at most 16 KiB, split on
  `~` under the draft's rules (one empty component between chain links), and no duplicate
  disclosures. Anything else is rejected before signature checks.
- **Scoping to the checkout.** The payment is scoped to the checkout by `transaction_id` equal to
  the session's `checkout_hash`, matching the MPP rule that the credential carry the closed
  mandate ([1.2.8](#128-verification-and-dispute-steps)).
- **Roles inside one process.** The Merchant role verifies `ap2.checkout_mandate`. The Credential
  Provider role verifies the token against the same checkout hash, evaluates constraints, reserves
  budget, then creates the PayPal order. The Payment Processor role authorizes and runs the capture
  gate. Each role verifies independently from the same inputs. None trusts another role's result.
- **Human Present mode.** The Direct flow has no worked example in the vendored AP2 files. The token
  format for a closed mandate signed by the platform key without an open mandate is fixed when the
  mandate issuer is built, and recorded here.
- **Receipts.** The Payment Receipt is a JWT signed by the Payment Processor role with the fields in
  [1.2.7](#127-receipts). Its transport back to the agent is fixed with gap 4.

### Decision 9: Handling the checkout mandate pattern

Resolves: the UCP `ap2.checkout_mandate` pattern mismatch (section [1.3.4](#134-carrying-the-mandates-in-ucp)).

The vendored pattern `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+(~[A-Za-z0-9_-]+)*$` rejects
valid SD-JWT with key binding, because elements after the first `~` may contain neither dots nor be
empty. A key-binding JWT contains dots, and the chain format requires an empty component. Tested
against the pattern as written: a string with disclosures only matches, but a string with a
trailing key-binding JWT, a trailing `~`, the AP2 chained example, or an empty element does not.

Handling:

- Countersign accepts mandates that are valid under AP2, RFC 9901 and the Delegate SD-JWT draft.
- Countersign does not apply the UCP pattern. It validates the mandate string structurally itself:
  character set (base64url, `.`, `~`), the `~` and `~~` splitting rules from the draft, component
  counts, and then full cryptographic verification.
- When request bodies are validated against the vendored UCP schemas in tests, the `pattern` of
  `ap2.checkout_mandate` is removed from the schema copy used, with a comment pointing here.
- A failing conformance test (expected failure, strict) records the mismatch:
  `tests/conformance/test_ucp_mandate_pattern.py`.
- An upstream issue text is drafted in `docs/upstream/ucp-mandate-pattern.md`. When upstream fixes
  the schema and the vendored copy is updated, the strict expected failure will start failing and
  must be removed, which signals that the workaround can be dropped.
- Interoperability risk: a strict UCP schema validator on a third-party platform or business may
  reject valid mandates until upstream is fixed.

### Decision 10: Provisional rules for open gaps

Resolves: gaps 6 and 7 provisionally.

- **Error transport.** AP2 error codes are returned in the UCP `messages` array as an error
  message (`type` `error`, `code` set to the code, `severity` `unrecoverable` for invalid or
  expired mandates and `recoverable` where the platform can fix the request). The checkout
  `status` stays unchanged, and no authorization is created. HTTP status follows the REST binding:
  business outcomes use 200, and protocol-level failures (idempotency conflict) use 409. This is
  provisional and recorded so tests and the attack suite share one behaviour.
- **Clock skew.** `exp` and `nbf` are checked with a skew of 60 seconds. This is a Countersign
  choice because the specs give none. Open mandates are issued with `exp` as short as the task
  allows.

### Decision 11: Pre-authorize check

Resolves: the mutation window between payer approval and authorization ([4.3](#43-patch), deviation
D13).

- **Check.** In redirect-approval mode, after payer approval and before calling authorize, the
  Credential Provider role fetches the live order, re-derives the canonical terms, compares them
  with the signed checkout, and calls authorize only on an exact match.
- **Mismatch.** The order is never authorized, so there is nothing to void. The role records a
  rejection receipt and releases the reservations.
- **Second layer.** The capture gate stays. Post-authorization amounts cannot be patched (observed),
  but the gate still covers mandate revocation, budget state and evidence assembly, and it covers
  any path in which the pre-check was skipped.
- **Vault mode.** Create and authorize happen in one call, so there is no PATCH window (observed in
  the sandbox, [4.7](#47-vaulting-a-sandbox-wallet)).
- **Who can patch.** Per the documentation the update operation needs the merchant app's API
  credentials ([4.3](#43-patch)). The modeled actor is a compromised or buggy merchant-side
  component, or a confused deputy using those credentials, not the buyer or the agent.
  Countersign does not claim that the agent can alter orders.
- **Ablation.** `ABL_NO_PREAUTH_CHECK` disables the pre-check in `full` mode, for evaluation. With
  it set, a patched-up order is authorized and the capture gate must void it; without it, the order is
  never authorized. Like the other ablations it is refused when `APP_ENV=demo`.

---

## 4. Confirmed PayPal facts

Observed in the PayPal sandbox with `scripts/sandbox_smoke.py` and `scripts/sandbox_confirm.py`
(request and field reference in [ENV.md](ENV.md) section 2). Everything here was observed against the
sandbox only, in runs by the maintainer, unless it is labelled as from documentation. Each result is
one observation; none is a guarantee about production. Section 4.8 is documentation, not observation.

### 4.1 Identifier and header limits

| Probe                                              | Result                                                          |
| -------------------------------------------------- | --------------------------------------------------------------- |
| `custom_id` of 255 characters                      | accepted, returned unchanged                                    |
| `custom_id` of 256 characters                      | rejected, HTTP 400 `INVALID_STRING_LENGTH`                      |
| `invoice_id` of 127 characters                     | accepted, returned unchanged                                    |
| `invoice_id` of 128 characters                     | rejected, HTTP 400 `INVALID_STRING_LENGTH`                      |
| `PayPal-Request-Id` of 108 characters              | accepted                                                        |
| `PayPal-Request-Id` of 109 characters              | HTTP 500 `INTERNAL_SERVICE_ERROR`                               |
| `PayPal-Request-Id` containing colons              | accepted                                                        |
| A second create with an `invoice_id` already used  | accepted at create                                              |

Across the runs, returned `custom_id` and `invoice_id` values were unchanged. A Request-Id over the
limit fails with a server error rather than a validation error, so the client must enforce the limit
itself. A duplicate `invoice_id` was not rejected at create; whether it is rejected later was not
tested.

### 4.2 Idempotent replay

| Call replayed with the same `PayPal-Request-Id` | Result                                                                                  |
| ----------------------------------------------- | --------------------------------------------------------------------------------------- |
| Create order                                    | the same order was returned                                                             |
| Create order, different amount in the body      | the original order was returned, with the original 74.00 amount                         |
| Authorize                                       | HTTP 200 with the same authorization                                                    |
| Capture                                         | the same capture                                                                        |
| Refund                                          | the same refund                                                                         |
| Void                                            | the same void result                                                                    |

Authorizing an order that was already authorized, with a new Request-Id: HTTP 422
`ORDER_ALREADY_AUTHORIZED`.

### 4.3 PATCH

- **After authorization**, every field tried (`custom_id`, `invoice_id`, `description`, `amount`)
  returned HTTP 422 `ORDER_ALREADY_COMPLETED`, and the authorization was unchanged.
- **While the order was `APPROVED`** (payer approved, not yet authorized):
  - PATCH of `custom_id` returned 204 and was reflected on the next GET.
  - PATCH of items and amount together (74.00 to 27.00) returned 204, the order stayed `APPROVED`,
    and authorize then authorized 27.00.
- **Consequence for the gate.** The mutation window is between payer approval and authorization.
- **Raising the amount while `APPROVED`** (script section `o4`, a fresh order approved at 74.00 and
  left `APPROVED`):
  - PATCH of `invoice_id` returned 204, and GET showed the patched value.
  - PATCH of items and amount together from 74.00 up to 100.00 (items 92.00 plus tax 8.00,
    consistent) returned 204. GET showed amount 100.00 with status `APPROVED`.
  - Authorize then returned 201 with an authorization of 100.00 in `CREATED` status, with no new
    payer approval. The authorization was voided afterwards (200, `VOIDED`).
- **Consequence.** Between payer approval and authorize, the order amount can be raised or lowered
  using the merchant app credentials, and PayPal authorizes the patched amount. The response is
  [Decision 11](#decision-11-pre-authorize-check).
- **Credentials (from documentation, not tested with other credentials).** In PayPal's Orders v2
  schema the update order operation lists only OAuth 2.0 bearer authentication. The PATCH calls in
  the runs were made with the merchant app's access token. Whether any other party can PATCH an
  order was not tested.

### 4.4 Authorization lifetime

`expiration_time` was 29 days after the authorization was created, in this run and in the earlier
smoke run. The event documentation (4.8) describes a 30 day validity period. Both are noted; the
gate reads `expiration_time` from the fetched authorization and does not assume a period.

### 4.5 Capture and void

| Step                                                   | Result                                                        |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| Capture 30.00 with `final_capture` false               | accepted; authorization status `PARTIALLY_CAPTURED`           |
| Second partial capture 20.00                           | accepted                                                      |
| Capture 40.00 when 24.00 remained                      | HTTP 422 `MAX_CAPTURE_AMOUNT_EXCEEDED`                        |
| Final capture 24.00                                    | accepted; authorization status `CAPTURED`                     |
| Capture after the final capture                        | HTTP 422 `AUTHORIZATION_ALREADY_CAPTURED`                     |
| Void after capture                                     | HTTP 422 `PREVIOUSLY_CAPTURED`                                |
| Capture of a voided authorization                      | HTTP 422 `AUTHORIZATION_VOIDED`                               |
| Second void of a voided authorization                  | HTTP 422 `PREVIOUSLY_VOIDED`                                  |

Also observed: a later GET of the first capture (requested with `final_capture` false) showed
`final_capture` true.

### 4.6 Refund

| Step                                                   | Result                                                        |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| Partial refund 10.00 of a 30.00 capture                | accepted; capture status `PARTIALLY_REFUNDED`                 |
| Refund 25.00 when 20.00 remained                       | HTTP 422 `REFUND_AMOUNT_EXCEEDED`                             |
| Refund with an empty body after the partial refund     | accepted; capture status `REFUNDED`                           |
| Refund of a fully refunded capture                     | HTTP 422 `CAPTURE_FULLY_REFUNDED`                             |

The amount refunded by the empty-body call was not printed, so it is not recorded.

### 4.7 Vaulting a sandbox wallet

- An order created with `payment_source.paypal.attributes.vault` (`store_in_vault` `ON_SUCCESS`),
  approved by the payer and authorized, returned a vault status of `VAULTED`.
- A second order created from the vault id with no payer approval (`payment_initiator` `MERCHANT`,
  `payment_type` `UNSCHEDULED`, `usage` `SUBSEQUENT`) returned HTTP 201 with order status
  `COMPLETED` and an authorization in `CREATED` status for 74.00, with `custom_id` and `invoice_id`
  intact.
- Sandbox only. Production availability is unverified.

### 4.8 Webhooks (from PayPal's documentation, not observed)

No webhook was received in any run. Live confirmation is deferred to the Render deploy, where a
public HTTPS URL exists (see [PROGRESS.md](PROGRESS.md)).

Events the documentation lists for the calls Countersign makes:

| Event                           | Documentation description                                                                                           |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `CHECKOUT.ORDER.APPROVED`       | a buyer approved a checkout order                                                                                   |
| `PAYMENT.AUTHORIZATION.CREATED` | a payment authorization is created, approved, executed, or a future payment authorization is created                |
| `PAYMENT.AUTHORIZATION.VOIDED`  | an authorization is voided, either on reaching its 30 day validity period or by the void authorized payment API     |
| `PAYMENT.CAPTURE.COMPLETED`     | a payment capture completes                                                                                         |
| `PAYMENT.CAPTURE.REFUNDED`      | a merchant refunds a payment capture                                                                                |

The same documentation also lists `PAYMENT.CAPTURE.PENDING`, `PAYMENT.CAPTURE.DENIED`,
`PAYMENT.CAPTURE.DECLINED`, `PAYMENT.CAPTURE.REVERSED` and `CHECKOUT.ORDER.COMPLETED`.

Signature verification, per the Notifications API schema: the receiver calls
`POST /v1/notifications/verify-webhook-signature` with `auth_algo`, `cert_url`, `transmission_id`,
`transmission_sig`, `transmission_time`, `webhook_id` and `webhook_event`. The first five come from the
notification's `PAYPAL-AUTH-ALGO`, `PAYPAL-CERT-URL`, `PAYPAL-TRANSMISSION-ID`,
`PAYPAL-TRANSMISSION-SIG` and `PAYPAL-TRANSMISSION-TIME` headers; `webhook_id` is the id configured in
the developer portal; `webhook_event` is the received body. The response carries
`verification_status`, either `SUCCESS` or `FAILURE`. Behavior beyond this (retries, ordering,
delivery delay) was not read and is not assumed.

---

## 5. Still to be written

Added by later work, not yet present in this file:

- Live webhook confirmation (deferred to the Render deploy).
- Human Present token format and receipt transport (see Decisions 8 and gap 4).
- Gate step codes, principal lock semantics, the evidence reference encoding and the PayPal field
  mapping in both directions.

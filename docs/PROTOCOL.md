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
- **Consent signature format (refined by [Decision 81](#decision-81-the-consent-record-and-the-platform-issuer); the text below is the original sketch).** A JWS with
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

### Decision 12: Strict JSON number rules

Resolves: the "excess decimal precision" rule of INV-8 and the `decimal_ambiguity` attack, which no
vendored file defines.

- **Integers and floats.** Any number of magnitude above 2^53 - 1 is rejected, whether it is
  written as an integer or as a float (`1e20`). This is the RFC 8785 and UCP integer cap. A float
  that large canonicalizes to integer digits that the loader would refuse on re-parse.
- **Excess precision.** A number with a fraction or an exponent is accepted only if its decimal
  value equals the shortest decimal that round-trips the binary64 value it parses to. So `0.1`,
  `1.50`, `15e-1` and `0.30000000000000004` are accepted, while `0.1000000000000000055`,
  `333333333.33333329` (the RFC 8785 sample number) and `1e-400` are rejected, because two different
  texts would otherwise denote one number. Trailing zeros and exponent spelling are not precision.
- **Overflow.** A number that overflows binary64 (`1e999`) is rejected as non-finite.
- **Not a money rule.** Money is never a JSON float (INV-9). Amounts are integer minor units or
  decimal strings, which this loader treats as ordinary integers and strings.
- **Consequence for vectors.** The RFC 8785 sample input is rejected by the strict loader (it
  contains `333333333.33333329` and `1E30`); the JCS function itself reproduces the RFC bytes from
  the parsed values, and the tests cover both.
- **Hash domains.** Countersign-internal hashes are SHA-256 over a validated ASCII domain name
  (`cs.<words>.v<N>`), a NUL byte, then the data. The NUL separator is a Countersign choice. AP2
  hashes never use it.

### Decision 13: Money exponents and decimal strings

Resolves: INV-9 for the PayPal boundary, and a mismatch between UCP and PayPal for HUF and TWD.

- **Two exponents.** UCP amounts are integers in ISO 4217 minor units. PayPal says HUF, JPY and
  TWD do not support decimals, while ISO 4217 gives HUF and TWD two decimals ([ENV.md](ENV.md)
  section 8). `Money` stores ISO minor units; converting to a PayPal string requires the amount to be
  a whole number of units for those currencies, and raises otherwise. There is no rounding.
- **Supported set.** The 25 currencies on PayPal's REST currency page. KWD and the other
  three-decimal currencies are not on it, so a `Money` in one is refused. The exponent-3 path exists
  in the decimal core and is tested there.
- **Grammar.** PayPal decimal strings are parsed as text, never through the JSON float path (the
  strict loader never sees them as numbers). Rejected: floats, `bool`, exponent notation, a leading
  plus, thousands separators, whitespace, a leading or trailing dot, leading zeros, negative zero,
  non-ASCII digits, more than 32 characters, and more fractional digits than the PayPal exponent even
  when the extra digits are zero. Fewer fractional digits are accepted because the value is exact.
- **Sign.** Negative amounts are refused unless the caller opts in (`allow_negative`); UCP amounts
  are never negative.

### Decision 14: Canonical checkout model

Resolves: which parts of a UCP checkout Countersign models, and the totals rules it enforces.

- **Fields.** `id`, `currency`, `line_items` (`id`, `item` {`id`, `title`, `price`, optional
  `quantity_unit`}, `quantity`, `totals`) and `totals` (`type`, `amount`, optional `display_text`).
  Other top-level members are ignored by `from_ucp`; unknown members inside line items, items and
  totals are errors. Sub-lines (`lines`), `parent_id`, `unit_price` and `image_url` are not modelled.
- **Total types.** The seven well-known types only: `subtotal`, `items_discount`, `discount`,
  `fulfillment`, `tax`, `fee`, `total`. UCP allows other types with a `display_text`; Countersign has
  no PayPal breakdown for them and rejects them. `items_discount` and `discount` must be negative
  (UCP: `exclusiveMaximum 0`); the others must not be negative.
- **Consistency.** Exactly one `subtotal` and one `total` at both levels (UCP). The `total` equals
  the sum of every other entry (the UCP verification rule). A line subtotal equals unit price times
  quantity. The order subtotal equals the sum of the line subtotals. The order `items_discount`
  entries sum to the line `items_discount` entries ("rollup of line-item discounts"). All three
  consistency rules are Countersign's reading of the UCP text, which does not state the line-level
  and rollup rules as formulas.
- **Units.** `quantity_unit` is accepted only as the `each` identity (`C62`, scale absent or 0);
  `display_text` and `increment` are ignored for identity, as UCP says. Anything else is rejected
  rather than priced.
- **Terms.** `terms()` omits `display_text` and an explicit `each` unit, because PayPal cannot return
  the first and the second does not change the money. Totals and line items keep their order. Every
  amount carries the checkout currency by construction, so the currency is bound once, in `currency`.
- **Lengths.** Item `id` and `title` are limited to 127 characters, the most PayPal returns
  unchanged for `sku` and `name`.

### Decision 15: Decision log entries and Merkle trees

Resolves: how log entries are hashed and how roots and inclusion proofs are built, so that a
verifier (including a TypeScript one) can be written from this text. Reference vectors are in
`tests/vectors/ledger_vectors.json` (regenerate with `uv run python -m tests.unit.test_ledger_merkle`;
a test fails if the file and the code disagree). All hashes are SHA-256. `domain_hash(d, x)` is
SHA-256 of the ASCII bytes of `d`, a `0x00` byte, then `x` (Decision 12). Integers are big-endian.

**Entry encoding.** An entry has `seq` (from 1, no gaps), `ts_us` (microseconds since the Unix
epoch, UTC), `checkout_id` (absent or 1 to 127 bytes of UTF-8), `kind` (1 to 64 characters of
`[A-Za-z0-9._:-]`, starting with a letter or digit), `payload` (the JCS bytes of a JSON object),
`policy_hash` (32 bytes), `prev_hash` and `entry_hash`.

```text
payload_hash = domain_hash("cs.log.payload.v1", payload)
scope        = 0x00                                     if checkout_id is absent
             = 0x01 || u32(len(checkout_id)) || checkout_id (UTF-8)   otherwise
entry_hash   = domain_hash("cs.log.v1",
                 prev_hash(32) || u64(seq) || u64(ts_us) || scope
                 || u32(len(kind)) || kind (UTF-8) || payload_hash(32) || policy_hash(32))
prev_hash of seq 1 = 32 zero bytes
```

`checkout_id` and `kind` are inside the hash (the architecture text lists five components; these
two are added) so an entry cannot be moved between per-checkout trees without breaking the chain.

**Verification** walks the entries in order and stops at the first of these, reporting its position
and a code: `field_invalid`, `seq_unexpected` (not the previous `seq` plus one; this covers
deletion, duplication, insertion and reordering), `prev_mismatch`, `payload_hash_mismatch`,
`entry_hash_mismatch`. With an `Anchor` (newest `seq` and `entry_hash`, kept where the writer cannot
change it) it also reports `truncated` (the log ends before the anchor) and `anchor_mismatch`.
Without an anchor, removing the newest entries, rewriting the newest entry with a recomputed hash,
or rewriting the whole chain is undetectable: the result is internally consistent.

**Merkle tree.** The shape and proof algorithm are those of RFC 6962 and RFC 9162. The leaves of a
tree are `entry_hash` values, in `seq` order.

```text
leaf(e)      = domain_hash("cs.merkle.leaf.v1", e)                 e is 32 bytes
node(l, r)   = domain_hash("cs.merkle.node.v1", l || r)            l and r are 32 bytes
tree([])     = domain_hash("cs.merkle.empty.v1", "")
tree([e])    = leaf(e)
tree(es)     = node(tree(es[0:k]), tree(es[k:n]))   n = len(es) >= 2,
                                                    k = the largest power of two < n
root(es)     = domain_hash("cs.merkle.root.v1", u64(len(es)) || tree(es))
```

- **Leaf and node separation.** Different domains, so an interior node cannot be passed off as a
  leaf.
- **Odd nodes.** There is no duplication and no padding: the split is at a power of two, so
  `[a, b, c]` and `[a, b, c, c]` have different roots.
- **Leaf count.** It is hashed into the root. A bare RFC 6962 tree hash does not authenticate its
  size: a proof for index 6 of a 10-leaf tree also verifies when the size is claimed to be 11.
- **Scopes.** A checkout tree holds the entries whose `checkout_id` equals the checkout, labelled
  `checkout:<id>`. A day tree holds the entries whose `ts_us` falls in the UTC day
  `[00:00:00, 24:00:00)`, labelled `day:YYYY-MM-DD`. Both are in `seq` order and may be empty
  (size 0).

**Inclusion proof.** For the leaf at `index` in a tree of `size` leaves: the sibling hashes from the
leaf level up to the top, as in RFC 6962 `PATH`. Recomputation (the rightmost element of the path is
the sibling nearest the root):

```text
root_from_path(index, size, leaf, path):
  if size == 1:  return leaf if path is empty else FAIL
  if path is empty: FAIL
  k = largest power of two < size;  sibling = path[-1];  rest = path[:-1]
  if index < k:  return node(root_from_path(index, k, leaf, rest), sibling)
  else:          return node(sibling, root_from_path(index - k, size - k, leaf, rest))
valid iff 0 <= index < size, the path has exactly the length the recursion uses, and
  domain_hash("cs.merkle.root.v1", u64(size) || root_from_path(index, size, leaf(entry_hash), path)) == root
```

The iterative algorithm of RFC 9162 section 2.1.3.2 computes the same tree hash; a test checks the
two agree for every index of every size up to 39.

JSON form: `{"v": 1, "index": i, "size": n, "path": ["<base64url, no padding, 43 chars>", ...]}`,
exactly those four members, `index` and `size` integers with `0 <= index < size`, `path` an array,
each element the canonical unpadded base64url of 32 bytes.

**Storage.** `payload` is kept as the exact JCS bytes (`bytea`, never `jsonb`). The application role
has `INSERT` and `SELECT` on the table only. Appends are serialized by a transaction-level advisory
lock; the primary key on `seq` and unique constraints on `prev_hash` and `entry_hash` refuse a fork
even if the lock is skipped.

### Decision 16: Merchant signing key and profile

Resolves: D8 (placement); the `kid` rule for the merchant key, which the specs leave open.

- **Key.** One ES256 key: JWK `kty` `EC`, `crv` `P-256`, `alg` `ES256` (required, not inferred),
  `use` `sig`. The service refuses to start if the file is missing, is a link, is readable by group
  or others, has duplicate JSON keys, holds members outside `kty crv x y d alg use kid`, has another
  type, curve or algorithm, has public members that do not match the private scalar, or has a `kid`
  that is not the thumbprint below. AP2 requires a non-deterministic scheme such as ECDSA for the Checkout JWT
  ([1.2.4](#124-hashes)); Ed25519 is therefore refused.
- **`kid`.** The RFC 7638 JWK SHA-256 thumbprint of the public key: SHA-256 over the JSON of the
  members `crv kty x y` in lexicographic order with no whitespace, written as unpadded base64url.
  It is derived, never chosen, so two different keys cannot share an identifier and the value is
  also valid for Web Bot Auth interop, where the UCP schema requires it.
- **Storage.** `secrets/merchant_es256.jwk.json` (`MERCHANT_KEY_PATH`), mode 600, created by
  `make keys` with exclusive creation: an existing file is never overwritten, because replacing the
  key invalidates every outstanding Checkout JWT, mandate binding and receipt. Rotation is
  deleting the file on purpose. The key is never printed or logged.
- **Profile.** `/.well-known/ucp` serves the business profile: service `dev.ucp.shopping` over
  `rest` with endpoint `<PUBLIC_BASE_URL>/ucp/v1`, capability `dev.ucp.shopping.checkout`, and
  `dev.ucp.common.payment.ap2_mandate` with `extends` and
  `config.vp_formats_supported = {"dc+sd-jwt": {}}`, as in the vendored example
  ([Decision 6](#decision-6-vp_formats_supported-placement)). `keys[]` is a top-level member holding
  the public JWK only, copied from an allowlist (`kty crv x y alg use kid`); the builder fails if any
  of `d p q dp dq qi oth k` is present. `payment_handlers` is an empty object because the schema
  requires the member and Countersign advertises no UCP payment handler at this stage.
- **Version.** `2026-08-25`, the pinned release. The profile validates against the vendored
  `profile.json#/$defs/business_schema` in a test.

### Decision 17: UCP checkout REST binding

Resolves: how the checkout operations treat request members, status, errors and expiry where the
specs leave room. Sources: `ucp/docs/specification/shopping/checkout/rest.md` ("Operations",
"Protocol Mechanics") and `index.md` ("Checkout Status Lifecycle", "Status Values", "Error
Handling", the operation sections); `ucp/source/schemas/shopping/checkout.json`,
`types/line_item.json`, `types/item.json`; `ucp/docs/specification/overview/index.md` ("Schema
processing").

- **Paths.** Under the advertised REST endpoint (`<base>/ucp/v1`): `POST /checkout-sessions`,
  `GET` and `PUT /checkout-sessions/{id}`, `POST /checkout-sessions/{id}/complete` and `/cancel`.
  Create answers 201, the others 200. A `UCP-Agent` header with a `profile="<URL>"` member is
  required on every request (the spec marks it required); absent or malformed is
  `invalid_profile_url`, HTTP 400. The profile is not fetched yet, so there is no capability
  negotiation and AP2 protection is enforced for every session (fail closed).
- **What a request controls.** Only `line_items`: per line `item.id` and `quantity`, and on update
  the line `id` and an optional `item.quantity_unit` assertion. The schemas mark these members
  `ucp_request: omit` for create and update: `id`, `status`, `currency`, `totals`, `links`,
  `expires_at`, `order`, line `totals`, `item.title`, `item.price`, and on create the line `id`. The
  published schemas are open (no `additionalProperties: false`), and the overview says conformance
  to the request direction is defined by the processing rules, not by rejecting extra members, so
  Countersign **ignores** them and never reads their values. When a value differs from what the
  business computed, the response carries a warning (`type` `warning`, `code` `field_ignored`,
  `path` the member); an echoed value equal to the business's own produces none, because the spec's
  full-replacement rule makes platforms send the whole resource back. `buyer`, `context`,
  `signals`, `attribution` and `payment` are accepted by the schema and are not modelled: they are
  discarded, not stored and not echoed.
- **Prices.** `item.price` and `item.title` come from the catalog when a checkout is written and are
  stored in the checkout; reads never re-price. Totals are the sum of line totals: there is no tax,
  fulfillment or discount.
- **Update** is full replacement of `line_items`. A line `id` on update must name an existing line
  and appear once; new lines get `li_<n>` from a per-checkout counter that never reuses a number.
  Lines are limited to 20 per checkout and quantity to 99 per line (Countersign limits, reported as
  `line_limit` and `quantity_limit`). An `item.quantity_unit` other than `C62` with scale 0 is
  `quantity_unit_mismatch` (the spec allows rejection with a recoverable outcome).
- **Status.** All six values and the edges of the lifecycle diagram are defined in
  `protocols/ucp/checkout_state.py`; every change goes through `transition`. Countersign collects no
  buyer, address or fulfillment data, so a valid checkout is `ready_for_complete` from creation and
  never `incomplete` or `requires_escalation` (there is no buyer handoff and no `continue_url`).
  `complete_in_progress` and `completed` are reached only by Complete, which is a stub until the
  mandate verification exists. Stays in one status on update.
- **Expiry.** `expires_at` is creation plus 6 hours (the spec's default TTL). It is applied when the
  checkout is next touched: a non-final checkout at or past `expires_at` becomes `canceled` and the
  change is logged.
- **Complete (stub).** From `ready_for_complete` it returns the unchanged checkout with an error
  message `mandate_required` (`severity` `recoverable`, `path` `$.ap2.checkout_mandate`), whatever
  the body carries: nothing is verified yet, so no mandate is accepted (INV-3, INV-10). From any other
  status it returns `checkout_not_ready`.
- **Errors** follow [Decision 10](#decision-10-provisional-rules-for-open-gaps). Business outcomes
  are HTTP 200: with no resource (unknown id, a create that cannot succeed) the body is an error
  response (`ucp.status` `error`, no checkout); otherwise it is the current checkout with an error
  message. Codes: `not_found`, `item_unavailable`, `mandate_required` (UCP); `checkout_not_modifiable`,
  `checkout_not_cancelable`, `checkout_not_ready`, `complete_in_progress`, `line_item_not_found`,
  `quantity_limit`, `line_limit`, `quantity_unit_mismatch`, `field_ignored` (Countersign, free-form
  as `error_code.json` permits). A refusal because the checkout is final is `unrecoverable`; one
  that the platform can fix (or wait out) is `recoverable`. A create with any unavailable line
  creates nothing, because dropping lines silently would change what the platform asked for.
  Protocol failures are 4xx or 5xx with a `{code, content}` body: 400 for a bad body (the strict
  JSON loader's codes `json_syntax`, `json_duplicate_key`, `json_non_finite`, `json_encoding`,
  `json_too_large`, or `invalid_request` for a wrong shape, content type or non-object body) and
  500 `internal_error` for anything unexpected, with no detail.
- **Storage and log.** One Postgres row per checkout holds the JCS bytes of the canonical checkout,
  status, version and times. Each operation changes the row under its lock and appends to the decision
  log in the same transaction (`checkout.created`, `.updated`, `.canceled`, `.expired`, and
  `.update_rejected`, `.complete_rejected`, `.cancel_rejected` for refusals), so a log failure rolls
  the change back. Reads are not logged. A row that no longer validates is never served (500).
  Migration `0002` also makes a final checkout immutable and requires each update to advance the
  version by one.
- **Not implemented.** `Idempotency-Key` (the spec says SHOULD; a retried create makes a second
  checkout), request and response message signatures, and the cart-to-checkout conversion.

### Decision 18: `merchant_authorization` signing and verification

Resolves: details of [1.3.3](#133-merchant_authorization) that the spec leaves open. Sources:
`ucp/docs/specification/payment/extensions/ap2-mandates.md` ("Business Authorization", "Signature
Computation", "Canonicalization", "Business Verification"); `ucp/source/schemas/common/payment_ap2_mandate.json`
(`merchant_authorization` pattern). Implemented in `countersign.merchant.authorization`; the
relationship to `checkout_jwt` is [Decision 7](#decision-7-checkout_jwt-and-merchant_authorization).

What the spec states and the code follows: the value is a detached JWS `<header>..<signature>`; the
header holds `alg` and `kid`; the signature is over `b64url(header) "." b64url(JCS bytes)` where the
payload is the checkout without its `ap2` member; coverage is the complete checkout JSON, including
`ucp` members. Interpretations that are ours:

- **Everything but `ap2` is covered, so a response is signed last.** `messages`, `expires_at`,
  `links` and `status` are inside the signature. Two responses for the same checkout therefore
  carry different signatures when anything in them differs, and, because ECDSA is randomized (AP2
  requires a non-deterministic scheme), even identical content signs differently each time. A
  platform builds its mandate from the exact response it verified. The Merchant role compares terms
  (id, totals, line items) with the session, not messages.
- **Header bytes.** The spec's pseudocode says `json_encode(header)` without fixing the encoding.
  Countersign signs the compact JSON `{"alg":"ES256","kid":"<kid>"}` (member order `alg`, `kid`, no
  whitespace, no `typ`). A verifier signs over the header segment it received, so any encoding of
  those two members verifies; the member set must be exactly `alg` and `kid`.
- **ES256 only.** The schema allows ES256, ES384 and ES512. Countersign signs ES256 and refuses the
  others when verifying, as it does `none` and every MAC algorithm. This narrows what the spec
  accepts and is deliberate: one algorithm, one key type (the merchant key,
  [Decision 16](#decision-16-merchant-signing-key-and-profile)).
- **Verification rules** (an unverifiable value is `merchant_authorization_invalid`; an absent one is
  `merchant_authorization_missing`, both UCP codes): the value matches the schema pattern; the header
  is a strict JSON object with exactly `alg` and `kid`; `alg` is `ES256`; header and signature are
  canonical unpadded base64url; the signature is 64 bytes; `kid` names exactly one entry of the
  published `keys[]`, which must be an EC P-256 public key (any `alg` it names is ES256, any `use` is
  `sig`, no private member); the payload is rebuilt from the response being verified.
- **Signature malleability.** ECDSA accepts both `(r, s)` and `(r, n - s)`. A copy with the other
  `s` verifies and has a different `checkout_hash`, because the hash is over the whole JWT string.
  This does not let anyone change terms, and a mandate binds the hash of the string its signer
  verified. It does matter for single use: every re-signed response, and every `s` flip, has a new
  `checkout_hash`, so single use cannot rest on the hash alone. [Decision 1](#decision-1-single-use-keys)
  rule 1 also makes the checkout id unique to one authorization, and the database must enforce that
  with a unique constraint on the checkout id (task P2.4 in [PROGRESS.md](PROGRESS.md)).
- **Scope.** Every response that carries a checkout is signed, whether or not AP2 was negotiated,
  because capability negotiation is not implemented yet ([Decision 17](#decision-17-ucp-checkout-rest-binding)).
  A response with no checkout (an error response) carries no `ap2`. A request that carries an `ap2`
  member on create or update is ignored, as the schema marks it `omit`; it is not reported as an
  ignored field, because an echoed `ap2` is always stale.
- **Interop.** `scripts/interop_verify.mjs` verifies a response with `jose` and `canonicalize`
  using only the public JWK from the profile, and prints the `checkout_hash` of the rebuilt
  `checkout_jwt`, which a test compares with the Python value. `make interop` starts the server with
  uvicorn, creates, updates, reads, completes and cancels a checkout over HTTP, and verifies each
  response with that script.

### Decision 19: PayPal client

Resolves: how `countersign.paypal` turns the facts in [section 4](#4-confirmed-paypal-facts) and
[ENV.md](ENV.md) section 2 into rules. Endpoints and fields are only those recorded there.

- **Calls.** OAuth `POST /v1/oauth2/token`; create `POST /v2/checkout/orders` (intent `AUTHORIZE`
  only); get order; authorize; get authorization; capture; void; refund; get capture. State is read
  with GET. A mutation returns only the identifier of the resource it touched (and, for create, the
  `payer-action` or `approve` link); `authorize` does not read its response body at all, because the
  authorization id is in the fetched order. Mutations send `Prefer: return=representation`, the
  setting the verified sandbox runs used. **A POST with no payload still sends a JSON body:**
  `authorize` and a full refund send `{}` with `Content-Type: application/json`, as the accepted runs
  did; with no body at all PayPal answered 415 `UNSUPPORTED_MEDIA_TYPE` (found when recording the
  cassette, [ENV.md](ENV.md) 2.5). `void` sends no body, which is what the accepted runs did.
- **Request ids.** `cs1.<operation>.<digest>`, the digest being the unpadded base64url of
  `SHA-256("cs.paypal.request.v1" || 0x00 || fields)` where each of the checkout id, the operation
  and any extra parts is a 4 byte big-endian length then its UTF-8 bytes. At most 60 characters.
  Create order adds the base64url of a domain separated SHA-256 (`cs.paypal.order_request.v1`) over
  the JCS bytes of the create-order body that is sent. The client computes it from that body and the
  caller cannot supply it, so the id always matches what goes out. PayPal replays the first order
  for a repeated id even when the body differs (4.2): a re-priced checkout, or any other change to
  the request, must be a different request. A test compares the derivation with a `hashlib` and
  `rfc8785` reference and pins one value. The generic derivation and its two golden values did not
  change. Recorded create-order ids in the cassettes use this form.
  Authorize adds the order id, void adds the authorization id, and capture adds the authorization
  id and the approved total (`<currency>:<value>`), `invoice_id` and `custom_id`. A checkout can now
  have several orders and authorizations over its life (a re-priced checkout creates a new order), and
  PayPal replays the first result for a repeated id, so an id from checkout and operation alone
  could replay the void or capture of an earlier authorization. Whether PayPal replays one id across
  different paths was not tested; the ids avoid depending on it. The authorize id carries no terms
  of its own: the order id fixes them, because the order was created from a request whose hash is in
  its own id. Pinned values and a `hashlib` reference cover all three.
  Refunds add the capture id, the amount (`full` or `<currency>:<value>`) and a required
  caller-supplied refund key (1 to 64 characters of letters, digits, `_` and `-`). The amount alone
  is not enough: two separate refunds of the same amount would send one id and PayPal would replay
  the first. A retry of one refund passes the same key, a new refund a new key. The client checks every id against the
  108 character limit and `[A-Za-z0-9._:-]` before sending and refuses to send a state-changing call
  without one. A test pins two values and compares the derivation with a `hashlib` reference.
- **Capture.** `capture_authorization` takes one argument, a `CaptureApproval`, a sealed value that
  states the checkout id, authorization id, total, `invoice_id` and `custom_id` the capture gate
  approved. Only `countersign.gate` is allowed to build one (`mint_capture_approval` in
  `paypal/approval.py`); a structural test fails if other library code imports the mint or calls the
  capture, and it lists the recording and test helpers outside the package that do. Python cannot
  stop a caller that reaches into private names, so the guard is the sealed constructor, that test
  and review. There is no amount argument and no partial form. The client fetches the authorization
  and requires: the same id, status `CREATED` (the status enum has no `EXPIRED`, so expiry is
  `expiration_time` against the client's clock with the rule in [4.4](#44-authorization-lifetime),
  and a zone required), `invoice_id` and `custom_id` equal to the approved values (so another
  checkout's authorization of the same total is not captured), and an amount equal to the approved
  total. It then sends that amount with `final_capture` true. Anything else raises before a capture
  request is sent (`AuthorizationNotCapturable`, `AuthorizationMismatch`, `AmountMismatch`). After
  an error with `outcome_unknown` the caller re-fetches and does not call capture again: a second
  call would see the status the first one produced. The sandbox recording cycle that captures
  without a gate lives in `tests/ungated_capture_cycle.py`, not in the package.
- **Retries.** 5xx, timeouts, connection errors and a 409 `PREVIOUS_REQUEST_IN_PROGRESS` are retried
  up to three attempts in total with a 0.5 s doubling backoff capped at 8 s, always with the same
  Request-Id. A 401 refreshes the token once without using an attempt. A 4xx is never retried.
  A state-changing call that ends in a timeout, a connection error, a 5xx or a 409 in progress raises
  an error with `outcome_unknown` true. Redirects are not followed.
- **Token.** Cached in memory, refreshed when less than 60 seconds remain, thread safe, never logged.
- **Error codes.** Mapped to typed exceptions: `INVALID_STRING_LENGTH`, `ORDER_NOT_APPROVED`,
  `ORDER_ALREADY_AUTHORIZED`, `ORDER_ALREADY_COMPLETED`, `MAX_CAPTURE_AMOUNT_EXCEEDED`,
  `AUTHORIZATION_ALREADY_CAPTURED`, `AUTHORIZATION_VOIDED`, `PREVIOUSLY_CAPTURED`,
  `PREVIOUSLY_VOIDED`, `REFUND_AMOUNT_EXCEEDED`, `CAPTURE_FULLY_REFUNDED` (observed) and
  `AUTHORIZATION_EXPIRED`, `TRANSACTION_DISPUTED`, `PREVIOUS_REQUEST_IN_PROGRESS` (documentation).
  **Interpretation:** the notes record these as error names, while PayPal's usual body puts a class
  name in `name` and the specific code in `details[].issue`. The mapper accepts either: `name` first,
  then each `issue` in order. Other errors map by status (401, 404, 409, 5xx, other 4xx).
- **Models.** Responses ignore unknown members and fail on a missing required one: an order needs
  `id`, `status`, `intent` and at least one purchase unit with an `amount`; an authorization needs
  `id`, `status`, `amount` and `expiration_time`; a capture needs `id`, `status`, `amount` and
  `final_capture`. These requirements follow the schema notes and fail closed; the recorded cassette
  will show whether PayPal always sends them. PayPal nests `breakdown` inside `amount`; the model
  lifts it. Amounts become `Money` and any non-exact decimal is a parse error.
- **Limits** enforced client side: `custom_id` 255, `invoice_id` 127, Request-Id 108, item `name` and
  `sku` 127, no control characters, and that `amount` equals items plus tax.
- **Hosts.** The sandbox host by default. Another host needs `allow_non_sandbox`; the two live PayPal
  hosts are refused whatever the setting.
- **Cassettes.** Recording is off unless `PAYPAL_RECORD_CASSETTES=1`. A recording keeps method, path,
  Request-Id, request body, status, debug id and response body; it drops the `Authorization` header,
  replaces the token, application id, nonce, scope, merchant and account ids and e-mail addresses,
  empties `payer`, `shipping` (except the `breakdown.shipping` amount) and `payment_source` in responses, replaces every known secret string,
  and is refused if an `@`, a bearer token or a known secret remains. Replay is strictly in order.
- **Not implemented here:** webhooks and signature verification, order PATCH, vaulted merchant-initiated
  orders ([4.7](#47-vaulting-a-sandbox-wallet)), and a refund read (re-fetch the capture instead).

### Decision 20: Canonical checkout to PayPal order, and back

Resolves: the field mapping in both directions (`src/countersign/paypal/translate.py`) and what PayPal
cannot carry. Compared by `OrderTerms.terms_hash()`, domain `cs.paypal.terms.v1`, over the JCS bytes of
`{checkout: <Decision 14 terms>, payee: {merchant_id}, invoice_id, custom_id}`.

**Forward mapping** (`order_request_from_checkout`):

| Canonical                                  | PayPal                                                           |
| ------------------------------------------ | ---------------------------------------------------------------- |
| checkout `id`                              | `invoice_id` (127 characters at most)                            |
| evidence reference                         | `custom_id` (255 at most), given by the caller                   |
| line `item.title`, `item.id`               | item `name`, `sku` (127 each)                                    |
| line `item.price`, `quantity`              | item `unit_amount`, `quantity` (decimal string of a whole number) |
| line `tax` entry (a total for the line)    | item `tax`, per unit                                             |
| order `subtotal`                           | `breakdown.item_total`                                           |
| order `fulfillment`                        | `breakdown.shipping`                                             |
| order `tax`                                | `breakdown.tax_total`                                            |
| order `fee`                                | `breakdown.handling`                                             |
| order `discount` (negative)                | `breakdown.discount` (positive)                                  |
| order `total`                              | `amount`                                                         |

**Refused, never rounded or truncated.** The forward direction raises `TranslationError` for: a
total type with no PayPal field (`items_discount`, and any line entry other than `subtotal`, `tax`
and `total`); a repeated total type; order entries not listed in the order subtotal, fulfillment, tax,
fee, discount, total (a breakdown has no order, so one order is fixed); a line tax that is not a
whole number of minor units per unit; an order tax that differs from the sum of the line taxes (or
is present without any line tax, or absent with one); a HUF or TWD amount that is not a whole unit
(Decision 13); a zero total; a checkout id or evidence reference over its limit. A title or item id
over 127 characters cannot be built into a checkout at all (Decision 14).

**Reverse mapping** (`paypal_order_to_canonical_terms`, takes the order from `get_order` and the signed
line ids). It fails closed, with `TranslationError`, when: the intent is not `AUTHORIZE`; there is not
exactly one purchase unit; `item_total`, `invoice_id`, `custom_id`, the payee `merchant_id`, an item
`sku` or an item `name` is missing; an item count differs from the line id count; a quantity is not
`[1-9][0-9]{0,9}`; any amount is in a different currency from the order amount; `item_total` is not
the sum of the items, `tax_total` is not the sum of the item taxes or is present without item taxes
or absent with them; `insurance` or `shipping_discount` is present (this mapping never produces them,
so they could hide money); a `discount` is zero; the amount is not `item_total` plus tax, shipping and
handling minus discount. Unknown members of the order are ignored (PayPal adds fields), and the
members that are read are the only ones that count.

**What PayPal cannot carry, and what covers it.** None of these can be re-derived from a live order.
They are bound by the evidence reference in `custom_id` (a hash of the evidence record, which holds
the signed checkout), so a change to one of them changes the signed checkout and the reference, not
the PayPal order:

| Canonical field                              | Why it is not in the order                                          |
| -------------------------------------------- | ------------------------------------------------------------------- |
| Line item `id`                               | PayPal has no per-line id; `sku` holds the item id, and one item may appear on two lines. Applied by position from the signed line ids, relying on PayPal returning items in the order sent |
| `display_text` of totals, `quantity_unit`    | Presentation, not money; `terms()` already drops them (Decision 14) |
| Per-line `total` entries                     | Derived: unit amount times quantity plus tax                        |
| Order of the `totals` array                  | A breakdown is unordered; the fixed order above is required instead |
| Item `category`, `reference_id`, `description` | Not terms; sent for PayPal, never compared                        |
| Titles and item ids over 127 characters      | Refused when the checkout is built (Decision 14), not truncated      |

Because line ids are applied by position, a PayPal order whose items were reordered reverses to
different terms whenever the reordered items differ, and an order with an added or removed item is
refused.

**Observed** in the recorded cassettes (`tests/cassettes/paypal_authorize_capture.json` and
`tests/cassettes/paypal_order_terms.json`): GET returned the purchase unit as sent, with the items in
the order sent, `breakdown` holding only the entries that were sent, `payee.merchant_id` added and
`payee.email_address` (scrubbed in the recording). The second cassette shows the sandbox accepting and
echoing unchanged item `tax`, `tax_total`, `shipping`, `handling` and `discount` with `NO_SHIPPING`,
and both of its orders reverse to the checkout that was sent. Create answered HTTP 200 in every run,
and replay detection does not use the status code. Item order was observed only for orders of two
items ([LIMITATIONS.md](LIMITATIONS.md) L13).

### Decision 21: Issuer JWT `typ`

**Status: confirmed by the owner.**

Resolves: the open item in [ENV.md](ENV.md) section 1.5 ("the `typ` of the issuer-signed JWT is
unspecified").

- The issuer-signed JWT (link 0) must carry `typ` `dc+sd-jwt`, the media type of an SD-JWT VC.
  Anything else, including the `example+sd-jwt` of the AP2 worked examples and `JWT`, is rejected
  with `typ_mismatch`.
- Why: no vendored file fixes the value, and an accepted-by-default `typ` lets a key-binding JWT or
  a checkout JWT be replayed as an issuer credential. `dc+sd-jwt` is also the format name in the
  profile (`vp_formats_supported`).
- Risk: a third-party platform that issues open mandates with another `typ` is refused until the
  value is widened. The allowed values are one tuple, `ISSUER_JWT_TYP` in `mandates/chain.py`.
- **Status after review (P2.2).** The vendored AP2 text does not normatively require `dc+sd-jwt`
  as the issuer JWT `typ`. It appears only as a credential `format` identifier (in
  `agent_authorization.md` and the UCP `vp_formats_supported`), while the worked examples show
  `example+sd-jwt`, and no vendored file states a required `typ`. `dc+sd-jwt` is therefore a
  Countersign choice (explicit typing, RFC 9901 recommends it), not an AP2 requirement.
- Key-binding links follow the Delegate SD-JWT draft verification text: `kb-sd-jwt+kb` for a link
  that another link follows, `kb+sd-jwt` for the last link. The older `kb+sd-jwt+kb` is not
  accepted (draft history, -01).

### Decision 22: Time claims in mandates

Resolves: gap 7 for the primitives, and the "RECOMMENDED" `exp` of AP2.

- `exp`, `nbf` and `iat` are checked with the 60 second skew of [Decision 10](#decision-10-provisional-rules-for-open-gaps),
  held as `CLOCK_SKEW_SECONDS`. Exactly 60 seconds outside passes, 61 fails. Applies to `exp`
  (expired), `nbf` (not yet valid) and `iat` (issued in the future).
- They must be JSON integers. Booleans, floats and strings are rejected (`time_claim_type`).
- `exp` is **required** on every link except a final key-binding link. AP2 only recommends it for
  open mandates. A mandate that never expires is a standing authority with no end, so the
  primitive refuses it. A final key-binding link has `iat` (required) and may have `exp`.
- The checks run on the disclosed delegate payload and on the signed JWT payload, because the draft
  moves issuer claims into the delegate payload while the key-binding `iat` stays in the JWT.
- No maximum age is applied to the key-binding `iat`. Replay is bounded by the single-use nonce
  ([Decision 1](#decision-1-single-use-keys)), which belongs to the caller.

### Decision 23: Accepted chain forms

Resolves: places where the Delegate SD-JWT draft allows more than AP2 mandates need.

- Every link carries its content (`vct`, `cnf`, claims) in a disclosed `delegate_payload` element,
  as in all AP2 examples. Every element of the signed `delegate_payload` array must be a `{"...": digest}`
  object and exactly one must be disclosed. Plaintext elements are rejected.
- A trailing delegate key-binding JWT (`dSD-JWT+KB`) is rejected (`structure_trailing_kb`). AP2
  mandates end with `~`.
- A key-binding link must carry `sd_hash`. `issuer_jwt_hash` alone is rejected (`sd_hash_missing`),
  because it does not cover the disclosures and would let a holder withhold constraint disclosures
  that the signer had committed to.
- `cnf` is accepted only as `{"jwk": <inline EC P-256 public key>}`. Other members, other key types
  or curves, a private scalar `d`, or a point off the curve are rejected with a typed error.
- Base64url must be canonical: re-encoding the decoded bytes must reproduce the text. Without this,
  the unused bits in the last character of a signature segment can be flipped without changing the
  decoded signature. With it, no single-character change to a valid mandate is harmless.
- JOSE header parameters `crit`, `b64`, `zip`, `jwk`, `jku`, `x5u` and `x5c` are rejected. Keys come
  only from the caller (issuer) or the previous link's `cnf`.
- Size limit: 16 KiB for the whole string, the limit of Decision 8, applied to checkout mandates
  too. Not a specification value.

### Decision 24: What "both directions" means for the chain

**Status: confirmed by the owner.**

Resolves: the draft's "Without verifying the binding in both directions a malicious Delegate Holder
may mis-match parts of the chain if the Holder `cnf` is reused" (Security Considerations). The draft
does not define the two directions. Countersign's reading, which needs the maintainer's confirmation:

- **Key binding to credential.** The key binding's `sd_hash` must equal the digest of the previous
  link as presented, including its disclosures and trailing `~`. A holder cannot pair a key binding
  with a different credential that reuses the same `cnf` key, and cannot drop a disclosure after
  signing.
- **Credential to key binding.** The key binding must be signed by the `cnf` key of the previous
  link, and by no other key. A holder or third party cannot attach their own key binding.
- **Review (P2.2): no other predecessor hash exists in the chain.** In the Delegate SD-JWT draft and
  the vendored AP2 files, the only value that hashes a predecessor link is the key binding's
  `sd_hash` (or `issuer_jwt_hash`, refused by Decision 23). The final-KB-JWT step of the draft
  (hash over the final KB-SD-JWT+KB) applies only to the trailing `dSD-JWT+KB` form, which is
  refused. The other hashes in AP2 link different credentials, not links of one chain:
  `checkout_hash` and `transaction_id` (Merchant step M3 here, Credential Provider in P2.4) and the
  Payment Mandate constraint `payment.reference.conditional_transaction_id`, the digest of the open
  Checkout Mandate (evaluated with the constraints in P2.3).
- There is no third `sd_hash` check pointing the other way: a credential cannot contain the hash of
  something signed after it. The two directions are therefore one `sd_hash` comparison and one `cnf`
  signature check, tested separately.

### Decision 25: What `verify_chain` leaves to the caller

Resolves: scope of P2.1 against the roles that use it.

- The caller names the issuer key to trust, the exact `vct` list (so chain length and every `vct`
  are fixed by the caller), the expected `aud` of the final key binding and optionally its `nonce`.
  `aud` and `nonce` are checked on the final key binding only; earlier key bindings must carry them.
- A verified link exposes `nonce` and `digest` (the `sd_hash` form of its serialization). Single
  use of the nonce, the checkout hash binding, constraint evaluation, who counts as a trusted
  issuer, and mapping the typed errors to the UCP error codes are the merchant and cp roles' work
  (P2.2 onward).
- The returned content is the resolved claims, with disclosures applied. It is not deeply
  immutable; callers must not mutate it.

### Decision 26: Merchant verification steps and the UCP error mapping

Resolves: gap 6 for the Merchant role, and the order of [architecture.md](architecture.md) 5.4.

The steps run in this fixed order; each has its own typed failure (`Rejection` with a step, an
internal reason and a UCP code). The reason is a fixed string, never request text.

| Step | Check | Failure reasons (internal) | UCP code |
| ---- | ----- | -------------------------- | -------- |
| M1 | a mandate is present | `mandate_missing` | `mandate_required` |
| M2 | chain: trusted platform key, `cnf` key, `vct`, `aud`, expiry | `platform_key_missing`; `chain:<mandates code>` | `agent_missing_key` for no platform key and for any `cnf` problem; `mandate_expired` for `exp` past the skew; `mandate_invalid_signature` for everything else, including not-yet-valid, issued-in-future, and any code this table does not know |
| M3 | `checkout_hash` claim equals the hash of the checkout JWT this session issued | `checkout_hash_missing`, `checkout_hash_mismatch`, `session_checkout_unavailable` | `mandate_scope_mismatch` |
| M4 | embedded checkout JWT carries our valid `merchant_authorization` and is the session's JWT | `checkout_jwt_absent`, `signature_stripped` (missing); `checkout_jwt_not_text`, `checkout_jwt_malformed`, `embedded_checkout_*`, `merchant_authorization_unverified` (invalid); `embedded_checkout_is_not_this_session` (scope) | `merchant_authorization_missing`, `merchant_authorization_invalid`, `mandate_scope_mismatch` |
| M5 | embedded terms equal the current session state (id, currency, line items, totals) | `terms_mismatch` with the first differing path, `embedded_checkout_malformed` | `mandate_scope_mismatch` |
| M6 | principal lock | added in P2.6 | |
| M7 | every constraint evaluates true | `constraint_violated`, `constraint_unresolved` | `mandate_scope_mismatch` |
| M8 | single-use keys reserved atomically | `checkout_hash_reused` (hash or checkout id), `nonce_replayed`, `open_mandate_in_use` | `mandate_scope_mismatch` |

Interpretations to confirm:

- The vendored extension has seven codes and no code for replay or constraints. Reuse of a key and
  constraint outcomes use `mandate_scope_mismatch` ("bound to a different checkout"), and an unknown
  constraint type does too; the AP2 `unresolved_constraint` of [architecture.md](architecture.md) 5.4
  is kept as the internal reason, not a UCP code.
- A missing agent key (`cnf`) maps to `agent_missing_key`, whose description in the extension is
  about the platform profile; the name is the closest fit.
- Severity: `recoverable` for `mandate_required`, `mandate_scope_mismatch` and both
  `merchant_authorization_*` codes (the agent can fetch the checkout again); `unrecoverable` for
  `mandate_invalid_signature`, `mandate_expired` and `agent_missing_key`.
- M4 distinguishes missing from invalid: a mandate with no `checkout_jwt` disclosed, or one whose
  signature segment is empty, is "missing"; any other defect in it is "invalid".
- M3 and M5 take two inputs: the last signed response the session issued, and the current session
  state from the store. They are equal in normal operation; a difference means state moved without
  being re-signed, which must never be accepted. The checkout id is compared in M5.
- Any unexpected exception inside the steps rejects with reason `internal_error` and the code
  `mandate_invalid_signature` (INV-10), and aborts a reservation if one exists. A decision log
  failure is not a rejection: the exception propagates and no result is returned (INV-12).

### Decision 27: Checkout Receipts

Resolves: receipt format and transport for the Merchant role (gap 4 in part).

- A receipt is a compact JWS signed with the merchant key; its payload is the JCS bytes of the
  claims (INV-8). Header: `alg` `ES256`, `kid`, `typ` `checkout-receipt+jwt`. The `typ` makes a
  receipt unusable as a `merchant_authorization` (whose header is exactly `alg` and `kid`) and the
  reverse.
- Success claims: `status` `Success`, `iss` (configured merchant identifier), `iat` (Unix seconds,
  injected clock), `reference`, `order_id`. Error claims: `status` `Error`, `iss`, `iat`,
  `reference`, `error` (the UCP code), `error_description` (the internal reason).
- `order_id` is the checkout id (the PayPal order does not exist yet at this step; the id is also
  the PayPal `invoice_id`, [Decision 20](#decision-20-canonical-checkout-to-paypal-order-and-back)).
- `reference` is the `sd_hash`-style digest of the final SD-JWT of the presented chain (Decision 7).
  For a rejection where the string cannot be split into links, it is the SHA-256 of the presented
  text (UTF-8, unpadded base64url), or of the empty string when nothing or a non-string was
  presented. This fallback is a Countersign choice; the spec defines the reference only for a
  parsed mandate.
- The receipt reaches the agent through the API layer (P2.7+); the Merchant role only produces it.

### Decision 28: Reservation, abort, release and consume

Resolves: the atomicity requirement of Decision 1 for the Merchant role.

- Reservation is the last step (M8) and takes every key in one call, so a failure at M1 to M7
  consumes nothing, including nothing of the open mandate; the same closed mandate can be presented
  again after a fix.
- Keys: checkout hash, checkout id, nonce scoped to (agent key thumbprint, audience, nonce), and the
  mandate digest (open mandate in autonomous mode, the mandate itself in Human Present mode). The
  checkout id is a key of its own so that re-signing a checkout does not make it a new purchase.
- `abort` frees every key (nothing outside the process happened, for example the decision log
  failed). `release` frees only the mandate digest, for a rejection after the reservation such as a
  void before capture; the hash, id and nonce stay consumed. `consume` makes the mandate digest
  permanently used (capture). The Postgres store (P2.4) must keep these semantics with unique
  constraints and transactions.
- A consequence of "reserve last": a replayed mandate is reported at M8, after the constraints were
  evaluated. Replay detection is not ordered before constraint evaluation.

### Decision 29: Human Present closed mandate

Resolves: the open item of Decision 8 ("Human Present mode ... fixed when the mandate issuer is built").

- A Human Present Checkout Mandate is a single SD-JWT (one link) with `vct` `mandate.checkout.1`,
  signed directly by the trusted platform key, content in a disclosed `delegate_payload` element,
  with `checkout_hash`, a disclosed `checkout_jwt`, `iat` and a required `exp`. It has no key
  binding, so it has no nonce.
- Because it has no nonce, single use rests on the checkout hash, the checkout id and the mandate
  digest (the digest of the mandate itself).
- The platform must issue it only after the customer signed the exact checkout on the Trusted
  Surface ([Decision 5](#decision-5-trusted-platform-provider-with-a-device-consent-signature)).
  The chain primitive treats link 0 like any issuer-signed credential (`dc+sd-jwt`, `exp` required).

### Decision 30: Constraint engine structure and interface

Resolves: where each native constraint is evaluated, and how the engine plugs into the Merchant role.

- **Two evaluators, one engine.** `CheckoutConstraintEvaluator` evaluates the open Checkout Mandate
  (`checkout.line_items`, `checkout.allowed_merchants`) for the Merchant role (step M7).
  `PaymentConstraintEvaluator` evaluates the open Payment Mandate (the eight `payment.*` types) for
  the Credential Provider (P2.4). The Merchant never sees a Payment Mandate, so the payment
  constraints cannot run inside M7.
- **Open against closed.** The open mandate holds the constraints (what the customer allowed). The
  closed values they bind are: for the Checkout Mandate, the checkout the closed mandate commits to
  (already matched to the session at M3 to M5); for the Payment Mandate, `payee`, `payment_amount`,
  `payment_instrument`, `pisp` and `execution_date`.
- **Structural interface.** `merchant/constraints.py` now defines `ConstraintOutcome` (a
  `runtime_checkable` Protocol with `satisfied`, `reason`, `unresolved`) as the result type, so
  `constraints/` returns its own `ConstraintResult` without importing `merchant/`. The Merchant
  accepts only a result whose `satisfied` is exactly `True`; any other object is a rejection. The
  default when no evaluator is injected stays `DenyAllConstraints`.
- **Merchant identity.** `allowed_merchants` is matched on the merchant `id` the evaluator is built
  with, never on `name` or `website`. Likewise payees match on `id`, instruments on `id` and `type`,
  PISPs on all three names.

### Decision 31: Strict reading of constraints

Resolves: "unknown constraints MUST be treated as failing evaluation", and places where the schemas are
open.

- A constraint with a member the engine does not evaluate (the schemas do not set
  `additionalProperties: false`) is `unresolved_constraint`. A member that is not understood might
  restrict the mandate further, so it is never ignored. A foreign mandate with extra members is
  therefore refused.
- A `type` that belongs to the other mandate (a `payment.*` type in a Checkout Mandate or the
  reverse) is `unresolved_constraint`.
- Two constraints of one `type` in one mandate are refused (`duplicate_constraint`). The spec does
  not say how to combine them.
- The schema-required constraints are required: `checkout.line_items` in an open Checkout Mandate,
  `payment.reference` in an open Payment Mandate. `checkout.allowed_merchants` is not required by the
  schema, so a mandate without it allows any merchant, as the spec reads. Countersign's own issuer
  includes it ([Decision 3](#decision-3-line-items-in-the-mandate-categories-in-merchant-policy)).
- AP2 processing rule 2: every claim of the open content other than `vct`, `constraints`, `cnf`,
  `iat`, `exp`, `nbf` must be present and equal, with the same JSON type, in the closed content
  (1, 1.0 and true differ). A closed mandate that carries `constraints` is refused.
- A single-link (Human Present) mandate has no open mandate and no constraints: the customer signed
  the exact checkout on the Trusted Surface ([Decision 29](#decision-29-human-present-closed-mandate)).
  A `constraints` claim in it is refused.
- Quantities and amounts are JSON integers. `true`, `1.0` and `"1"` are malformed, never coerced.
  `checkout.line_items` follows the spec's maximal flow formulation; an empty `acceptable_items`
  (nothing revealed) simply matches nothing.

### Decision 32: Payment constraint interpretations

Resolves: gaps in the Payment Mandate text.

- `payment.amount_range`: `max` and `min` are non-negative integers with `min <= max`; the currency
  must equal the payment's; the payment amount must be a positive integer (zero and negative amounts
  are invalid). Bounds are inclusive.
- `payment.budget`: as [Decision 2](#decision-2-strict-single-use-and-add-only-budget). `max` that is
  not a JSON integer (a fraction, `100.0`, an exponent, a string, a boolean) makes the mandate
  invalid. The vendored schema types `max` as `number` and accepts a fraction; the engine does not.
  `payment.budget` is evaluated even without `payment.agent_recurrence` (stricter than the spec's
  "to be used with").
- `payment.agent_recurrence`: valid only with `max_occurrences` of exactly 1; any frequency is
  accepted in that case because one occurrence makes the frequency moot. Missing, other or
  non-integer `max_occurrences` is `unresolved_constraint`; an unknown `frequency` is invalid.
- `payment.execution_date`: values are `YYYY-MM-DD` (a UTC day) or a full ISO 8601 timestamp with
  `Z` or an offset. A timestamp without an offset is ambiguous and invalid. For `not_after`, a date
  without a time means the end of that UTC day; for `not_before` the start. Bounds are inclusive. The
  execution time is the closed mandate's `execution_date` or, when absent, the injected clock.
- **Countersign executes immediately.** A closed `execution_date` later than now plus the 60 second
  skew is refused (`execution_date:in_future`) even when no constraint mentions it, because the
  system would otherwise capture before the date the customer approved. This goes beyond the spec.
- `payment.reference`: the digest must equal the `sd_hash`-style digest of an open Checkout Mandate
  link of the Checkout Mandate chain presented with the payment. A digest of the closed link does not
  count. The check that `transaction_id` equals the checkout hash stays with the Credential Provider.

### Decision 33: Spend view, accounting and category policy

Resolves: how the add-only budget of Decision 2 is fed to the evaluator.

- **The view is an argument.** `SpendView(currency, captured_minor, in_flight_minor)` is built by the
  caller from PayPal capture and void outcomes and verified webhooks (INV-7). The evaluator never
  reads an amount the agent states. Without a view, a mandate that has `payment.budget` fails.
- **The view excludes the presentation being evaluated.** The Credential Provider evaluates, then
  reserves atomically; the gate re-evaluates with its own reservation removed
  (`BudgetAccount.view_excluding`). Otherwise a purchase would count against itself.
- **Rules** (`BudgetAccount`, also the contract for the Postgres implementation): `reserve` adds to
  in-flight; `capture` moves in-flight to captured; `void` releases an uncaptured reservation and is
  the only event that raises headroom; `refund` changes nothing in the view. Refusing an event
  changes nothing. These are property tested.
- **Single use is separate.** One purchase per open mandate is enforced by the reservation store
  ([Decision 28](#decision-28-reservation-abort-release-and-consume)); the budget stops a purchase
  that would exceed the ceiling. After a void before capture the mandate can be retried; after
  capture, even if refunded, it cannot.
- **Category limits are merchant policy.** `check_category_policy` takes the checkout, a
  `CategoryPolicy` and a catalog lookup, and is separate from mandate evaluation. An unknown category
  is refused when a policy exists. The unmandated cap and velocity limits of the architecture are not
  implemented yet. It is not wired into the Merchant verifier in P2.3.

### Decision 34: The evidence reference in `custom_id`

Resolves: the "evidence reference encoding" listed as still to be written in section 5.

- `custom_id` = `cs1.` + the unpadded base64url of `SHA-256("cs.evidence.ref.v1" || 0x00 || R)`, where
  `R` is the JCS bytes of `{"v": 1, "checkout_hash": H, "checkout_mandate": C, "payment_mandate": P}`.
  `H` is the hash of the checkout JWT (equal to `transaction_id`), `C` the `sd_hash`-style digest of
  the closed Checkout Mandate and `P` that of the closed Payment Mandate (both over the final
  link of the chain, Decision 7).
- It is 47 characters, so the full 256 bit digest fits PayPal's 255 and nothing is truncated. The
  evidence bundle (P3) holds `H`, `C` and `P`, so the reference can be recomputed from the bundle and
  matched to the PayPal order, and a change to the checkout or to either mandate changes it.
- `invoice_id` stays the checkout id ([Decision 20](#decision-20-canonical-checkout-to-paypal-order-and-back)).
  The live order's `custom_id` is part of the terms the pre-authorize check compares.

### Decision 35: Credential Provider steps and rejections

Resolves: the CP verification order of [architecture.md](architecture.md) 5.5 and the error mapping.

C1 token present; C2 both chains (Payment Mandate with audience `credential-provider`, Checkout
Mandate with `merchant`, one trusted platform key, same mode); C3 `transaction_id` equals the hash of
the checkout JWT embedded in the Checkout Mandate and equals its `checkout_hash`; C4 payee `id`, amount
(integer, exact) and currency equal this merchant and the current checkout total; C5 constraints
([Decision 30](#decision-30-constraint-engine-structure-and-interface)); C6 single-use reservation;
C7 PayPal order; C8 pre-authorize check and authorization.

- Mandate failures use the same codes as the Merchant role ([Decision 26](#decision-26-merchant-verification-steps-and-the-ucp-error-mapping)):
  `mandate_required` (C1), `agent_missing_key`, `mandate_expired`, `mandate_invalid_signature`
  (chains), `mandate_scope_mismatch` (C3 to C6, C8).
- Everything that fails after the mandates verified (a PayPal error, an order that needs payer action
  in vault mode, an internal error) is **`payment_failed`**, a standard UCP error ("Payment processing
  failed", vendored `shopping/checkout/index.md`, "Standard Errors"; listed in `error_code.json`),
  `severity` `recoverable` as the spec recommends, message text "The payment could not be processed."
  It is not one of the seven AP2 mandate codes, and the AP2 extension's code list is not closed for
  messages (`error_code.json` permits any code). A log failure after the reservation cleans up and
  raises `DecisionLogError`; the API answers HTTP 500 `internal_error`, because no checkout
  outcome can be reported when the decision could not be recorded (INV-12).
- A rejection is answered with a signed Payment Receipt: `typ` `payment-receipt+jwt`, claims
  `status` `Error`, `iss`, `iat`, `reference` (the digest of the presented Payment Mandate, or the hash
  of the presented text as in [Decision 27](#decision-27-checkout-receipts)), `payment_id` (the
  checkout id), `error`, `error_description`. The success Payment Receipt needs the capture and is the
  gate's (P2.5).
- The CP verifies the Checkout Mandate chain itself (it needs the open Checkout Mandate digest for
  `payment.reference` and the embedded checkout JWT), but does not repeat the Merchant's M4 and M5:
  the merchant signature on the checkout and the terms comparison are the Merchant role's, run
  before the CP in UCP complete. The CP compares amount and currency with the current checkout.

### Decision 36: One transaction, row lock, and the Postgres schema

**Status: confirmed by the owner.**

Resolves: race safety of the budget and of single use (INV-6, INV-7).

- **Transaction.** C5 and C6 are one database transaction: lock the open Payment Mandate's row in
  `open_payment_mandates` (`SELECT ... FOR UPDATE`, creating it first), read the spend view (it does
  not yet contain this presentation, [Decision 33](#decision-33-spend-view-accounting-and-category-policy)),
  evaluate the constraints, reserve the single-use keys, insert the in-flight spend entry and the
  payment attempt, and append the decision to the log. A second presentation for the same open mandate
  waits on the row lock and then reads a view that includes the first. Any rejection or error rolls
  everything back except the rejection's own log entry. PayPal is called after the commit, never under
  the lock.
- **Where the budget race is tested.** One purchase per open mandate means the single-use key
  already admits only one presentation end to end. The budget race is therefore tested on the
  check-and-reserve transaction itself (20 parallel transactions against a budget that fits three give
  exactly three), with a negative control that removes the lock and over-spends. End to end, 20 parallel
  completes of one mandate give one order and one authorization.
- **Schema** (migration 0003). `reservations` per role (`merchant`, `cp`) with partial unique indexes
  on checkout id, checkout hash, the scoped nonce (all while the row is not `aborted`) and on the open
  mandate while `reserved` or `consumed`. The checkout id is its own key because the checkout hash is
  not unique per checkout (re-signing). `spend_entries` (add-only, trigger enforced),
  `open_payment_mandates`, `payment_attempts` (one row per checkout id), `payer_vault`. Triggers make
  keys immutable, allow only the legal state changes, and forbid a refund from lowering a captured
  entry.
- **Roles.** The runtime role has SELECT, INSERT and UPDATE on these tables, no DELETE and no
  TRUNCATE, and only SELECT and INSERT on the decision log. Tests run as that role and check the grants.
  Aborted and released rows stay as history.
- The in-memory store remains for unit tests; `PostgresReservationStore` honours the same contract
  (the same tests run against both).

### Decision 37: The checkout JWT the Merchant compares in UCP complete

**Status: confirmed by the owner.**

Resolves: what "the checkout JWT of this session" is when the service keeps no copy.

Each response is signed with ES256, whose signatures differ every time, so two responses to the same
checkout have different hashes and the service stores none of them. In UCP complete the Merchant is
called without an `issued_checkout`: M3 compares `checkout_hash` with the hash of the JWT the mandate
itself embeds (the consistency AP2 requires), M4 verifies our signature on it, and M5 compares its terms
with the current session state. Freshness therefore comes from M4 and M5, not from remembering what was
issued. A stale response with identical terms is accepted, which is harmless; the checkout id key
([Decision 36](#decision-36-one-transaction-row-lock-and-the-postgres-schema)) stops it buying twice.
Tests that pass an `issued_checkout` still exercise the stricter comparison.

### Decision 38: UCP complete, statuses and resumption

**Status: confirmed by the owner.**

Resolves: how complete drives two roles and a payer approval inside the UCP lifecycle.

- `countersign.completion.CompleteCoordinator` runs the Merchant verification, then the CP, and the
  UCP service reaches it only through a port it defines, so `cp/` and `merchant/` import no protocol
  adapter.
- The service works in three steps with no database lock held over PayPal: move `ready_for_complete`
  to `complete_in_progress` (logged), run the coordinator, record the outcome.
- A missing payment token is refused before the Merchant reserves anything, and the checkout stays
  completable. A rejection before the Merchant's reservation leaves the checkout `ready_for_complete`.
- A rejection after the Merchant reserved (CP rejection, failed pre-authorize check, PayPal failure)
  releases the Merchant reservation (the open mandate is usable again) and **cancels the checkout**
  with `checkout_canceled_after_rejection`: its hash and id are consumed ([Decision 1](#decision-1-single-use-keys)),
  so the agent creates a new checkout.
- Payer approval (redirect mode) answers with status `complete_in_progress`, `continue_url` set to the
  PayPal approval link and an info message `payer_approval_required`. UCP requires `continue_url`
  with `requires_escalation`, but `ready_for_complete` has no edge to it ([Decision 17](#decision-17-ucp-checkout-rest-binding)),
  so the link rides on `complete_in_progress`.
- After the payer approves, a second `POST .../complete` (the body may be empty) continues the same
  attempt: the mandates are not verified again. It runs the pre-authorize check and authorizes, and
  answers `payment_authorized`. The checkout stays `complete_in_progress`: capture, and the move to
  `completed`, belong to the capture gate (P2.5). A concurrent complete is told
  `complete_in_progress`.
- Without a completion port configured, complete never succeeds (fail closed).

### Decision 39: The payment handler that carries the Payment Mandate token

**Status: confirmed by the owner.**

Resolves: item 7 (the empty `payment_handlers`).

- The vendored AP2 extension shows `"payment_handlers": {}` in its profile example, and its complete
  request puts the mandate in `ap2.checkout_mandate` and the Payment Mandate in
  `payment.instruments[*].credential.token` ([Decision 8](#decision-8-payment-mandate-credentialtoken-format)).
  UCP ties an instrument to a handler by `handler_id`, which "corresponds to the `id` field in the Payment
  Handler definition" (`payment_instrument.json`). Without a handler there is no `handler_id` to put on
  the instrument, so the profile now declares one.
- Handler: registry key `dev.countersign.payment.ap2_payment_mandate`, one entry `{id:
  "countersign_ap2_payment_mandate", version, config: {credential_type: "ap2_payment_mandate"}}`. It
  is also returned in every checkout response (`ucp.payment_handlers`). `spec` and `schema` are omitted
  (optional in the business schema) because no document is published for them. The reverse-domain name
  is a **placeholder** (no registered domain) and the whole handler is a Countersign construct, not
  something the specs define ([LIMITATIONS.md](LIMITATIONS.md) L14).
- Request parsing: the instrument whose `handler_id` is ours and whose credential `type` is
  `ap2_payment_mandate` carries the token. Instruments of other handlers are ignored. Two of ours, a
  credential of another type, or a token that is not a string is HTTP 400 `invalid_request`.
- The Node interop verifier checks only `merchant_authorization` over the whole response, so it
  verifies responses that now carry the handler without a change; `make interop` still passes.

### Decision 40: Payer approval, the vaulted path, cleanup and recovery

**Status: confirmed by the owner.**

Resolves: item 3 (cleanup), item 6 (honest payer approval) and the outcome-unknown rules.

- **Redirect mode** (default): the order is created with the experience context; the payer approves on
  PayPal; `finish` re-fetches the order, requires `APPROVED` (still `CREATED` or `PAYER_ACTION_REQUIRED`
  is "pending", nothing changes), runs the pre-authorize check
  ([Decision 11](#decision-11-pre-authorize-check)) and authorizes only on an exact match. An order that is
  never approved is abandoned by `recover`, never authorized.
- **Vault mode** (sandbox only): if the principal (the thumbprint of the agent key named in the open
  mandate) has a vault id, the order is created from it with the stored-credential form recorded in
  [4.7](#47-vaulting-a-sandbox-wallet) and no payer approval. PayPal created and authorized in one call
  in the sandbox, so there is no patch window; the order is fetched and its terms and the authorization
  are verified, and a mismatch is voided. If PayPal asks for payer action instead, the attempt is
  rejected (`vault_requires_payer_action`) rather than presented as autonomous. Enrolment: with
  `enroll_vault` the redirect order asks PayPal to vault the wallet, and the vault id PayPal reports
  is stored for the principal. The principal is the agent key because no customer id exists in the
  mandates yet (INV-5 asks for customer id and agent key); the Trusted Surface (P3) supplies it.
  **Nothing here claims production availability** ([LIMITATIONS.md](LIMITATIONS.md) L1).
- **Cleanup** after a reservation (any exception, PayPal error, schema error, rejection or log failure):
  void every authorization PayPal reports for the order and confirm each with a GET (a void response
  body can be incomplete); void the spend entry; release the mandate; mark the attempt `voided` (an
  authorization existed) or `abandoned`. If PayPal cannot be read, or a void cannot be confirmed, the
  attempt becomes `unresolved` and the spend and the mandate stay reserved, because money might be
  held; `recover` settles it when PayPal answers. A crash that skips cleanup leaves the attempt
  `reserved`, `order_created` or `authorizing`, and `recover` handles those too.
- **Outcome unknown.** A create that fails after the client's three attempts with the same
  Request-Id is not retried further: no order id is known, an unapproved order is harmless, and the
  attempt is abandoned. An authorize with an unknown outcome is resolved by GET first; if the
  authorization exists it is used, otherwise one more attempt with the same Request-Id replays the
  first result if it lands late. A void is always followed by a GET. No path issues a second
  authorization or order for a checkout.
- **Cassettes.** Only the redirect happy path is recorded from the real sandbox. A vault id appears in
  request bodies, which the recorder keeps verbatim, and `payment_source` is dropped from responses, so
  the vaulted path is tested against the simulator in `tests/paypal_sim.py`, which models the
  behaviour of section 4. This is a limit of the evidence, not of the code.

### Decision 41: The capture gate claims an attempt before it acts

**Status: confirmed by the owner.**

Resolves: exactly-once capture and void (INV-4, INV-11), and the states the attempt moves through.

- `payment_attempts` gains the states `gating`, `capturing` and `captured` and the columns `capture_id`,
  `receipt`, `gate_code` and `gate_reason` (migration 0004). The path is `authorized`, then `gating`
  (the claim), `capturing` (just before the capture request), `captured`; or `gating`, then `voided`;
  or `unresolved` from either. `captured` and `voided` are final (a trigger enforces it, and that a
  captured attempt names its capture and receipt).
- **The claim** is one conditional `UPDATE ... SET state = 'gating' WHERE state = 'authorized'`.
  Postgres takes the row lock for that statement, so of two gates racing on one checkout exactly one
  sees `rowcount == 1` and runs. The other returns `GatePending` and makes no PayPal call. A claim that
  is older than `claim_stale_us` (default 60 s) is taken over with the same kind of statement, which
  also matches the `updated_us` the taker saw, so two takers cannot both win.
- **A takeover starts again from G-FETCH.** It finds either an authorization that is still `CREATED`
  (and captures with the same deterministic Request-Id, Decision 19) or one PayPal shows captured. In
  the second case G-STATUS fails and the fail path (Decision 43) settles it as captured by reading
  PayPal: it finalizes the books and never captures again. A capture is therefore issued at most once
  per authorization even across a crash; the Request-Id covers the case in which the first request
  landed but its answer was lost.
- **`recover(older_than_us)`** settles attempts a crash or an unreadable PayPal left behind
  (`authorized`, `gating`, `capturing`, and `unresolved` ones the gate marked). It never captures. A
  captured authorization is finalized, an uncaptured one is voided (the safe end), a voided one is
  released, and an unreadable PayPal leaves the attempt `unresolved` with everything reserved.
- A repeated call for a finished attempt returns the stored result (`captured` or a gate-voided
  attempt) without calling PayPal.

### Decision 42: What each gate step reads, and where the signed terms come from

**Status: confirmed by the owner.**

Resolves: the sources of G-MANDATE, G-BUDGET and G-TERMS, which the architecture left open.

- **Stored mandates.** The Credential Provider stores the Payment Mandate token and the Checkout
  Mandate it verified in `attempt_mandates`, in the reservation transaction (insert only). The gate
  runs `verify_payment` on those stored tokens again at capture time, with its own clock and the
  current session checkout. It does not trust a caller for the mandates, and it needs no cache of
  anything. A mandate that expired between authorization and capture fails here.
- **G-MANDATE** (in this order): the stored tokens exist; both chains verify now (expiry, signatures,
  `transaction_id`, payee, amount, currency); neither open mandate (Payment or Checkout) is in
  `mandate_revocations`; the Merchant and the Credential Provider reservations of this checkout are
  both still `reserved`; and the Credential Provider reservation holds the nonce of the closed Payment
  Mandate. `mandate_revocations` is insert only; the Trusted Surface will write it in P3 and the
  gate only reads it.
- **G-BUDGET** locks the open mandate's row, reads the spend view WITHOUT this checkout's own
  in-flight entry (the evaluator adds this purchase itself, so counting it would count it twice), and
  runs the payment constraint evaluator again. Money captured under the same open mandate since the
  authorization counts.
- **G-TERMS** compares the live order's re-derived terms (Decision 20) with `expected_terms` of the
  session checkout. The session is frozen while it is `complete_in_progress` (an update is refused,
  Decision 38), and the Merchant compared it with the signed checkout when `complete` began (M5), so
  it is the signed checkout. `invoice_id` and `custom_id` are compared on the order and on the
  authorization, each with its own reason.
- **G-STATUS** also fails if the order lists any authorization other than the attempt's, or any
  capture. **G-AMOUNT** compares the authorization and the order amount with the checkout total.
- The first failing step ends the run (INV-10). A raised order therefore stops at G-TERMS, which comes
  before G-AMOUNT, and G-AMOUNT is covered by a test in which only the authorized amount differs.

### Decision 43: The fail path lets PayPal decide what is true

**Status: confirmed by the owner.**

Resolves: what a step failure, an exception or a log failure does (INV-10, INV-12).

- Whatever failed, the next thing the gate does is read PayPal: the order and every authorization it
  lists. Then, per authorization: `CAPTURED` or `PARTIALLY_CAPTURED` (the attempt's own) is settled as
  captured by reading the capture (Decision 44), never voided (PayPal refuses it:
  `PREVIOUSLY_CAPTURED`); `CREATED` or `PENDING` is voided and the void is confirmed by a GET that
  must show `VOIDED` (a void answer can be incomplete); `VOIDED`, `EXPIRED` and `DENIED` need nothing;
  any other status is unresolved. Every authorization on the order is handled, not only the attempt's.
- Only when every authorization is confirmed ended does one transaction void the spend entry, release
  both reservations (the open mandate can be used again with a NEW checkout; this checkout's id, hash
  and nonce stay consumed, Decisions 1 and 2) and mark the attempt `voided` with the failing code and
  reason, and a signed rejection Payment Receipt is returned.
- If PayPal cannot be read, a void cannot be confirmed, or that transaction fails, the attempt becomes
  `unresolved`, the spend entry stays in flight and the reservations stay reserved. No receipt is
  issued: neither "captured" nor "rejected" is known. A later `run` or `recover` settles it by reading.
- A PayPal call whose "started" entry cannot be written to the log is not made (as in Decision 40), so
  with the log down a void is not attempted and the attempt ends `unresolved`; the authorization then
  expires by itself.
- UCP codes: G-MANDATE is `mandate_expired` when the reason says expired, else
  `mandate_scope_mismatch`; G-BUDGET is `mandate_scope_mismatch`; G-LOCK is `mandate_required`; every
  other step is `payment_failed`. The receipt's `error_description` is the fixed reason.

### Decision 44: Capture, its confirmation, and the receipt

**Status: confirmed by the owner.**

Resolves: what counts as a captured payment.

- The gate captures with the sealed `CaptureApproval` (Decision 19): the whole authorization,
  `final_capture` true, one request. It then GETs the capture and the authorization. Success needs the
  capture `COMPLETED`, `final_capture` true, an amount equal to the checkout total, the approved
  `custom_id` when the capture reports one, and the authorization `CAPTURED`. Anything else is not
  success: the fail path reads PayPal and, since the authorization is captured, ends `unresolved`
  (`G-CAPTURE`), keeping the money reserved. It is never voided.
- A capture request that fails with a definite refusal (for example the authorization was voided) and
  leaves the authorization uncaptured takes the normal fail path and voids. A capture whose answer was
  lost is confirmed by reading PayPal.
- Books are finalized in one transaction: spend entry to `captured`, both reservations `consumed`,
  attempt `captured` with the capture id and receipt, and a `gate.captured` log entry. If that
  transaction fails the attempt is `unresolved` (`bookkeeping_failed`) and a retry finishes it without
  capturing again.
- **Success Payment Receipt** (`ap2/schemas/ap2/payment_receipt.json`, type `payment-receipt+jwt`):
  `status` `Success`, `iss`, `iat`, `reference` (the digest of the closed Payment Mandate),
  `payment_id` (the checkout id), `psp_confirmation_id` (the PayPal capture id) and
  `network_confirmation_id`. PayPal is a closed-loop PSP here and reports no separate network
  transaction reference to this client, so `network_confirmation_id` repeats the capture id. **To
  confirm.**
- `ABL_NO_GATE` skips every step and captures the amount the authorization states, through the same
  sealed approval, confirmation and bookkeeping. It is the naive baseline, refused when
  `APP_ENV=demo` (`countersign.ablations`). With it, an order raised after approval is captured at the
  raised amount (tested), and the spend entry keeps the reserved amount, which is one of the ways the
  baseline's budget is wrong.

### Decision 45: UCP complete with the gate

**Status: confirmed by the owner.**

Resolves: what the final response says.

- `CompleteCoordinator` runs the Merchant, the Credential Provider and then the gate. A gate pass
  moves the checkout to `completed`. A gate rejection releases the reservations itself and the
  service cancels the checkout (`checkout_canceled_after_rejection`), as for any rejection after the
  single-use keys were spent. An unresolved payment leaves the checkout `complete_in_progress` with
  one `payment_failed` error ("could not be confirmed yet"); a later `complete` calls the gate again,
  which settles by reading PayPal. A concurrent complete is told `complete_in_progress`.
- A completed checkout carries `order` (UCP `order_confirmation`): `id` is the checkout id and
  `permalink_url` is the checkout resource URL. The service keeps no separate order record, so the
  order is derived and appears on every later read. The PayPal order and capture ids are in the
  receipt and the log.
- The response carries the signed Payment Receipt in `ap2.payment_receipt` on the complete that
  captured. It is outside `merchant_authorization` (which excludes `ap2`) and is a JWS of its own. The
  UCP extension defines no slot for receipts, so these members are a Countersign extension (the
  vendored `ap2` object schema allows other members). The same response carries `ap2.checkout_receipt`,
  a Success Checkout Receipt issued by the Merchant role when the order completes
  (`CheckoutMandateVerifier.completion_receipt`): `reference` is the digest of the closed Checkout
  Mandate (as at acceptance) and `order_id` the checkout id. The receipt returned at acceptance goes
  only to the first `complete`, which cannot carry it when a payer approval comes first, so this one
  is issued again from the stored mandate. It is a new receipt with a later `iat`, not the same JWS.
- Without a configured gate the payment stays authorized and in flight (nothing is captured).

### Decision 46: The principal lock as the gate sees it

**Status: confirmed by the owner.**

Resolves: G-LOCK before the lock exists.

- `LockPolicy` is a Protocol in `gate/policy.py`: `check(LockQuery) -> LockDecision`. The default
  policy denies everything. A policy that raises, or returns anything but a `LockDecision`, is a denial.
  The gate imports neither `lock/` nor any protocol adapter (import guard test).
- The provisional adapter that first answered G-LOCK (a `# SHORTCUT:` that only checked that a mandate
  chain was stored) is removed. `GateLockAdapter` (in `countersign.completion`, the composition root)
  now answers it from the principal lock ([Decision 49](#decision-49-entry-points-and-the-ucp-signals)).

### Decision 47: Where the customer id comes from

Resolves: gap 12 (principal identity) and the principal of Decision 40 (the agent key thumbprint
stood in for it).

- **Source.** The customer id is the `sub` claim (RFC 7519) of the issuer-signed JWT of link 0 of a
  mandate: the JWT the trusted platform provider signs ([Decision 5](#decision-5-trusted-platform-provider-with-a-device-consent-signature)).
  `verify_chain` has already verified that signature, and a top-level claim is not selectively
  disclosable, so a verifier sees it without help from the agent and the agent cannot alter or withhold
  it. The principal is `(customer id, thumbprint of the key in the open mandate's cnf)`. Code:
  `mandates.customer_id_of`, `lock.principal_from_chain`.
- **Validity.** A `sub` counts only if it is a printable, trimmed string of 1 to 128 characters.
  Anything else is "no customer id". When the Payment Mandate and the Checkout Mandate both name one
  they must agree (`VerifiedPayment.customer_id`); if they differ the customer is unknown.
- **Unknown is never unlocked.** A principal without a customer id is matched on its known parts. When
  the merchant policy requires AP2 for the total, or the lock that matched names a customer, an
  unknown customer is denied (`denied:customer_unknown`). With the policy off and no lock that names a
  customer, it is treated like any principal whose lock requirement is only the mandate.
- **Alternatives considered.**
  1. *A member inside the selectively disclosable open mandate content.* It is inside AP2's content
     model, but the agent decides what to disclose, the strict content rules would need an extension,
     and it is a Countersign member in a standard credential. Rejected.
  2. *The customer id of the Trusted Surface consent record* ([Decision 5](#decision-5-trusted-platform-provider-with-a-device-consent-signature)).
     It is the right root but it is not carried in the mandate, so a verifier would need a lookup by
     device key at every request. Rejected for the hot path; the consent record stays evidence.
  3. *The agent key thumbprint only* (the status quo). It cannot tell two customers of one agent apart,
     and a Human Present mandate has no agent key. Kept as the fallback half of the principal.
- **Consequence for the build (superseded by [Decision 82](#decision-82-the-sub-claim-is-mandatory)).** The
  platform provider (the Trusted Surface backend) now writes `sub` on every mandate it issues, and a
  mandate without a usable `sub` is refused by `verify_chain`; the sub-less leniency and L19 are gone. The
  vault principal of Decision 40 is still the agent key and moves to the pair in P3.4 (L32).

### Decision 48: The shared lock function and the merchant policy

Resolves: what "locked" means and what the policy can say.

- **One function.** `PrincipalLock.decide(LockRequest) -> LockVerdict` holds all the logic. A request
  has an operation (`create`, `update`, `complete`, `capture`), the checkout id, a `Principal` or none,
  `negotiated_ap2`, `mandate_valid` and the total. It has no protocol and no session field, so the lock
  cannot key on either (INV-5); the two "key uses protocol" and "key uses session" mutations are
  therefore only expressible as a changed key, which the tests catch.
- **Order.** Read the policy (unreadable or hash mismatch denies); if AP2 is in use and the principal is
  known, record the lock; a mandate is required when this session negotiated AP2, the principal is
  locked, or the policy requires AP2 for the total; create and update need the capability, complete and
  capture need a valid mandate; the decision is logged before it is returned and a log failure denies.
- **Matching.** A lock matches a principal when the known customer and the known agent parts agree
  (an unknown part matches anything) and at least one known part is equal. So an agent key alone and a
  customer alone (Human Present) both find the lock, and two customers sharing an agent do not share
  a lock. A lock is in force when the newest event for its exact key is `lock`.
- **Storage** (migration 0005): `lock_policies` (versioned, hashed, insert only) and `lock_events`
  (insert only). The runtime role has SELECT and INSERT only. Recording takes a transaction-level
  advisory lock on the key and inserts only if the newest event is not already a lock, so parallel
  negotiations leave one event; the record and its log entry are one transaction.
- **Policy** is pure data: `off`, `all`, or `over_threshold` with a threshold in integer minor units
  and a currency (INV-9). Over means strictly above. A total that cannot be compared (another
  currency, or none) counts as over. The unmandated cap and velocity limits are not built.
- **Unlock** is the merchant action `PrincipalLock.unlock`: a new policy version, an `unlock` event and
  a log entry in one transaction. No protocol adapter or HTTP route reaches it.
- **Privacy of the log.** Lock entries record whether a customer and an agent were known, never the
  customer id or the thumbprint.

### Decision 49: Entry points and the UCP signals

Resolves: how the UCP adapter, which does not fetch platform profiles (L11), takes part.

- **Enforcement points**, all calling `decide`: UCP create and update in `UcpService`; UCP complete in
  `CompleteCoordinator` (once before the Merchant when no mandate was presented, once after the
  Merchant accepted, with the principal named by the verified chain, releasing the Merchant
  reservation on a denial); the capture gate through `GateLockAdapter`, built at the composition root
  because the gate may not import the lock. The Credential Provider never authorizes without a
  verified mandate, which is the same requirement. The adapter reads `verdict.allowed` and nothing
  else (a test checks the adapter source for lock internals).
- **Two request headers**, a Countersign extension: `Countersign-Delegation` carries an open Checkout
  Mandate that names the principal (verified against the one trusted platform key, unexpired; anything
  that does not verify names nobody), and `Countersign-Capabilities` lists the capabilities the agent
  negotiated. `dev.ucp.common.payment.ap2_mandate` there counts as negotiating AP2. UCP does this by
  profile; this server fetches none, so the header stands in for it. Identity and negotiation are
  separate on purpose: an agent that identifies itself but does not negotiate AP2 is the new-session
  escape, and is denied when its principal is locked.
- **Lock on negotiation.** A create (or update, or complete with a mandate) that shows AP2 in use for a
  known principal records the lock before the decision is returned, so a later checkout by that
  principal on any protocol or session is processed under it.
- **What it cannot do.** An agent that sends no delegation is unidentified. The lock cannot apply to
  it; only the merchant policy can (`all`, or over the threshold). That is the stated limit of the
  design ([LIMITATIONS.md](LIMITATIONS.md) L20). The ACP adapter (P2.7, [Decision 51](#decision-51-the-acp-agent-identity-is-the-ucp-delegation-header)) reads the same
  headers and calls the same function; the test-only second entry point of the lock tests remains as a
  unit-level check.
- **Denial** is the UCP code `mandate_required` for every lock reason (the reason is in the log and, for
  the gate, in the receipt). A denied create returns an error response with no resource.

### Decision 50: Ablation and failure

- `ABL_NO_PRINCIPAL_LOCK` (refused when `APP_ENV=demo`) records nothing and ignores stored locks: only
  the session that negotiated AP2 is protected. With it on, a second session or a second protocol path
  without a mandate gets through to the point where the Credential Provider or the gate would run; with
  it off it is denied with `mandate_required`. Tested both ways.
- A store that cannot be read, a policy whose hash does not match its row, an exception, or a log
  that cannot be written all deny (INV-10, INV-12). A lock recorded in a transaction whose log entry
  fails is not recorded.

### Decision 51: The ACP agent identity is the UCP delegation header

Resolves: how an ACP request names its principal (architecture 5.7: "a documented Countersign agent
identity header").

- ACP defines no agent identity that Countersign can verify (its `Authorization` bearer names an API
  client, not a customer). The ACP adapter therefore reads the same two request headers as the UCP
  adapter ([Decision 49](#decision-49-entry-points-and-the-ucp-signals)): `Countersign-Delegation` (an
  open Checkout Mandate naming the principal) and `Countersign-Capabilities` (AP2 negotiated when it
  lists `dev.ucp.common.payment.ap2_mandate`). Both are a **Countersign extension**, not part of ACP.
- Both adapters hand the header to `PrincipalLock.principal_from_delegation`, so the same delegation
  gives the same `Principal` whatever the protocol. The ACP adapter decides nothing itself: it builds a
  `LockRequest` and reads `verdict.allowed`, at create, update, complete and for delegated payment.
- Consequences, as on UCP: an agent that presents no delegation is unidentified, and only the merchant
  policy reaches it ([LIMITATIONS.md](LIMITATIONS.md) L20). A principal that negotiated AP2 on UCP is
  denied on a new ACP session that does not negotiate it (the new session escape and the protocol
  downgrade), and negotiating on ACP records the same lock. **For the owner to confirm.**

### Decision 52: ACP request and response mapping

Resolves: field, status and money mapping, checked against the vendored OpenAPI and JSON Schema
(`spec/vendor/acp/spec/2026-04-17`).

- **Paths and verbs** as the OpenAPI: `POST /checkout_sessions` (201), `GET` and `POST
  /checkout_sessions/{id}` (update), `POST .../complete`, `POST .../cancel` (405 when not cancelable),
  `POST /agentic_commerce/delegate_payment`. Every POST needs `Idempotency-Key` (400
  `idempotency_key_required`, the text of the vendored example). An `API-Version` other than
  `2026-04-17` is refused.
- **Request bodies** have `additionalProperties: false`, so an unknown top-level member is
  `invalid_field`. Create requires `line_items`, `currency` and `capabilities`. The published `Item` is
  `{id, name, unit_amount}` with no `quantity`, although its description and the OpenAPI examples use
  one: **an integer `quantity` (default 1, at most 99) is accepted as the single extension**, a
  fractional or boolean value is refused (whole items only). `unit_amount` is integer minor units
  (INV-9) and is compared with the catalog price and refused on a difference; prices and names always
  come from the catalog. Coupons and discount codes are refused. More than 20 lines is `line_limit`.
- **Responses** are `CheckoutSession` with the required members `id`, `status`, `currency`,
  `line_items`, `totals`, `fulfillment_options`, `messages`, `links`, `capabilities`, plus `protocol`
  and RFC 3339 timestamps. Amounts are the canonical integers. The currency is written in lower case
  as in the vendored examples. `Total` types are the canonical ones (all are in the ACP enum). Status:
  `ready_for_complete` is `ready_for_payment`; the other lifecycle names are equal. A completed session
  carries `order` (`id` and `checkout_session_id` are the session id, `permalink_url` its URL).
- **Same canonical model.** Lines are priced from the catalog with `Checkout.from_lines` and numbered
  `li_1`, `li_2` as on UCP; sessions live in the same table (the storage moved to `countersign.checkout`
  so both adapters share it). An equivalent cart has identical canonical bytes and terms hash (500
  example property test). ACP only members are added around the checkout and are not in its bytes.
- **Errors.** `Error` is `{type, code, message, param?}` with fixed text. `type` is `invalid_request`
  (400, 403, 404, 405, 409) or `processing_error` (500). `code` is open in the checkout schema, which
  is where the stable Countersign codes live ([Decision 53](#decision-53-acp-complete-delegated-payment-and-the-unmandated-seam)).

### Decision 53: ACP complete, delegated payment and the unmandated seam

Resolves: what an ACP complete does in `CS_MODE=full`. **Flagged for the owner.**

- ACP's complete carries `payment_data` and no AP2 mandate, so an ACP complete is an unmandated request.
  The adapter asks the shared lock (`complete`, no mandate, the capability header, the total). A
  denial is **403 `Error`, `type` `invalid_request`, `code` `mandate_required`**, `param` `$.ap2`. Nothing
  is reserved, authorized or captured, and the denial is logged before it is returned.
- If the lock does not deny (no lock applies and the policy does not require AP2), the request goes to
  `UnmandatedCompletion.complete`, whose default `DenyUnmandated` returns **403
  `unmandated_checkout_not_allowed`**. Reason: the Credential Provider and the capture gate both require
  mandates, and the unmandated cap is deferred, so there is nothing safe to do with the request. A
  merchant policy that explicitly allows unmandated checkouts does not exist yet; when it does, it is
  another implementation of the Protocol. The adapter accepts only an `UnmandatedDenied` back: anything
  else is an internal error (500), so a permissive outcome needs a deliberate change here.
- **Baseline seam.** The naive baseline (accept the complete without a mandate, authorize and capture
  at once) plugs in at this Protocol; see [Decision 62](#decision-62-the-acp-seam-outcomes).
- **Delegated payment** is rejected and nothing more. `POST /agentic_commerce/delegate_payment` reads
  its body through the strict loader and answers 403: `mandate_required` for a locked principal or a
  require-all policy, `delegated_payment_unsupported` otherwise. The vendored delegate payment `Error`
  has a closed `code` enum that cannot hold either, so this response is outside that endpoint's schema
  and uses the checkout `Error` shape ([LIMITATIONS.md](LIMITATIONS.md) L24).
- **Alternatives considered** for the unmandated case: allow it and let the Credential Provider fail
  later (it would fail with a PayPal-facing error after a reservation was attempted, and turns the
  adapter into a place where "allowed" is decided); allow it under a threshold (the cap is deferred).
  Deny with a documented reason was chosen as the only option that cannot move money.

### Decision 54: Fail closed and logging on ACP

- Any exception in an ACP route becomes a 500 `Error` of type `processing_error`, code `internal_error`,
  with no detail, and is caught in the ACP route so the UCP-shaped global handler never answers for ACP.
- State changes append their log entry in the same transaction (`acp.session_created`,
  `acp.session_updated`, `acp.session_canceled`, `acp.session_expired`); denials append
  `acp.create_denied`, `acp.update_denied`, `acp.complete_denied` or `acp.delegated_payment_rejected`
  before the answer. A failed append fails the request and, for a create, leaves no session.
- The lock additionally logs its own `lock.decision` for every ACP decision.

### Decision 55: A verified webhook is a hint, never a source of truth

Resolves: INV-7 and INV-10 for webhooks. **For the owner to confirm.**

- Order of work in `POST /webhooks/paypal` (`countersign.webhooks`): read the body with a 64 KiB limit and
  the strict JSON loader (INV-8); require the five signature headers (`PAYPAL-TRANSMISSION-ID`, `-TIME`,
  `-SIG`, `PAYPAL-CERT-URL`, `PAYPAL-AUTH-ALGO`); ask PayPal's `verify-webhook-signature`; only then
  dedupe and work. The verify request carries the notification bytes unchanged (they are embedded, not
  re-serialized, because PayPal's check is over those bytes) and the webhook id from `PAYPAL_WEBHOOK_ID`.
  `verification_status` `SUCCESS` is genuine, `FAILURE` is not, anything else is an error.
- **Answers.** 200 verified and accepted (including a duplicate, an event for something we do not know,
  and a verified type we do not act on, so PayPal does not retry them for days); **400** malformed
  headers or body (nothing could be checked); **401** unverified (a `FAILURE`, an empty webhook id, or a
  certificate URL that is not on `paypal.com`); **503** PayPal could not be asked, or the gate is
  working on that attempt, so PayPal delivers again; **500** internal error or a log failure, so PayPal
  delivers again. 401 rather than 403: the sender is not authenticated. 400 for shape, 401 for
  authenticity, so the log can tell a broken sender from a spoofer.
- Every refusal appends `webhook.rejected` (reason, status, and the event id only if it is a plain
  token), never a body or a header. If that append fails the answer is 500.
- **The body is a hint.** The event type and one id are read to choose which PayPal resource to read
  again. The attempt is found from our own records (`payment_attempts` by authorization, capture or
  order id; for a capture we did not make, by the `up` link of PayPal's own capture record). The ledger
  is then reconciled from `GET` of the order, with our credentials, by a pure function
  (`webhooks.reconcile.plan`) of the attempt's recorded state and that fetched state. An amount, a
  status or an order id in the body is never read. A webhook cannot capture, void, authorize or refund:
  the module references none of those client methods (import guard test) and every webhook test asserts
  zero money moving requests.
- No local secret comparison exists (the signature check is PayPal's), so there is no constant-time
  comparison to make. The webhook id is configuration, empty by default, and an empty id means every
  event is unverified.

### Decision 56: Dedupe and idempotency

- `webhook_events` (migration 0006) has the PayPal event id as its primary key. The handler inserts the
  row (`ON CONFLICT DO NOTHING`), locks it, does the work, marks it `done` or `ignored`, appends
  `webhook.processed` and commits, all in one transaction. A parallel delivery of the same id waits on
  the key and then finds the row finished, so 20 at once apply once; a crash or a raised error rolls the
  row back with the work, so PayPal's retry starts clean. A trigger lets a row move only from
  `processing` to a final state.
- `unknown_resource` and `unhandled_type` events are recorded as `ignored` and answered 200.
- Verification is done before the row is claimed, so an unverified sender cannot claim an event id.
  (A flood of unverified requests costs one PayPal call each; there is no rate limit yet,
  [LIMITATIONS.md](LIMITATIONS.md) L26.)

### Decision 57: Reconciliation rules

Add-only accounting ([Decisions 2 and 33](#decision-2-strict-single-use-and-add-only-budget)); every rule
is a function of the fetched order, so out-of-order, late and repeated events converge.

- **Void or expiry before capture** (`authorized` attempt, own authorization `VOIDED`, `EXPIRED` or
  `DENIED`, no capture): the same release as the gate's fail path, in the event's transaction: the spend
  entry voided, both reservations released (the open mandate can be used with a new checkout), the
  attempt `voided` with code `W-VOID` and no receipt. A later `complete` finds a gate-voided attempt and
  rejects cleanly.
- **Capture present** on an `authorized` attempt, or any gate-`unresolved` attempt with a capture or an
  ended authorization: the handler asks the gate to settle (`CaptureGate.settle`), after the event row
  commits. The gate reads PayPal itself and finalizes, so the Success receipt, the spend capture and the
  consumed reservations come from the same code as the normal path. The handler asks only when its own
  read shows the authorization already captured or ended, so the gate has nothing left to void.
- **Capture completed** on an attempt the gate already captured confirms it: no change.
- **Refund after capture**: `refunded_minor` rises to the sum of `COMPLETED` refunds PayPal reports
  (capped at the capture) and never falls; a captured entry stays captured, so the spend view and the
  headroom do not change. A `PENDING` refund is not counted until it completes. (`payments.refunds` on
  an order is documented by PayPal and has not been observed here.)
- **Reversed, denied, declined capture** on a captured attempt: recorded in the log entry
  (`anomalies`), no ledger change (money that was spent stays spent in the budget).
- **Unknown order or authorization**: logged, ignored. **Attempt `gating` or `capturing`**: 503, not
  recorded, so PayPal redelivers once the gate is done. **Attempt unresolved by the Credential
  Provider** (not the gate): ignored; the Credential Provider's recovery owns it.
- Not done: a webhook that arrives for an `authorized` attempt whose authorization PayPal still shows
  open changes nothing (`authorization_still_open`); only the gate or `recover` ever voids.

### Decision 58: Settling after commit, and what is lost if that fails

The settle request runs after the event's transaction commits, because the gate takes its own locks on
the attempt. If the process dies between the commit and the settle, the event is recorded as processed
and the settle is not repeated by PayPal. The attempt stays `authorized` or `unresolved` with its money
reserved, and `CaptureGate.recover` (which reads PayPal and never captures) finishes it
([LIMITATIONS.md](LIMITATIONS.md) L26).

### Decision 59: The baseline definition

**Flagged for the owner.** Resolves: what `CS_MODE=baseline` is, so the comparison with `full` is
fair. Baseline is our model of a careful but conventional AP2 aware gateway, not a competitor product
([LIMITATIONS.md](LIMITATIONS.md) L27). It is **not** a strawman: it verifies what a good integration
verifies, and it fails only at the places this project adds something.

**What baseline still does, exactly as `full` does:** the Merchant's verification of the Checkout
Mandate (signature chain, `vct`, `checkout_hash`, terms equal to the session, constraints, expiry), the
Credential Provider's verification of the Payment Mandate (chain, binding to the same checkout, amount
and payee constraints), the UCP Security Lock inside the session that negotiated AP2, signed
`merchant_authorization`, idempotent PayPal calls, the decision log, and the cleanup of a failed
authorization. A forged, expired, wrong `vct` or hash mismatched mandate is refused in baseline
(`tests/integration/test_modes.py`).

**What baseline omits, each with the reason a careful integration would plausibly do the same:**

| Omission | Why a careful integration would plausibly do this |
| --- | --- |
| No capture gate: capture right after authorization, for the amount PayPal reports on the authorization, booked from the capture response | The mandates were verified at `complete`, PayPal authorized exactly what it was asked, and a second verification pass looks redundant. This is the normal "authorize, then capture" flow |
| No live re-derivation of the order, no read of the capture | The order was created by this same service a moment ago; re-reading it looks like paying for a read to confirm one's own write |
| No pre-authorize check (the order is not re-derived between payer approval and authorize) | The order is the service's own, and nothing in AP2 or UCP says an order can change between approval and authorization |
| No principal lock: the UCP lock still covers the session that negotiated AP2, a new session or a second protocol is judged on its own | UCP's Security Lock is defined per session. A merchant that adds ACP wires it up like any other protocol |
| ACP complete without a mandate is accepted: the order is created, the payer approves (or a vaulted wallet is charged), then it is authorized and captured | ACP has no mandate slot, so a conventional ACP integration charges the buyer. Payer approval is obtained exactly as the Credential Provider obtains it: a vault entry for the principal (the agent key thumbprint) means create and authorize in one call, otherwise the answer carries the PayPal approval link and a later complete, after the payer approved, authorizes and captures. Nothing charges without one of the two. The ACP `payment_data` token is ignored (delegated payment is not implemented, Decision 53) |
| Budgets come from a persistent local counter in the service's own database, built from its own authorizations and captures. Nothing is reconciled with PayPal: webhook reconciliation is not installed, so an external void, refund or capture is not seen | AP2 evaluates a constraint against the presentation in hand, and a cumulative budget needs a state source. The obvious one is the service's own record of what it authorized and captured. Reading PayPal back to correct that record is the extra step (N4) |
| Single use memory is per session: a nonce, a checkout hash or an open mandate seen in another session is not remembered | Replay protection is usually a nonce cache or a "seen" flag on the session being completed. A global registry across sessions is the extra step |
| Request bodies are parsed by Python's own JSON parser (a duplicate key keeps the last value) | It is what every framework does by default. Signed material (mandates, receipts, the merchant authorization) is still read strictly, because a signature check is not a place to be lenient |

**What that means in the matrix** (`tests/vectors/behavior_matrix.json`): baseline differs from `full`
in exactly six of eleven scenarios: a nonce replayed in a new session, an order raised while
approved, an order whose items were changed while approved, an ACP complete without a mandate by a
locked principal, duplicate JSON keys, and a budget split across sessions. The split is **refused in
baseline too** (by the local budget counter, one stage later than in `full`, where the open-mandate
rule refuses it first), so no money moves; it still differs from `full` in where and how it is refused.
This result stands: baseline was not weakened to make the split succeed (changed in P2.10, Decision 63). It does not differ for a
forged or expired mandate, a mandate for another amount, or the first checkout's mandates presented
for another checkout, because baseline verifies in session.

**Where it lives.** `src/countersign/degraded/` (`immediate_capture.py`, `unmandated.py`,
`lenient_json.py`), imported only by the composition root (Decision 61). Baseline keeps the same
Postgres tables as `full`; it differs in the objects it is given.

### Decision 60: What each ablation switches off

(Revised in P2.10 by [Decision 63](#decision-63-the-baseline-budget-is-a-persistent-local-counter).)

**Flagged for the owner.** Each ablation changes one thing in `full`; refused when `APP_ENV=demo`.

| Flag | What it does | What it reopens on its own (matrix) |
| --- | --- | --- |
| `ABL_NO_GATE` | Existing (Decision 41): the gate skips its checks and captures what the authorization says | Nothing: the pre-authorize check stops every order change in the matrix first |
| `ABL_NO_PREAUTH_CHECK` | Existing (Decision 11): the order is authorized without being re-derived | Nothing is captured: the gate catches it, voids the authorization, and the answer is `payment_failed` instead of `mandate_scope_mismatch` |
| `ABL_NO_PRINCIPAL_LOCK` | Existing (Decision 50) | The ACP complete reaches the unmandated seam, which in `full` still denies (`unmandated_checkout_not_allowed`): the code changes, no money moves. With baseline's permissive seam it is the downgrade |
| `ABL_NO_GLOBAL_NONCE` | Single use memory per session (nonce, checkout hash, open mandate in flight), as in baseline. The checkout id stays unique | A nonce replayed in a new session passes. A budget split is still refused, one layer later, by the budget counter |
| `ABL_NO_BUDGET_RECON` | The webhook reconciliation is not installed, so the local budget counter is never corrected from PayPal (external voids, refunds and captures are not seen). The counter itself is the same Postgres ledger | **Nothing, alone,** and not with `ABL_NO_GLOBAL_NONCE` either: the counter still refuses the split (`test_the_budget_counter_refuses_the_split_even_with_every_single_use_rule_off`). What reconciliation adds is accuracy against events that happen outside Countersign, not protection against an agent |
| `ABL_NO_STRICT_JSON` | The request body parser is Python's. Only the UCP and ACP request bodies; signed material stays strict | A body with a duplicate key is accepted, the last value wins |

Combined: with `ABL_NO_PREAUTH_CHECK` and `ABL_NO_GATE` both set, a raised order is captured at the
raised amount (the two layers are independent; `test_modes.py`).

### Decision 61: Mode selection, labelling and the composition root

**Flagged for the owner (the INV-4 line).**

- `RuntimeSettings.from_env` (`src/countersign/runtime.py`) reads `CS_MODE` (exactly `full` or
  `baseline`, default `full`), `APP_ENV` and the flags. Anything else, an ablation with
  `APP_ENV=demo`, or an ablation with `CS_MODE=baseline`, raises `ModeRefused`. `countersign.main.create`
  does this first, before a key, the database or PayPal is touched, so the process does not start.
- Baseline is allowed in demo (the side by side comparison needs it), must be named, is logged at
  warning level at start, appears in `GET /health` (`mode`, `app_env`, `ablations`) and in the
  `X-Countersign-Mode` header of every response, including the catch-all 500. Active ablations add
  `X-Countersign-Ablations`.
- `src/countersign/composition.py` is the only place that turns settings into collaborators. The
  invariant modules take injected objects (a reservation store with `session_scoped`, a spend ledger
  with `reconciled`, a capture stage, a lock with ablations, a JSON loader, an unmandated seam) and
  never read the mode; a test fails if one mentions it. `countersign.degraded` is imported only
  there and only inside the branches that need it (`tests/unit/test_degraded_import_guard.py`); a
  test builds `full` with every degraded constructor patched to fail.
- **INV-4 and the capture surface.** Baseline captures without the gate by definition. The capture
  surface tests (`test_capture_surface.py`, `test_gate_import_guard.py`) now also allow
  `countersign/degraded/` to build a capture approval and capture. This is the one recorded exception
  to "no capture without the gate": it is unreachable in `full` and is what the evaluation compares
  against. The mint and the client's own checks (status, expiry, invoice id, custom id, and an
  authorization amount equal to the approved amount) are unchanged; baseline approves the amount
  PayPal reports.
- **Two instances side by side.** `make dev-pair` (`scripts/dev_pair.py`) creates two databases
  and two login roles on the compose Postgres, migrates each, and starts a full instance on `:8000`
  and a baseline instance on `:8001`. No row, reservation or log entry is shared.

### Decision 62: The ACP seam outcomes

**Flagged for the owner.** Widens Decision 53's "the adapter accepts only an `UnmandatedDenied`".

- `UnmandatedCompletion.complete` may return `UnmandatedDenied`, `UnmandatedApproval(url)` or
  `UnmandatedPaid(order_id, capture_id)`. Anything else is still an internal error (500).
  `DenyUnmandated` (the default) returns only denials, and `resumable` is `False`, so in `full` a
  session that is `complete_in_progress` is still a 409.
- `UnmandatedApproval` moves the session to `complete_in_progress` and puts the PayPal link in
  `continue_url`. `UnmandatedPaid` moves it to `completed` (through `complete_in_progress`) with its
  order. Both log (`acp.complete_approval_required`, `acp.completed_unmandated`).
- The baseline seam keeps its pending orders in process memory (`# SHORTCUT:`; a restart loses them;
  PayPal's deterministic Request-Ids keep a retry from creating a second order).

### Decision 63: The baseline budget is a persistent local counter

**Flagged for the owner.** Revises Decisions 59 and 60. The first baseline kept a per session spend view,
which made every cumulative budget invisible and was the least defensible omission. Baseline (and
`ABL_NO_BUDGET_RECON`) now keep the same persistent counter as `full`: the `spend_entries` ledger in the
instance's own database, built from the service's own reservations, authorizations, captures and voids.
What they lack is the PayPal side: no webhook reconciliation and no handling of an external void, refund
or capture.

- **Matrix effect.** One cell changed: baseline, `budget_split_across_sessions`, from "completed, two
  captures" to "canceled by the Credential Provider, one capture". Nothing else moved.
- **Honest consequence.** Baseline no longer loses money to a split purchase. The open-mandate rule
  (global in `full`, per session in baseline) and the counter are two layers; baseline keeps one.
  Baseline was not changed to bring the old result back.

### Decision 64: The attack suite, its judge and its determinism

**Flagged for the owner.** Cases are data plus a small function (`eval/core.py`): category, description,
actor, steps, the attacker's success condition and the expected outcome per mode. The verdict is never
the case's: `eval/judge.py` reads the PayPal objects the simulator holds and the hash-chained log.
An attack succeeds on a capture for a checkout no mandate covers, a capture above the signed total, of
other goods than signed, or under a `custom_id` other than the recorded evidence reference, a capture
under a void mandate (revoked), a second capture under one single-use key (the open mandate, a closed
nonce), captures above the signed budget, a money-moving PayPal call during input that must not move
money, a capture with no log entry, or a duplicate PayPal order, authorization or capture. Counted
explicitly per case: unauthorized captures and duplicate PayPal objects. A non-money symptom
(`side_effects`, for example an ambiguous body that was accepted) is reported and never counted as
success. Rows carry no identifiers, so two runs of the suite are identical. The suite runs on the
PayPal simulator and the real Postgres; no case needed a new sandbox recording.

### Decision 65: Definitions the cases rely on

**Flagged for the owner.**

- **`consent_missing`.** A well formed mandate chain whose issuer link is signed by a key other than the
  trusted platform key. Reason: the platform signs only after the customer's device key signed the
  consent record ([Decision 5](#decision-5-trusted-platform-provider-with-a-device-consent-signature)),
  so a chain the platform did not sign carries no consent. The device consent signature is not verified
  anywhere yet (the Trusted Surface is P3), so that half has no case. [Decision 47](#decision-47-where-the-customer-id-comes-from)
  (a mandate without `sub`) is a lock question, covered by the lock tests, not by this case.
- **`category_escape`.** Tests the mandate level `checkout.line_items` constraint (an item outside the
  approved list). A merchant level category policy ([Decision 3](#decision-3-line-items-in-the-mandate-categories-in-merchant-policy))
  is deferred, so it is not tested.
- **`order_changed_after_approval`.** The PATCH-while-`APPROVED` path only; a PATCH after authorization
  is rejected by PayPal (section 4.3), so there is no case for it. `custom_id_tamper` and `invoice_id_tamper`
  use the same path before authorize.
- **Weakening a defense.** The case level mutation check runs a case with an ablation (or both layers
  off) and requires the attack to flip. Where a second layer backs the first, one switch reopens
  nothing and the test says so: the principal lock alone is backed by the merchant's refusal of
  unmandated checkouts, and the pre-authorize check alone by the gate.

### Decision 66: A concurrent burst of `complete` voided the winner's authorization (RESOLVED)

**Status: resolved in P2.11a by [Decision 67](#decision-67-ownership-of-a-payment-attempt).** Found by the
attack suite while writing `double_complete_retry`. With ten concurrent completes after the payer
approved, about one run in twenty (both `full` and `baseline`) ended with the authorization voided, no
capture, and one request answering 500.

**The real cause (the hypothesis in the task was refuted in part).** Deterministic `PayPal-Request-Id`s
did not make racers share objects: they are what kept a repeated `authorize` from creating a second
one. The racers shared objects because there is exactly one payment attempt per checkout (a row keyed by
the checkout id), and the Credential Provider's `finish` decided before it claimed. Each racer:

1. read the attempt row (`order_created`);
2. read the live order from PayPal;
3. decided what to do from that read, and only then
4. tried to claim the attempt (`order_created` to `authorizing`).

A request that read the order after the winner had authorized it saw `COMPLETED` instead of `APPROVED`,
treated that as "this order cannot be authorized", and ran the failure cleanup. The cleanup looked up the
authorization from the attempt row and the order, which is the winner's authorization, and voided it. If
the winner had already captured, the void was refused and the cleanup tried to write `unresolved` over a
finished attempt, which the table's guard trigger rejects: that `IntegrityError` was the 500. A second,
related path: a request that arrived while the first was still creating the order saw the attempt
`reserved`, rejected it, and the coordinator released the Merchant's reservation and cancelled a checkout
that was healthy. A third: two requests that both reached the gate after the capture both tried to move
the checkout to `completed`, and the second raised on a transition the lifecycle has no edge for.

So the defect was ownership, not identity: nothing established which request owned the attempt before
one of them acted on it.

### Decision 67: Ownership of a payment attempt

**Flagged for the owner.** One request owns an attempt at a time, and only the owner acts on PayPal
objects, reservations or the attempt's state.

- **Claim first.** `CredentialProvider.finish` claims the attempt with one conditional update
  (`order_created` to `authorizing`) before it calls PayPal or decides anything. The existing
  uniqueness (one row per checkout id, one reservation per checkout) already gives `start` ownership
  from the reserving transaction. The owner gives the claim back (`authorizing` to `order_created`) when
  the payer has not approved yet, so a later call can try again.
- **A request that does not own the attempt does nothing.** It gets `CpInProgress` (a new outcome) and
  makes no PayPal call, writes nothing, voids nothing and releases nothing. This covers a lost claim, an
  attempt another request is creating (`reserved`), and one it is authorizing (`authorizing`).
- **Cleanup is the owner's only.** `_cleanup` takes the states its caller owns (`start` from the
  reservation, `finish` after the claim, `recover` for stale attempts). It refuses to act unless the
  attempt is still in one of them, before any PayPal call; the statement that ends the attempt is
  conditional on the same states, so a release or a rewrite never happens for an attempt that changed
  hands; a failed cleanup records `unresolved` only under the same condition and never raises.
  `recover` is also fenced by the `updated_us` it read: an attempt its owner touched since is left alone.
  These are the same rules for the Merchant reservation (the coordinator releases it only for a
  rejection whose `cleaned` flag says the rejecting call owned and cleaned the attempt), for the CP
  reservation (released inside the owner's cleanup transaction) and for the gate (its own conditional
  claim, unchanged).
- **No schema change and no ownership token column.** Ownership is winning the state transition, which
  the database enforces, plus the guard trigger that makes finished attempts final. A token would add a
  migration for a guarantee the state machine already gives; the fence on `recover` covers the one actor
  that does not win a transition.
- **Idempotency and request ids are untouched.** No `PayPal-Request-Id` derivation changed, so the
  cassettes are valid as recorded. Fail-closed behavior (INV-10) is unchanged: an owner failure still
  voids and releases, an unreadable PayPal still leaves `unresolved`.
- **Late requests.** A request that reaches `_finish_complete` after another ended the checkout reports
  the ended checkout (the completed one, with its receipts) and does not attempt a transition the
  lifecycle does not have.

### Decision 68: What the loser is told

**Flagged for the owner.** HTTP 200, status `complete_in_progress` (a vendored UCP checkout status) with
the message code `complete_in_progress` and severity `recoverable`, the same typed answer the service
already gave while another request was verifying. The decision is logged before the response
(`checkout.complete_in_progress`, INV-12), so a burst of N requests writes N-1 small entries. A request
that arrives after the purchase completed gets the completed checkout. Never a 500. For the baseline's
ACP path, a repeated complete answers with the first result (`completed`).

### Decision 69: How the interleavings are tested

- `tests/interleave.py` holds a request at an exact PayPal call (`PausingTransport`, `Rendezvous`) or
  schedules N request threads one at a time at PayPal-call granularity from a drawn list of picks
  (`TokenScheduler`). No transaction is held across a PayPal call, so a thread never waits on a lock held
  by a thread without the token.
- Three reproductions force the bad interleavings (the stale read, an attempt being created, a late
  loser at the gate). Each fails on the code before this change and passes after it.
- A Hypothesis property (500 examples, `full` and `baseline`, with and without a failing owner, with and
  without a concurrent start) asserts that a non-owner never voids and money stays within the signed total.
- A stress test runs 200 iterations of 10 or 20 concurrent completes over HTTP on Postgres for `full`
  and `baseline`, and for the baseline's ACP path: exactly one order, one authorization and one capture,
  no void, every answer 200, every non-winner `complete_in_progress`.
- The `double_complete_retry` attack case is a real concurrent burst again. It records no winner, only
  what PayPal ended up holding.

### Decision 70: Cancel is refused once a payment attempt exists

**Flagged for the owner.** Sources: UCP `shopping/checkout/index.md` ("Status Values": `canceled` is
"invalid or expired"; the `complete_in_progress` operation table says the Platform must follow the
cancellation race rules, which end with "Cancellation can race completion; the Platform MUST NOT treat
the Checkout as canceled unless the Business reports `status: canceled`"), and the vendored ACP
`openapi.agentic_checkout.yaml` (cancel: 200, or 405 "Not cancelable"). The specs let the Business refuse;
they name no code for it. Decisions 17 and 51 allowed cancel in every non-final status, which left the
hole recorded as L30.

- **Rule.** `countersign.checkout.cancel.cancel_refusal`, called by both adapters under the checkout row
  lock, refuses a cancel when the checkout is `complete_in_progress` OR a payment attempt exists in any
  non-final state (`reserved`, `order_created`, `authorizing`, `authorized`, `gating`, `capturing`,
  `unresolved`), whatever the checkout's status says. The attempt test is the second half on purpose: an
  attempt that outlives its checkout's status is still money held. Before any attempt exists and
  while the checkout is not completing, cancel works as before.
- **What a refusal does.** Nothing but log. It does not void, release, abandon or touch the attempt, the
  reservations or the ledger. The refusal is logged in the same transaction as the decision, before the
  answer (INV-12): `checkout.cancel_rejected` (UCP) and `acp.cancel_rejected` (ACP). ACP logs and
  commits first and raises after, because raising inside the transaction would roll the log back.
- **Answer, UCP.** HTTP 200 with the unchanged checkout (status `complete_in_progress`) and the message
  `complete_in_progress`, severity `recoverable`: the same code the update refusal uses, and "try
  again later" is what it means. A final checkout keeps `checkout_not_cancelable` (unrecoverable) and the
  body is that checkout, so a cancel after completion reports the completed checkout and a cancel after a
  void or rejection reports the canceled one.
  UCP answers a refused cancel with HTTP 200 and the unchanged checkout, so clients must read the status
  and the message, not the HTTP code.
- **Answer, ACP.** 405 (the spec's only "not cancelable" answer) with code `complete_in_progress`, or
  `not_cancelable` for a final session. The ACP error body carries no session, so the final state is
  read with GET; this is the schema, not a choice.
- **Order against a complete.** `complete` moves `ready_for_complete` to `complete_in_progress` under the
  same row lock. A cancel before it wins and the complete is refused as not ready with nothing created
  (a canceled checkout never has a PayPal order); a cancel after it is refused. The database orders them.
- **Same in `full` and `baseline`.** The guard is protocol and mode neutral (INV-5 spirit): it lives in
  the checkout layer, not in the gate, so the baseline has it too. The `cancel_during_completion` attack
  case is therefore blocked in both modes and does not separate them.
- **Baseline ACP.** See [Decision 72](#decision-72-the-baseline-acp-seam-claims-the-session-first).

### Decision 71: G-CHECKOUT, the gate re-reads the checkout under the row lock

**Flagged for the owner.** The second defense, for any path that slips past Decision 70: a cancel
written straight to the store, an expiry (`_open` cancels a non-final checkout past `expires_at`, also
while it is completing), a bug.

- **Step.** A ninth check, `G-CHECKOUT`, after `G-LOCK` (the code is in `STEP_CODES`). It is not a
  separate read followed by a transition: `GateStore.begin_capture` does both in one transaction. It
  reads the checkout row `FOR SHARE`, requires status `complete_in_progress` and `now < expires_at`, and
  in the same transaction moves the attempt `gating` to `capturing`. Only then does the gate mint the
  `CaptureApproval`. The cancel takes the row `FOR UPDATE`, so a cancel that committed first is seen
  here, and one that comes later waits for this transaction and then finds a live attempt and is refused.
  Read outside the lock, there would be a window between the check and the capture.
- **Failure.** Reasons are fixed strings in the log and the receipt: `checkout_missing`,
  `checkout_<status>` (canceled, completed, ready_for_complete, incomplete, ...), `checkout_expired`.
  Any of them is a `GateFailure` and takes the existing fail path (GET, void and confirm by GET,
  release the reservations, signed rejection receipt, attempt `voided`). A missing row fails closed.
  UCP code on the receipt and in the answer: `payment_failed`, unchanged mapping for an unlisted code.
  A lost transition (another gate already holds the attempt) is `GatePending`, as before.
- **The service.** When the gate rejects because the checkout was canceled under it, the checkout stays
  `canceled` and the response carries the gate's messages (`payment_failed`), not "being completed".
- **Not in `baseline`.** The baseline's immediate capture and `ABL_NO_GATE` skip the check: it is a gate
  step. They rely on Decision 70 alone. No new ablation was added.
- **No schema change, no request id change.** The cassettes are valid as recorded. The `checkout_id` of
  the attempt is the checkout id, so the join needs nothing new.
- **Residual: expiry.** An expiry that cancels a completing checkout is caught by the gate if the gate
  runs. If nobody completes again, the authorization is voided by `recover` (L26), which is not scheduled
  until P5.1.

### Decision 72: The baseline ACP seam claims the session first

**Flagged for the owner.** The baseline ACP complete used to read the session without the lock, call the
seam (which creates, authorizes and captures at PayPal) and only then take the lock to move the session
to `complete_in_progress` and `completed`. A cancel committed in between left a capture on a canceled
session, and `_finish_unmandated` raised `InvalidTransition` (a 500). The ACP adapter now claims
`complete_in_progress` under the row lock BEFORE a seam that can pay is called (`resumable` seams, which
is only the baseline's), so Decision 70 refuses the cancel from then on.

- **The claim is never given back.** A seam that raised or denied may already have moved money (an unknown
  capture outcome), and a session that could be canceled again would contradict the books. A denied
  baseline complete therefore leaves the session `complete_in_progress`, which the seam can resume. In
  `full` the seam never pays and nothing is claimed.
- **Repeats.** A repeated complete finds `complete_in_progress` or `completed` and goes to the seam, which
  reports the first result (Decision 63).
- **SHORTCUT, baseline only:** an expiry that cancels the session before `_finish_unmandated` leaves the
  capture standing on a canceled session. The baseline has no gate to catch it ([L30](LIMITATIONS.md)).

### Decision 73: The shared UI has no build step

**Flagged for the owner.** `web/ui/` is plain CSS custom properties, one ES module (`ui.js`) and static
HTML, so any surface (dashboard, Trusted Surface, demo store) can load it with a link and a script tag.
No framework and no bundler. The only addition is a development dependency, `playwright` in
`web/ui/package.json` (and its Chromium download), used only by `web/ui/test/screenshots.mjs` to write
review images to the gitignored `web/ui/.artifacts/`. `pnpm-lock.yaml` changed for it.

### Decision 74: Fonts

**Flagged for the owner.** Newsreader (display headings and large amounts), Instrument Sans (interface)
and JetBrains Mono (hashes, fingerprints, tabular figures), all SIL Open Font License 1.1, the Latin
variable subset only (about 128 KB in total), self-hosted as woff2 in `web/ui/fonts/` with each licence
text beside the files. No remote font service. A test fails if any page names another origin.

### Decision 75: Gallery availability and contrast rules

**Flagged for the owner.** The component gallery is served at `/_ui/gallery.html` only when `APP_ENV` is
exactly `dev` or `eval` (an allowlist: `demo`, an unknown value or an empty one serve nothing). The
contrast test checks the manifest in `tests/ui_contrast.py`: 4.5 for every text pair and badge, 3.0 for
control outlines (`--color-border-strong`) and the focus ring, in light and dark. The decorative
`--color-border` hairline is not a control boundary and is not held to 3.0. The state pills carry a glyph
as well as a tone, so no state depends on colour alone. The tokens that the AG Grid theme will use in P4
are listed in the comment at the top of `tokens.css`.

### Decision 76: The Trusted Surface page is served from an exact allowlist

**Flagged for the owner (approved with the allowlist change).** The Trusted Surface setup page is a
product page, so unlike the gallery (Decision 75, `/_ui`, dev and eval only) it is served in every
mode, including demo. Nothing serves a directory. `api/static_routes.py` holds one table from URL path
to one file and one media type, and registers one route per entry:

- the page: `/approve/` (`index.html`), `/approve/approve.css`, `/approve/app.js`,
  `/approve/device-key.js`, `/approve/messages.js`;
- the shared UI files it needs, under `/ui/` (not `/_ui/`, which stays the gallery mount):
  `tokens.css`, `components.css`, `fonts.css`, `ui.js` and the three `.woff2` fonts.

Everything else, including `/ui/gallery.*`, `/ui/test/`, `/ui/node_modules/`, `/ui/.artifacts/`, the font
licence texts, `/approve/package.json`, `/approve/test/` and any path with `..` (plain, percent-encoded,
backslash, doubly encoded or with a NUL), is a 404 because no table entry matches. A test fails if a file
appears in `web/approve` that is not in the table, or if a table entry has no file. The page is sent with
`Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self';
connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. `/approve` redirects to
`/approve/`. Tests: `tests/unit/test_approve_static.py` (every mode, plus traversal through the ASGI
interface so nothing normalizes the path first).

### Decision 77: Device key enrolment: challenge, proof of possession, tables

**Flagged for the owner.** Refines the "consent signature format" paragraph of Decision 5 for the
registration step only; the consent record itself is still P3.3.

- **Challenge.** `POST /trusted-surface/keys/challenge` with `{"purpose": "register_device_key"}` (the
  only purpose accepted today) returns `challenge_id` (`kch_` plus `token_urlsafe(16)`), a 32 byte
  random `nonce`, the purpose and `expires_us`. A challenge lives 5 minutes. **Expiry is computed from
  the issue time** (`created_us` plus 300 s, expired at exactly that instant) and nothing is ever updated
  to expire it. The runtime database role has SELECT and INSERT only, on every new table.
- **Single use is an INSERT.** Consuming a challenge inserts a row into `key_challenge_uses` whose
  primary key is the challenge id; a unique violation means it was already used (`challenge_used`).
  Of N simultaneous registrations on one challenge, the others wait on the unique index until the
  winner commits and then fail; exactly one wins (tested with 12 threads, with 12 keys and with one key).
  A refused registration rolls back, so it does not spend the challenge.
- **Record the new key signs.** The JCS (RFC 8785) bytes of
  `{"v":1,"purpose":"countersign.device-key.register.v1","challenge_id":...,"challenge":<nonce>,
  "thumbprint":...,"customer_id":<id or null>,"origin":...}`. The `customer_id` member is always present:
  `null` for a new customer, the id when adding a key. The server rebuilds the record from its own
  values and verifies the ES256 signature (raw `r || s`, 64 bytes, canonical base64url, ECDSA over
  SHA-256) over it. A signature made for another challenge, purpose, origin, customer or key does not
  verify (`proof_invalid`).
- **JWK.** Exactly `kty` `EC`, `crv` `P-256`, `x`, `y`: each coordinate the canonical unpadded base64url
  of 32 bytes, the point on the curve. A private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) is
  `jwk_private_member`; any other extra member (`alg`, `kid`, `use`, `key_ops`, `ext`) is
  `jwk_extra_members`; other shape errors `jwk_malformed`; another curve or key type
  `jwk_unsupported_curve`; an off-curve point `jwk_not_on_curve`. The thumbprint is RFC 7638 and is
  computed on the server only (the four members in lexicographic order, which is their JCS form).
- **Origin.** Compared as `(scheme, host, port)` with scheme and host lower-cased and the default port
  filled in, against the origin of `PUBLIC_BASE_URL`. The request `origin` member must match, and so
  must the `Origin` header when the browser sent one (`origin_mismatch`). Anything that is not exactly
  an origin (path, query, fragment, user information, whitespace or control characters) does not match.
  A bad configured origin stops the start.
- **Tables** (migration 0007; 0008 moves revocation out of `customer_keys`). `key_challenges`,
  `key_challenge_uses`, `customer_keys` (customer id, thumbprint primary key, the JWK as JCS text,
  `created_us`). The convention of the other
  tables (`_us` microsecond columns) is kept instead of `created_at`.
- **Revocation (settled in P3.3, [Decision 83](#decision-83-revocation-is-an-insert-only-table)).** An
  earlier draft of this decision gave `customer_keys` a `revoked_us` column that an owner role could set once,
  guarded by a trigger. **That column and that trigger are gone** (migration 0008): a key is revoked when a row
  exists in the insert-only `key_revocations` table, and `customer_keys` has no updatable column and no
  trigger. Its protection is the missing UPDATE and DELETE grant of the runtime role.
- **Logging.** Every refusal is appended to the hash-chained log before the answer (`ts.key.refused`,
  `ts.challenge.refused`), with the code, the thumbprint when it was computed and the challenge id; never
  a request body. A success is logged in the transaction that inserts the key (`ts.key.registered`), so a
  key never exists without its entry. If the log cannot be written the answer is `log_unavailable` (503)
  and nothing was registered.

### Decision 78: Customer identity and the add-only key rules

**Flagged for the owner.**

- A new customer gets `cus_` plus `token_urlsafe(16)` (the convention of `chk_` and `sp_`). This is the
  value that becomes the `sub` claim of the platform issuer JWT (Decision 47, L19).
- **Adding a key to an existing customer** names the customer id and carries the signature of an
  already registered, non-revoked key of that customer over the same record
  (`authorizer: {"thumbprint", "signature"}`): `authorizer_required`, `authorizer_unknown` (not a key of
  that customer), `authorizer_revoked`, `authorizer_invalid`. An unknown customer is `customer_unknown`.
  An `authorizer` without a customer id is `malformed_request`.
- **Same thumbprint twice.** The same customer: an idempotent success that changes nothing (200,
  `new_key: false`) and still spends its challenge. A different customer: `key_conflict` (409). A revoked
  key: `key_revoked`. Keys are never overwritten or deleted.
- **A deliberate extension.** A registration that names no customer for a thumbprint that is already
  registered returns the existing customer (200) instead of a conflict. The signature proves possession
  of that key, the customer id is not a secret, and the browser needs it when a response was lost after
  the registration committed. **For the owner to confirm.**
- Creating a new customer is unauthenticated in this demo (LIMITATIONS L35).

### Decision 79: Where the browser keeps the key, and what it shows

**Flagged for the owner.**

- `crypto.subtle.generateKey` ECDSA P-256, `extractable: false`, usages `sign` and `verify`; the public
  key is exported from the pair as a JWK with only `kty`, `crv`, `x`, `y`. The `CryptoKeyPair` is stored
  with the structured clone algorithm in IndexedDB (`countersign-trusted-surface`, store `device`, key
  `current`) together with the customer id once registered. The private key is never exported, logged or
  sent. `navigator.storage.persist()` is requested and a refusal is told to the user.
- The key is saved **before** the registration is attempted, so a registered key is never lost for want
  of a write, and a registration that fails leaves a saved key that a reload offers to finish.
- On a reload the stored pair is validated (private, non-extractable, ECDSA P-256) and the thumbprint is
  recomputed from the public key; nothing is sent. A stored private key that is extractable or any other
  damaged record is `key_unreadable`.
- A small `localStorage` marker (thumbprint and customer id) lets a later visit tell "never enrolled"
  from "enrolled, key gone" (`key_lost`). It is a hint and is not trusted for anything else.
- **Recovery is a new customer.** A lost or unreadable key cannot sign, so it cannot vouch for a new
  one. Re-enrolment creates a new key and a new customer id; the old key is not usable any more
  (LIMITATIONS L36).
- Every sentence on the page is in `messages.js` as a fixed template. The only service-supplied text is
  the stable error code, shown only if it matches `^[a-z][a-z0-9_]{0,47}$` and otherwise as `unknown`. A
  browser test checks every text node against the templates and that no request leaves the origin.

### Decision 80: Browser tests, the new package and a shared component fix

**Flagged for the owner.** `web/approve` gains the development dependency `playwright` (the version of
`web/ui`; `pnpm-lock.yaml` changed). The browser tests are `web/approve/test/enrol.test.mjs`; they are run
by `tests/integration/test_approve_browser.py`, which starts the real app on a real Postgres on a free
port and runs `node --test`, so they are part of `make test` and `make test-safety`. A missing Chromium
fails the test, it is not skipped. `countersign.trusted_surface` joins the strict typing list and the
safety coverage list. The shared `button()` in `web/ui/ui.js` set `aria-busy=""` instead of `"true"`
when loading; fixed, because the browser test asserts it.

### Decision 81: The consent record and the platform issuer

**Flagged for the owner.** Implements the consent step of Decision 5 (`POST /trusted-surface/consent`,
`trusted_surface/consent.py`, `service.py`, `issuer.py`, migration 0009).

- **The record the device key signs.** JCS bytes of `{v: 1, purpose: "countersign.consent.open-mandates.v1",
  customer_id, device_thumbprint, challenge_id, challenge (the nonce), issued_at, expires_at, origin,
  terms, mandate}`. `terms` is `{merchant {id, name, website}, items [{id, title, quantity}], ceiling_minor,
  currency "USD", mandate_expires_at, agent_thumbprint}`. `mandate` is the contents of the two open
  mandates (`checkout` and `payment`: `vct`, `exp`, `constraints`). Times are integer seconds. The page
  renders the terms from this record with fixed templates and signs the JCS bytes of this same object; the
  object it sends is the object it signed.
- **Nonce.** The existing challenge mechanism with the purpose `consent_open_mandates`: server issued,
  single use (an INSERT into `key_challenge_uses`), 5 minutes from issue. `issued_at` is the server's own
  time at issue (returned with the challenge), so the device clock never matters; `expires_at` is
  `issued_at` plus 300 s and a record may live at most 600 s.
- **What the platform adds after verification** (so the customer does not sign these byte for byte): `iat`;
  `cnf` (the agent's public key, supplied beside the record, whose thumbprint is in the terms and is
  checked); the issuer JWT `sub` (the customer id the device key vouches for); and the `payment.reference`
  constraint, the `sd_hash` of the open Checkout Mandate, which exists only once that mandate is signed.
  Everything else is in the record.
- **The mandates.** Native AP2 constraints only. Checkout: `checkout.line_items` (one requirement per item,
  `acceptable_items` with the catalog id and title, the quantity) and `checkout.allowed_merchants`.
  Payment: `payment.reference`, `payment.amount_range` (`min` 1, `max` the ceiling), `payment.allowed_payees`,
  `payment.budget` (`max` the ceiling) and `payment.agent_recurrence` (`ON_DEMAND`, `max_occurrences` 1, so
  one purchase per consent). Both are validated against the vendored `open_checkout_mandate.json` and
  `open_payment_mandate.json`. Every constraint element is a plain object in the one disclosed content
  element (Decision 84).
- **Verification, each step with a stable code, logged before the answer** (`ts.consent.refused`, with a
  fixed `detail` token and never a request body): the shape of the record (`consent_malformed`,
  `consent_purpose_mismatch`); the origin (`origin_mismatch`); the platform can sign (`signing_unavailable`);
  the challenge exists, has the consent purpose, carries this nonce, is unexpired and unused
  (`challenge_unknown`, `challenge_purpose_mismatch`, `challenge_nonce_mismatch`, `challenge_expired`,
  `challenge_used`); the device key is registered, belongs to the record's customer and is not revoked
  (`device_key_unknown`, `device_key_customer_mismatch`, `device_key_revoked`); the signature verifies with
  the STORED public key, never one from the request (`consent_signature_invalid`); the record's own times
  (`consent_time_invalid`, `consent_expired`); the agent key matches the terms (`agent_key_mismatch`); the
  terms mean something (`consent_terms_invalid`: this store's merchant record exactly, catalog items with
  their catalog titles, no duplicates, 1 to 99 each, ceiling 1 to 1,000,000 minor units, a mandate expiry
  60 s to 14 days away and not before the consent expires); and **the backend's own rebuild of the
  mandate contents from the terms equals the claimed contents byte for byte** (`consent_claims_mismatch`,
  with `detail` naming `checkout`, `payment` or `other`). Only then does the issuer sign.
- **One transaction.** The work holds the per-customer advisory lock (so it serializes with revocation),
  spends the nonce, signs, stores the consent record, its signature, the device public key and both open
  mandates in `consent_records` (insert only, `challenge_id` unique) and appends `ts.consent.issued`
  (digests, never the mandates). A log failure means no mandate and an unspent nonce.
- **The proposal.** The page takes an agent's request from the address, `#intent=<base64url JSON>`
  (never sent to a server). It carries only structured values: item ids and quantities, `ceiling_minor`,
  `currency`, `mandate_expires_at` and the agent's public JWK. **No store name and no item title:** those
  come from `GET /trusted-surface/store` (the store's own merchant record and catalog titles), so no text an
  agent wrote can reach the page (INV-2). A proposal with any other member, an unknown item or a malformed
  value is `intent_invalid` and is not echoed.
- **Platform key.** `PLATFORM_KEY_PATH` now names the platform's ES256 key including its private half
  (`make keys` writes `secrets/platform_es256.jwk.json`). Without a private key the backend refuses to
  consent (`signing_unavailable`), and verification works as before.

### Decision 82: The `sub` claim is mandatory

**Flagged for the owner.** Removes the sub-less leniency of Decision 47 and closes L19.

- `verify_chain` requires, on link 0 (the platform-signed issuer JWT), a usable `sub` read from the **signed
  top-level payload**, never from a disclosure: a string of 1 to 128 printable characters with no leading or
  trailing space (`customer_id_of`). Otherwise `SubjectMissingError`, code `subject_missing`, checked after the
  `vct` (so the older errors keep their order). Key-binding links need none. The Merchant maps it to
  `mandate_invalid_signature` like every other chain failure.
- The shared vectors gained eight cases (a missing, empty, padded, over-long, control-character and non-string
  `sub`; a `sub` that exists only as a selectively disclosable claim; a 128 character one that is valid) and
  were regenerated (152 vectors); the Node cross-check implements the same rule and agrees on all of them.
- The principal's customer id is now always known for a verified mandate. The lock's handling of an unknown
  customer (`denied:customer_unknown`) stays as defence in depth and is exercised at the lock level; it can
  no longer be reached through a verified chain.
- **Tests that relied on the leniency, and what changed.** (1) `test_lock_ucp.py`: "a mandate naming no
  customer is denied and released" became "a mandate with no customer id is refused before anything is
  reserved or authorized" (`mandate_invalid_signature`, no order); the two gate tests that authorized a
  "nameless mandate" and expected `G-LOCK` could not be built any more and became one test that the Merchant
  refuses it with `subject_missing`; the "named mandate still captures" counterparts are unchanged.
  (2) `tests/lock_support.delegation(sub=None)` and `tests/integration/test_ucp_complete.mandates(no_sub=True)`
  now really omit the claim (before, "None" meant "do not add one", and the test issuer added none); the ACP
  tests that pass a sub-less delegation now get a delegation that names nobody, which is what they asserted.
  (3) The test issuer writes a `sub` by default. (4) The two real-sandbox cassettes recorded with sub-less
  mandates (`cp_authorize`, `gate_flow`) cannot replay: `custom_id` derives from the mandate digests, so
  they had to be re-recorded from the live sandbox, which was done. The recording scripts and their fixtures now build
  mandates with a `sub` in the issuer's shape, and void or capture everything they create.

### Decision 83: Revocation is an insert-only table

**Flagged for the owner.** Replaces the owner-trigger design of Decision 77.

- `key_revocations` (migration 0008): `thumbprint` primary key (and foreign key), `customer_id`,
  `signer_thumbprint`, `challenge_id`, `record` (JCS text), `signature`, `revoked_us`. A key is revoked when
  a row exists. SELECT and INSERT only. `customer_keys.revoked_us` and its trigger are dropped; existing
  revocations are copied over first (marker proof `migrated`), and the downgrade restores both.
- `POST /trusted-surface/keys/revoke` with `{challenge_id, customer_id, target, signer, origin, signature}`.
  The signer is a registered, non-revoked key of the same customer and may be the target or another key of
  that customer; it signs the JCS bytes of `{v, purpose "countersign.device-key.revoke.v1", challenge_id,
  challenge, customer_id, target_thumbprint, signer_thumbprint, origin}` over a challenge of purpose
  `revoke_device_key` (single use, 5 minutes). Codes: `customer_unknown`, `signer_unknown`, `signer_revoked`,
  `proof_invalid`, `key_unknown` (also for another customer's key), `origin_mismatch`, the challenge codes.
- **Idempotent.** Revoking a revoked key answers 200 (`new_revocation: false`) and still spends the
  challenge. A revoked key cannot sign, so it cannot repeat its own revocation (`signer_revoked`).
- **Final.** A revoked thumbprint never gets the idempotent re-registration 200 of Decision 78, whether or
  not the request names the customer (`key_revoked`; tested). A revoked key cannot vouch, revoke, or consent.
- **Serialized per customer.** Revocation, adding a key with a voucher, and consent each hold a per-customer
  advisory lock, so two keys cannot revoke each other at once (exactly one wins; the other is
  `signer_revoked`), and a consent cannot commit on a key that was revoked a moment before. Tests hold the
  lock from another connection and require each operation to wait.

### Decision 84: Whole constraint elements are never selectively disclosable (L31, issuer side)

**Flagged for the owner.** `issuer.issue_open_mandate` refuses to sign content in which any element of
`constraints` is not a plain object with a `type`, is a `{"...": digest}` placeholder, or carries `_sd` or
`_sd_alg` (`constraint_element_disclosure`, `constraint_element_not_plain`, `constraints_missing`); it also
refuses content members other than `vct`, `exp` and `constraints`, a `vct` that is not the open mandate's, a
customer id that is empty or padded, and a signing key without its private half. Issued mandates have
exactly one disclosure, the whole content, so a holder can neither withhold nor reorder anything: the digest
of an issued open mandate has one possible serialization. **Re-keying single use, budget and revocation on a
presentation-independent open-mandate identity stays in P3.4.** P3.3 is correct without it for issued
mandates for that reason: there is nothing nested to vary, and an unreferenced extra disclosure is refused by
`verify_chain`. It would matter for mandates not issued here (none are accepted: the platform key is the only
trusted issuer).

### Decision 85: Recording scripts, CI browser and the status of two cassettes

**Flagged for the owner.** `scripts/record_cp_cassette.py` and `scripts/record_gate_cassette.py` build
mandates with a `sub` of the shape the issuer writes (`cus_` plus 22 characters, fresh for each recording) and
leave nothing open in the sandbox: the gate script captures A and the gate voids B; every authorization that
is neither is voided with a client that is not recording, so the cassette holds exactly the calls the replay
makes. No `PayPal-Request-Id` or `custom_id` derivation changed. Both cassettes were re-recorded from the live sandbox with these mandates (2 November 2026) and their
replay tests pass; they are never skipped.
CI installs Chromium with its system libraries (`playwright install --with-deps chromium`, cached) before
pytest, because the browser tests fail, by design, when it is missing.

### Decision 86: Open mandate identity

**Flagged for the owner.** Closes the re-keying of L31. The identity of an issued mandate is `b64url(domain_hash("cs.mandate.identity.v1", JCS({v, iss, sub, iat, vct, sd_alg, delegate: [digests of delegate_payload]})))`, computed by `mandates.mandate_identity` from the verified, issuer-signed payload of link 0 (`VerifiedChain.identity`). Each `delegate_payload` digest covers the salt and the whole disclosed content (`cnf`, `exp`, every constraint), so the identity cannot change without the issuer key and is unique per issuance. It does not depend on the signature bytes, the key binding, the nonce, the checkout or the order of disclosures. The old key (`sd_hash` of the presented serialization) is not stable: an ES256 signature can be rewritten as `(r, n - s)` without the key, which changes the digest and not the mandate. Single use (Merchant, keyed on the checkout mandate identity), the Credential Provider reservation, the budget row (`open_payment_mandates`, keyed on the payment mandate identity), the capture gate and revocation all use it. `payment.reference` still pins the AP2 `sd_hash` of the open checkout mandate as the spec says. An open mandate pair is named by its payment identity; `open_mandates` (migration 0010, insert only) records the pair, customer, agent, ceiling and expiry at consent. Column names `mandate_digest` are kept and now hold the identity (no migration of data; the old digests were never persisted in a way anything else read).

### Decision 87: The agent channel (closes L40)

**Flagged for the owner.** `POST /trusted-surface/proposals` files a proposal (item ids and quantities, ceiling, currency, expiry; structured fields only, items must be in the catalog). The agent signs, with the key it names, a JCS record of purpose `countersign.agent.proposal.v1` over a server challenge (purpose `agent_proposal`). The backend returns `prp_` plus 16 characters; the page loads `GET /trusted-surface/proposals/{id}` (`#proposal=<id>`). Proposals live 15 minutes (computed from `created_us`). Consent now takes `{record, signature, proposal_id}`; the agent key comes from the stored proposal (never the request), the record terms must equal the proposal (`consent_proposal_mismatch`), and the proposal is spent for issuing by an INSERT into `proposal_uses` (primary key = proposal id). The agent collects the mandates with `POST /trusted-surface/proposals/{id}/mandates`, proving the stored key over a fresh `agent_fetch` challenge bound to the proposal id (`countersign.agent.fetch.v1`); `consent_pending` (409) before consent, `proof_invalid` for any other key, `challenge_used` on replay. A proposal id is an address, not a credential: whoever holds it can consent to it as their own customer (L42), and nobody but the agent key can fetch.

### Decision 88: Revocation while a purchase is in flight

**Flagged for the owner.** Revocation is a row in `open_mandate_revocations` (insert only; it replaces the unused `mandate_revocations`, dropped in 0010). It is effective for anything not yet claimed as capturing. `openmandates.revoke_in` takes the open mandate's budget row `FOR UPDATE`, then reads the attempts: `capturing` or `unresolved` (money may be held) answers `in_flight`, `captured` answers `already_used`, both writing nothing; otherwise it inserts the row; an already revoked mandate is an idempotent success. The capture gate takes the same row `FOR SHARE` in the transaction that moves the attempt to `capturing` and re-reads revocations there (`GateStore.begin_capture`, G-MANDATE `mandate_revoked`). Either the revocation committed first and the gate voids, or the gate holds the row, the revoke waits, then sees `capturing` and is refused. A revocation row therefore never coexists with a capture that started after it (tests: deterministic lock-order tests in both directions and a 36-interleaving race). The Credential Provider checks revocation in its reservation transaction (after the row lock) and again before authorizing. A revoke does not void an existing authorization itself; the next gate run does.

### Decision 89: Revocation in baseline, and what the new cases show

The reservation-time check is shared by both modes (a conventional gateway refuses a revoked mandate when it is presented). The pre-authorize check is part of the pre-authorize check that baseline omits (Decision 59), and baseline has no gate. Result (29 cases, `eval/reports/latest.json`): `open_mandate_reuse_new_presentation` blocked in full, succeeds in baseline (baseline's per-session memory also fails the plain reuse, so the case does not isolate the rewritten signature; the unit and Credential Provider tests do). `purchase_after_revoke` and `revoke_during_capture` are blocked in both modes and do not separate them: baseline also moves the attempt to `capturing` before calling PayPal, so the same in-flight rule applies. The existing `mandate_revoked` (revoke before the claim) still separates. Its ablation flip now needs both the gate and the pre-authorize check weakened.

### Decision 90: Human Present approval

**Flagged for the owner.** `POST /trusted-surface/purchases/offer` loads the checkout from the database (never from the client), signs it with the merchant key, verifies its own `merchant_authorization`, builds the terms from the VERIFIED payload and stores the JWT, its hash and the terms (`purchase_offers`, insert only). Nothing is shown before that verification. The page renders the terms with fixed templates. The device key signs a record of purpose `countersign.consent.checkout.v1` (challenge purpose `consent_checkout`, distinct from the open consent) that holds the offer id, the terms and the closed mandate contents. `POST /trusted-surface/purchases/consent` verifies the device key and nonce as in Decision 81, re-reads the checkout (`checkout_not_ready`, `checkout_expired`, `checkout_changed`), re-verifies the stored JWT, rebuilds the terms and the mandate contents itself and requires JCS byte equality with the record (`consent_claims_mismatch`); only then does the platform key sign two single-link closed mandates (Decision 29, `sub` is the customer id, `exp` is the earlier of the checkout expiry and 15 minutes). `purchase_consents` is insert only with unique offer and challenge. The issued mandates verify with the real Merchant and Credential Provider verifiers (test). The page shows the mandates; completing the checkout with them is not part of this step.

### Decision 91: The activity read session

**Flagged for the owner.** `POST /trusted-surface/activity/session`: the device key signs a `countersign.activity.read.v1` record over an `activity_read` challenge; the response is an opaque `ats_` token (5 minutes from `created_us`, computed). Only its SHA-256 is stored (`activity_sessions`, insert only). `GET /trusted-surface/activity` with `Authorization: Bearer` lists the session customer's open mandates with state `unused`, `in_flight`, `used`, `revoked` or `expired` (order: used, revoked, in flight, expired, unused), ceiling, expiry, agent fingerprint and the captured purchase (checkout id, amount, capture id, time). Each use re-checks that the device key is not revoked. The page holds the token in memory only.

### Decision 92: Revoking from the activity screen

**Flagged for the owner.** `POST /trusted-surface/activity/revoke` needs its own device-key signature over `countersign.open-mandate.revoke.v1` (customer, device key, open mandate identity, origin, `revoke_open_mandate` challenge); the bearer token is neither needed nor sufficient. Another customer's mandate answers `open_mandate_unknown`, the same as a missing one. Outcomes follow Decision 88 (`in_flight`, `already_used`, idempotent success). The challenge is spent only on success. Refusals and successes are logged before the answer.

### Decision 93: Tests that changed

Consent tests moved from the request-supplied `agent_jwk` to proposals (`Setup.proposal`; a refused agent key is now a proposal signed by another key, and the old odd-JWK cases moved to proposal creation). `revoke_mandate` takes both identities (six call sites; a test helper `open_identity` recomputes the identity independently). The browser tests file proposals as an agent (`hashFor`), with crafted proposal views served by a route for the cases that test the page's own validation. The attack-suite ablation row for `mandate_revoked` weakens both revocation layers. The "no button on a revoked card" and "which states offer a button" browser assertions count only Take back buttons (the fingerprint Copy button was being counted).

### Decision 94: The model gateway interface

**Flagged for the owner.** `countersign.llm.LlmGateway.complete(LlmRequest)` is the one way to call a model (shopping agent, adversary, Ask Countersign). A request has a task name, system and user text, a JSON schema, a timeout (the total deadline), a maximum output size and a temperature (default 0, optional seed). The result is parsed JSON validated against the schema, still untrusted data. A schema failure retries once with the validator's error appended (path and rule only, never the offending value) and then raises `LlmSchemaError`; an oversized reply raises `LlmOutputTooLargeError` with no retry. The gateway runs no tool or code and acts on nothing found in the text. Validation uses a small built-in JSON Schema subset (`llm/schema.py`, unsupported keywords are an error when the request is built) so the package needs no new dependency; it is checked against the reference `jsonschema` in a test. Errors are typed (`LlmError` subclasses with stable codes).

### Decision 95: The authorization boundary is a test

**Flagged for the owner.** INV-1 is enforced statically by `tests/unit/test_llm_boundary.py`: from the import graph of `src/countersign`, no module of `gate`, `constraints`, `mandates`, `lock`, `trusted_surface`, `openmandates`, `checkout`, `paypal`, `canonical`, `evidence`, `merchant`, `cp`, `mpp` or `ledger` reaches `countersign.llm` directly or through any chain, and `llm` reaches none of them. There is no exception. Consequences: the gateway keeps its own schema validator and its own sorted-key JSON for cassette keys instead of importing `canonical`; the callers (agents, assistant) sit outside both sets and re-validate every proposed value with deterministic code. The test was shown to fail on a violating import (`gate/policy.py`, removed) and has a synthetic-tree test for direct, transitive and reverse violations.

### Decision 96: Providers, limits and the key

One adapter, `OpenAICompatProvider`, for any OpenAI-compatible chat completions endpoint, configured by `LLM_PROVIDER` (a label), `LLM_BASE_URL` (https, or loopback), `LLM_MODEL`, `LLM_API_KEY` from the environment only. `response_format` is `json_schema` (strict), `json_object` (schema also in the system message) or `text`; a 400 or 422 steps the adapter down one level. Documentation facts and sources are in [ENV.md](ENV.md) section 6 (checked 2026-11-03); no model id is defaulted. Free-tier safety: a client-side sliding window (default 10 per minute), a per-run call budget (default 50; replays are free), exponential backoff with jitter on 429 and 5xx and transport errors (`Retry-After` honoured, capped at 20 s, at most 4 tries, never past the request deadline), hard per-call timeouts. The key is only ever the `Authorization` header: not in logs, errors, `repr` or cassettes (tests assert it). Logs hold task, model, mode, latency, request hash, outcome and token counts; prompts and outputs only at debug level and never when `APP_ENV=demo`.

### Decision 97: Record and replay

`LLM_MODE` is `replay` (default everywhere, including tests, CI and demo), `record` or `live`. A cassette is `eval/cassettes/llm/<key>.json`, `key` = SHA-256 of the sorted-key JSON of (task, model, messages, schema, temperature) under the domain `cs.llm.request.v1`; timeout, size limit and seed are not part of it. A retry has different messages and so its own cassette. Replay with no file raises `LlmReplayMissingError` naming the record command (fail closed). Recording stores only the model, scrubbed messages, schema hash, the reply and token counts, never a header or URL; strings (and JSON replies value by value) pass through `scrub` (bearer tokens, common key shapes, org and project ids, the configured key). `scripts/record_llm_cassette.py` records a named smoke request; it is for the owner to run after choosing a provider (open until P3.6) and has not been run. No test uses the network.

---

### Decision 98: The shopping agent is a separate process that speaks HTTP only

**Flagged for the owner.** `agents/shopper` imports only the standard library, `httpx`, `rfc8785`, `cryptography` and
`countersign.llm`; it has its own `wire.py` (JCS, ES256, SD-JWT reading, closed-mandate signing) instead of an extracted
shared package, so it is an independent implementation of what the service verifies. `tests/unit/test_shopper_boundary.py`
enforces the allowed imports and that nothing server-side is reachable through `countersign.llm`. The agent key is created
in the process (`AgentKey`: no accessor for the private half, no `repr`, copy or pickle; `save` writes a 0600 file and
refuses to overwrite); a test scans all HTTP traffic, events, results and reprs for the private scalar. The `UCP-Agent`
profile URI is `{base}/trusted-surface` (no profile document is served there; the server does not fetch it, L11). Added
`GET /catalog` (read-only, exact filters `category`, `q`, `max_price_minor`, fixed 400 code) because the agent had no HTTP
view of the catalog.

### Decision 99: End-to-end replay maps four per-run values and nothing else

**Flagged for the owner, accepted with conditions.** A checkout id, the `custom_id` (derived from mandate digests), the
PayPal-Request-Ids (derived from the checkout id) and the loopback port in the return URLs are new on every run, so the
exact cassette match of the earlier replays cannot hold for a run that includes a real agent and a browser.
`tests/shopper_e2e.SubstitutingTransport` maps those four, in requests (live to recorded) and in responses (recorded to
live), consistently; everything else must equal the recording in order (method, path, body, and the Request-Id prefix
`cs1.<operation>`), and one live Request-Id may not stand for two recorded ones. Tests show a changed amount, item, quantity
or path fails the replay (`test_a_mutated_recording_no_longer_replays`) and the unit tests show the mapping both ways. No
Request-Id or `custom_id` derivation changed.

### Decision 100: The item is chosen before the proposal

The mandate's `checkout.line_items` constraint names exact items, so the second model call (choose one of the search
results) happens before the proposal is filed, not after consent. After consent the agent checks that the issued open
mandates equal what it proposed (items, quantities, ceiling, expiry, key in `cnf`, one allowed payee) before it builds
a checkout. The wish (call 1) is clamped by code: known categories only, integers only, quantity 1 to 9, ceiling 1 to 100,000
minor units, 1 hour to 14 days; the choice must be one of the returned results that fits the ceiling. The agent creates the
checkout at quantity 1 and sends a UCP update only when the approved quantity is another number.

### Decision 101: The rejection receipt is not transported yet; the agent retries on the typed refusal

A rejected `complete` today answers with the UCP error codes and a canceled checkout but no signed rejection receipt (only
capture receipts are returned, `ap2.checkout_receipt` and `ap2.payment_receipt`). The agent makes one more attempt, on a new
checkout under the same open mandate, only when the response carries a signed `Error` receipt or the typed
`checkout_canceled_after_rejection` (the service has then released the open mandate, Decision 28). L47 records the gap.

### Decision 102: Payer approval in the agent

When `complete` answers `complete_in_progress` with a `continue_url`, the agent hands the link to `on_payer_approval` and,
when it returns, completes again with an empty body. With no callback it returns `payer_approval_pending` with the link. The
agent never approves for the payer.

### Decision 103: What the service keeps of PayPal objects

`PayPalClient.observe_with` gives an observer the parsed body of each successful order, authorization and capture read
(never a header, never the access token). `evidence.observer.pick` copies only allowlisted members at every depth (no payer,
no payee email, no shipping, no links, no free text), and the result is stored in the insert-only `paypal_observations`
(migration 0011). An observer failure is logged and never fails a read. Bundles read these rows; assembly makes no PayPal
call of its own, so the recorded cassettes did not change. Every committed evidence vector is synthetic and a test scans them.

### Decision 104: Evidence bundles are frozen at capture, keyed by the capture id

`CompleteCoordinator` calls `EvidenceService.record` when the gate passes (best effort: a failure is logged and the checkout
stays completed). The bundle (`evidence/bundle.py`: checkout_jwt, the four mandate chains, both receipts, the device consent
record with signature and device key, the sanitized PayPal objects, the checkout's decision log entries with a Merkle root
and inclusion proofs, the merchant and platform public keys) is stored as JCS text in the insert-only `evidence_bundles`
and `evidence.stored` is logged after it. `GET /evidence/{capture_id}` serves it only where the shared UI is served
(`APP_ENV` dev or eval) until the dashboard has a login (L46). *Superseded by Decision 107: served in every mode.*

### Decision 105: The offline verifier

`countersign_verify` (repo root; `python -m countersign_verify bundle.json [--merchant-key K --platform-key P] [--json]`)
imports nothing of `countersign` (a test enforces it). Exit 0 all steps pass, 1 a step failed, 2 unreadable input. Steps, in
order, with stable names: `bundle_structure`, `checkout_mandate` (AP2 dispute 1), `checkout_jwt_hash` (2), `checkout_receipt`
(3), `payment_mandate` (4), `payment_receipt` (5), `consent_signature`, `paypal_objects`, `paypal_custom_id`, `gate_result`,
`decision_log`, `trusted_keys`. Every step runs on its own; the first failure in order names the defect. Base64url must be
canonical, JSON strict (duplicate keys, NaN refused). Without pinned keys `trusted_keys` fails on purpose: a bundle proves
it is consistent, not whose it is. Vectors for the browser verifier (P3.8): `tests/vectors/evidence/` (`valid.json`, 29
tampered bundles with the first failing step in `index.json`, the pinned keys; 30 since Decision 108, with codes); `WRITE_EVIDENCE_VECTORS=1` rewrites them
from a real run. `scripts/mutate_verifier.py`: 35 mutants, 33 killed, 2 equivalent (explained in the script).

### Decision 106: The verifier's number rules, nesting cap, type-exact checks and failure codes

**Flagged for the owner, approved.** Both verifiers (the Python CLI and the browser port) parse every JSON text, the bundle and
each JSON value inside it, with the same rules, checked in this order: UTF-8 with no byte order mark, no lone surrogate, at
most **64** arrays and objects open at once (a bundle needs 8), then in document order no `NaN` or `Infinity`, integers only
within +/-(2^53 - 1), no excess precision (Decision 12), no duplicate key (checked when an object closes), then no escaped
lone surrogate. A number written with a fraction or an exponent is a float and is never equal to an integer: `1.0` is not `1`
and `true` is not `1` (`same`, `is_int`). A PayPal amount `value` must be a string of digits with an optional fraction
(`Infinity`, exponents, signs and spaces are refused) of whole US cents. Any error inside a step fails that step with a
stable code (`malformed` for a value of the wrong shape); nothing in a bundle can crash the verifier. `trusted_keys` passes
only when both keys are pinned (`keys_partly_pinned` otherwise). The rules are tested identically in both verifiers from one
table (`tests/vectors/evidence/json_rules.json`) and 20 bundles under `tests/vectors/evidence/strict/` (big integer, big float,
excess precision, `Infinity`, overflow, lone surrogate, nesting at 64 and 65, `1.0` and `true` for `1`, float log size,
`Infinity` and exponent amounts, negative and float `seq` and `ts_us`). Every earlier vector and the recorded shopper run keep
their outcome; the service's own bundle parses with no float in it (`test_the_service_never_emits_what_the_strict_verifier_refuses`).

### Decision 107: Evidence bundles are served in every mode (settles Decision 104 and L46)

**Flagged for the owner.** `GET /evidence/{capture_id}` is served in every `APP_ENV`, so the verifier page can load a bundle
by capture id in the hosted demo. A bundle is sanitized sandbox data (Decision 103: PayPal objects pass a member allowlist,
the customer is a random `cus_` id); a test scans a served bundle for email-shaped text and payer or buyer name, address or id
members. No listing endpoint. Every path under `/evidence/` answers through one handler: an unknown id, a malformed one and a
deeper path get the same 404 `{"code":"evidence_unknown"}` with the same headers, so the answer says nothing about which ids
are well formed. `Cache-Control: no-store`. One process log line per fetch (`evidence_fetch`, the id only when well formed);
no decision log entry, because a read decides nothing.

### Decision 108: The browser verifier and the `/verify/` page

**Flagged for the owner.** `web/ui/evidence/` is a line by line port of `countersign_verify` in plain ES modules (no build step,
no dependency, nothing vendored): its own strict parser (objects with a null prototype, floats as a `Float` type), RFC 8785,
canonical base64url, and SHA-256 and ES256 on WebCrypto. It makes no network request. The same twelve steps, in the same order,
raise the same codes; `tests/unit/test_verifier_agreement.py` runs both over every vector (valid, 30 tampered, 20 strict, 40
forged) and 400 mutated bundles and fails on any difference in step name, outcome, code or first failure. The 40 signed but
inconsistent bundles of the forger are now committed (`tests/vectors/evidence/forged/`, each verified with its own keys) so the
browser side meets the same checks. `/verify/` (served in every mode from the exact allowlist of Decision 76, with the same
CSP): paste, drop or choose a bundle file, or load one by capture id; optionally paste both public keys. Without pinned keys
the page says the keys come from the bundle and are not pinned. Every sentence is a fixed template; bundle content is only ever
set as text. The page and its modules may name PayPal as the platform the evidence comes from, in text only (the no-trademark
test exempts these two folders for that one word). Mutation sweep of the port: `scripts/mutate_browser_verifier.py`, 24
mutants, 23 killed, 1 equivalent (explained in the script).

### Decision 109: The P3 gate test

`tests/integration/test_p3_gate.py` replays the recorded run of 4 Nov (capture 49029167TJ689282S) with a headless phone, the
real composition root in `demo` mode and the service's own keys, then checks: the capture is the recorded one; the bundle passes
all twelve steps in the Python CLI and in the browser verifier with those keys pinned; the database, the process log, the
environment and every object alive in the process hold no private key of the device (only its public JWK); only three modules
sign anything and none of them handles a consent; `issue_open_mandate` is called only after the device signature check; and
the run's mandates are the ones issued from its browser-signed consent record. With `GATE_VIDEO_DIR` set it also records the
phone, the agent log and the verifier page (gitignored, never committed).

### Decision 110: Both verifiers evaluate the open mandates' constraints (review finding, HIGH)

**Flagged for the owner.** The independent review of P3 found that a bundle for goods the customer never allowed passed every
content step: the verifiers checked signatures, bindings and the budget, not the other constraints. Fixed in both verifiers
(`countersign_verify/constraints.py`, `web/ui/evidence/constraints.js`), with the same codes, inside the existing steps so the
step names and order do not change:

- `checkout_mandate` (AP2 dispute step 1, "verify the closed checkout conforms to every constraint"): the open Checkout
  Mandate may hold only `checkout.line_items` (required) and `checkout.allowed_merchants`; `checkout.line_items` is evaluated
  with the maximal flow reading of Decision 31 against the checkout the closed mandate commits to (`constraint_line_items`).
  At most 100 requirements and 100 lines, quantities 1 to 1,000,000.
- `payment_mandate`: the open Payment Mandate may hold only `payment.reference`, `payment.amount_range`,
  `payment.allowed_payees`, `payment.budget` and `payment.agent_recurrence` (Decision 32 readings; `max_occurrences` must
  be 1); `checkout.allowed_merchants` is matched on `id` against the closed Payment Mandate's payee, the merchant that was
  paid (`constraint_merchant`), because the signed checkout does not name its merchant.
- `consent_signature`: the consent's `terms` must rebuild, as the issuer does, into exactly the `mandate` the device signed
  (`consent_terms_mismatch`), so the terms the page showed and the mandates cannot differ.
- Any other constraint type, a member not understood, or two of one type fail (`constraint_unresolved`,
  `constraint_duplicate`): an unknown constraint might restrict more, so it is never ignored.

Seven forged vectors cover the cases (another item, a larger quantity, another merchant, an amount outside the range, more
than one occurrence, an unknown constraint type, terms that differ from the mandates). Every earlier vector keeps its first
failing step and code.

### Decision 111: A checkout belongs to one customer (closes L55, narrows it to L56)

**Flagged for the owner.** `checkout_customers` (migration 0012, insert only, primary key = checkout id) binds a
checkout to one customer id, once, never changed. Written (`checkout/binding.py`, `bind_or_match`: INSERT ... ON
CONFLICT DO NOTHING, then read): at UCP or ACP create, in the checkout's own transaction, when the delegation names a
customer (source `delegation`, the principal of Decisions 47 and 49); otherwise by the first Human Present offer
(source `offer`); otherwise by the first complete whose chain verified (source `mandate`).

- **Opening an offer needs the device key.** `POST /trusted-surface/purchases/offer` now takes
  `{checkout_id, challenge_id, customer_id, device_thumbprint, origin, signature}`: the device key signs JCS of
  `{v 1, purpose "countersign.purchase.offer.v1", challenge_id, challenge, customer_id, device_thumbprint,
  checkout_id, origin}` over a single use challenge of purpose `purchase_offer`. Under the per-customer advisory lock,
  then the checkout row lock (the order consent uses), the checkout is bound to that customer or must already be;
  otherwise `checkout_customer_mismatch` (403), logged before the answer. The offer stores its customer
  (`purchase_offers.customer_id`, NULL for older rows).
- **Consent** re-checks, under the same two locks, that the offer was opened for the consenting customer and that the
  checkout's binding names them. An offer row without a customer never issues.
- **Complete** (`CompleteCoordinator`, after the Merchant accepted and the lock allowed): the verified chain's
  customer must be (or now becomes) the checkout's customer; otherwise the Merchant reservation is released and the
  answer is the UCP code `mandate_scope_mismatch` (the log entry `checkout.customer_refused` names
  `checkout_customer_mismatch`). Any error refuses (INV-10). Wired at the composition root (`CompletionBinding`).
- **Both modes.** The binding is part of the checkout record in full and baseline alike: a conventional store also
  ties a cart to the customer it was made for. Attack case `agent_self_approval` (both paths: Human Present offer
  and open mandate path): blocked in full and in baseline; it does not separate the modes.
- **Mutation check** (`scripts/mutate_binding.py`): 9 mutants, 8 killed, 1 equivalent (the consent re-read of the
  binding, explained in the script).
- **What remains** is L56: an agent can still enrol a customer of its own and buy for that customer on a checkout it
  creates for it.

### Decision 112: The dashboard has a build step (exception to Decision 73)

**Flagged for the owner.** `web/dashboard` is `@countersign/dashboard`: Vite 7, React 19, TypeScript, `ag-studio-react`
and `ag-studio` 3.1.0 (commercial licence, used under the owner's trial key). Decision 73 still holds for the shared UI
and the phone pages; the dashboard imports `web/ui/tokens.css`, `fonts.css` and `ui.js` (`formatAmount`,
`groupFingerprint`) from there, so money is formatted by the same code. The licence key is read from
`AG_STUDIO_LICENSE_KEY` (environment or the gitignored `.env`) by `vite.config.ts` and compiled into the bundle, as any
browser licence key is; it is never committed. `.env.example` names it empty, `web/*/dist/` is ignored,
`tests/unit/test_licence_key_not_committed.py` and a secret scan rule fail on the local key, a licence-shaped string
or a non-empty assignment in tracked files. Without a key the build works and Studio logs "License Key Not Found";
CI builds that way and the browser test skips only the licence assertion.

### Decision 113: Serving `/dashboard/`, and the one CSP relaxation

**Flagged for the owner.** Served in every `APP_ENV` (`api/dashboard_routes.py`) from an exact table built at start
from the Vite manifest: `/dashboard/` (index.html) and each `assets/<name>-<hash>.<js|css|woff2|svg>` the manifest
names, with a fixed media type. No directory, no path joined from the request, a manifest naming any other shape stops
the start, no build answers 503 `dashboard_not_built`. CSP on `/dashboard/` only: `default-src 'none'; script-src
'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none';
form-action 'none'; frame-ancestors 'none'`. Relaxed: `style-src 'unsafe-inline'` (Studio and its grid set `style`
attributes and inject `<style>` at run time; a nonce was tried and cannot cover style attributes) and `img-src data:`
(Studio's inline icons). Scripts stay `'self'` only. The phone and verifier pages keep Decision 76.

### Decision 114: The dashboard read API

**Flagged for the owner.** `GET /dashboard/api/v1/{status, orders, summary, mandates, events, eval, stream}`, every
body with `version: 1`, `Cache-Control: no-store`; no other method is routed (test). Rows are built from explicit
member lists (`dashboard/read.py`). An order: `id, created_at, created_us, updated_us, agent` (key thumbprint),
`customer_id, items` (fixed "n × title"), `amount_minor, currency, status, mandate, protocol, gate, refusal,
capture_id, source, funnel_stage, captured_minor, blocked, reason, unauthorized`. `status` is the checkout status,
`voided` for a voided attempt, `rejected` for a canceled checkout with a refused complete. **Unauthorized capture**: a
capture with no verified mandate behind it (a captured attempt without stored mandates, or the baseline's unmandated
capture). `status` reports booleans and labels only (PayPal configured yes or no, never a value). **Who may call:**
anyone who can reach the server; there is no merchant login yet (L57). A test scans every answer for email-shaped
text, payer, buyer, name, address, phone, token, secret and key members, JWT-shaped strings and PEM blocks.

### Decision 115: The live stream

`GET /dashboard/api/v1/stream` (Server-Sent Events): `hello` with the newest log seq, then every second the ids of
checkouts named by newer log entries (`orders` events, ids only, at most 500), a keep-alive comment every 15 s, closed
after 300 s (the browser reconnects) or when the client leaves. The page fetches those rows by id and applies them to
Studio's data engine as one transaction (`applyTransaction`, the table has `primaryKeyField: id`).

### Decision 116: Every row is labelled by where its data came from

**Flagged for the owner.** `checkout_sources` (0012, insert only, a CHECK on the three labels) is written at create:
`live_sandbox` only by the real process (`countersign.main`, the sandbox client), `simulator` by every test, eval and
seed world (the `Wiring` default), `recorded` by the seed's replay of the gate cassette. A row without a label shows as
`unlabelled`, never as a sandbox capture. The grid shows Source as its second column and the CSV export keeps it.
`make dashboard-seed` (`scripts/dashboard_seed.py`, `APP_ENV=dev` and a local database only) makes simulated rows
through the real app over the simulator (completed, refused for amount, expiry, forgery and customer, lock denials,
waiting for payer approval, ACP refusals, open, and gate voids from an app with the pre-authorize check off) and
replays the recorded gate cassette once (one recorded capture, one recorded void).

### Decision 117: The Orders view on AG Studio

**Flagged for the owner.** A pre-composed Studio report over one `orders` table: four value tiles (captured, orders,
blocked, unauthorized captures, each an aggregate of a per-row field), a donut of orders by status, a bar chart of
blocked attempts by reason (a widget filter `blocked = 1`), the custom **Authorization funnel** widget and the orders
grid (status, mandate and source pill renderers, amounts through `formatAmount`, newest first, totals row, Studio's
CSV export). The funnel is registered with `createWidgets` (`additionalTypes`, its own data mapping and form, default
size, AI description); it reads the furthest step and a count through Studio's data API, so filters apply to it,
and clicking a step cross-filters the page to the checkouts that stopped there. The quick filter is a page filter
(`contains`) on a hidden lower-case search field. "Group by agent and customer" swaps the grid for Studio's pivot grid
with those row groups. Theme: `studioTheme.withParams` in a light and a dark mode built at run time from the computed
values of `tokens.css` (colours, fonts, chart palette), switched with `data-ag-theme-mode`. View mode for visitors;
"Edit layout" (Studio's edit panels) only when `APP_ENV=dev`. Onboarding is read only in demo; in dev it points to
the environment, and there is no credentials form.

### Decision 118: Order detail is a custom Studio widget driven by the grid's row selection

**Flagged for the owner.** Studio's grid widget has no master and detail. A grid row click starts a cross filter, so
the **Order detail** widget (`web/dashboard/src/OrderDetail.tsx`, registered with a form, default size and AI
description like the funnel) asks Studio for the cross filtered rows of the `orders` table and shows an order only
when that selection is exactly one checkout. A quick filter or page filter that leaves one row does not select it.
Chosen over a separate detail page because it needs no second routing path, follows every other widget's filters,
and is a second custom widget for the AG Grid story. Panels: (1) the merchant-signed checkout with the
`merchant_authorization` status (the browser verifier's `checkout_jwt_hash` step) and items and totals through
`formatAmount`; (2) both mandates decoded with each link's own result (platform signature on the open mandate, agent
key binding on the closed one), the constraints, and the device consent with its signature step and the device key
fingerprint; (3) the PayPal objects as stored in the bundle, labelled "as fetched at capture time" and never live
(the dashboard has no PayPal credentials and no route that calls PayPal), next to the amount, `invoice_id`,
`custom_id` (recomputed from the signed mandates by `expectedCustomId`, now exported from `steps.js`, behaviour
unchanged), item names and prices re-derived from the signed checkout, a difference shown as "Differs" on a red row
and the payee flagged if it changed between reads; (4) the nine gate steps, and the log entries with an inclusion
proof each, noted as consistency checks (L48). Every check is a call into `web/ui/evidence`; `evidenceModel.ts`
re-implements none. `GET /dashboard/api/v1/orders/{id}/detail` returns the order row, an `evidence.state` and the
stored bundle text (the text `GET /evidence/{capture_id}` serves: allowlisted PayPal members, a random customer id,
public keys only), so the browser verifies the exact bytes the offline CLI would. An unknown or malformed id is 404.

### Decision 119: Rows without evidence say so in fixed words

**Flagged for the owner.** `state` is `bundle`, `simulated` ("No evidence bundle: simulated"), `unmandated` (the
baseline captured with no mandate, so none can exist), `missing` ("Bundle missing", a verified capture whose assembly
failed, L49) or `not_captured`. A simulated row with no bundle always reads `simulated`, even if it was captured. No
panel renders without a bundle and nothing is invented. The service's own bundles need the phone flow's device
consent, which the simulated seed does not run, so `make dashboard-seed` also stores one order made from the committed
synthetic vector `valid.json`, labelled `simulator`; its detail and Evidence views are real verification of
synthetic data. Untrusted text (item titles, customer and agent ids, claim values, PayPal fields) is React text only;
there is no `dangerouslySetInnerHTML`, and a Playwright test with `img onerror` and `script` payloads in a bundle and
in a plain order asserts nothing runs, no element is created and the payload shows literally.

### Decision 120: The Evidence view and its samples

**Flagged for the owner.** `#/evidence/<checkout id>`: choose a captured order, **Verify evidence** runs
`verifyText` on its stored bundle and lists the twelve steps with the `/verify/` wording, pills and stable step names
(`verify-text.js` imported, not copied); **Download bundle** fetches `GET /evidence/{capture_id}`; a bundle file from
disk uses the same path. Without pinned keys the last step reports `keys_not_pinned` and the summary says "Keys not
pinned", as on `/verify/`. **Try a committed sample** uses `GET /dashboard/api/v1/samples[/{name}]`: an exact table of
four names (the valid vector, two tampered, one forged) to files under `tests/vectors/evidence/`, built in
`dashboard/samples.py`, nothing joined from a request; an unknown name or traversal shape is 404. A sample carries the
first step it must fail at (from the vectors' index) and, for the valid and tampered vectors, the public keys to pin.
The forged vectors are signed with their own throwaway keys, so they are checked against their bundle keys unpinned.

### Decision 121: The Protection dashboard

**Flagged for the owner.** A second Studio report over four tables: `orders`, `events` (blocked and voided attempts from
the decision log), `mandates` (the open mandate registry with ceiling and spend) and `attacks`, with one relation
(`events.checkout_id` to `orders.id`, many to one) so the funnel narrows the attempts. Tiles: blocked or voided
attempts (count of events), voided authorizations (sum of a 0 or 1 field), open mandates, spend under mandates; charts
by reason code, by day and mandates by state; the mandate grid; the funnel; attack cases by category. Numbers are
aggregates of rows from the read API. A test compares three tiles with independent SQL over `decision_log` and
`open_mandates` and checks the funnel's cross filter against SQL. A tile over no rows is blank, not 0.

### Decision 122: The attack matrix widget

**Flagged for the owner.** `GET /dashboard/api/v1/eval` now carries one short entry per case and mode (case, category,
outcome, reason code, unauthorized captures, captured minor units; no other report member). The **Attack matrix**
widget (`AttackMatrix.tsx`, form, default size and AI description) reads one row per case (full and baseline outcome
side by side) through Studio's data API, so a click on a category bar narrows it. It shows the totals (full: 0 of 30
succeeded, 0 unauthorized; baseline: counts from the report), a row per case with the reason code, and says in words
how many cases do not separate the modes (the baseline also blocks them) and marks those rows. The widget computes
every number from the rows it receives; a test compares them with `eval/reports/latest.json`.

### Decision 123: Seeded open mandates are labelled by a reserved id prefix

**Flagged for the owner.** `scripts/dashboard_seed.py` (`seed_mandates`) writes five open mandates, one per state (unused, in flight,
used, revoked, expired), with fixed ids (`om_sim_<state>`), fixed times, customers and agent keys, with replication checks off (a
real mandate needs a phone consent). The used and in-flight ones have a payment attempt, spend entry and stored-mandate row, so no
tile counts them as unauthorized. Mandates have no source table, so the read model labels `om_sim_*` as `simulator` and anything
else `unlabelled`; real ids are token digests. The seed's own random choices are fixed too; app-minted checkout ids, signatures and
times are not, so a rebuilt database matches in shape and counts, not byte for byte. The test support `reset()` now truncates
`open_mandates`.

### Decision 124: The policy snapshot and its hash

**Flagged for the owner.** `dashboard/policy.py` builds one JSON object from the running code (the gate's `STEP_CODES`, the checkout
and payment constraint handler tables, the runtime mode and ablations, the stored merchant lock policy), the dashboard's read-only
status and explicit `not_enabled` entries (unmandated cap, velocity limits, category policy, editing and versioning). It is
serialised with RFC 8785, hashed with SHA-256 and served by `GET /dashboard/api/v1/policy` with the hash; the Policy panel shows
both and says in fixed text that it is read only. The hash is logged once per process start (`policy_snapshot`, process log: the
decision log is per checkout). No write route exists (the test over every `/dashboard` route covers it). The editable, versioned
policy view is cut for time and `check_category_policy` is not wired into the Merchant verifier (L62).

### Decision 125: Ask Countersign is a read-only package with a fixed tool catalog

**Flagged for the owner.** `src/countersign/assistant/`: eight tools (`query_orders`, `get_order`, `get_gate_steps`,
`explain_error_code`, `summarize_evidence`, `compare_modes`, `blocked_attempts_by_reason`, `open_mandate_state`), each a pure function
of validated arguments and a `DataSource` (an interface the package defines; `dashboard/assistant_data.py` adapts the dashboard read
models and runs the offline verifier for evidence steps). The package imports no authorization module, the database layer, the
dashboard or the API, and none imports it: `tests/unit/test_llm_boundary.py` checks it transitively. Orders can be named `latest`,
`latest_captured` or `latest_voided`, resolved in code. Item titles and other free text are never echoed. Two GET routes under
`/dashboard/api/v1/assistant/` (`suggestions`, `ask`), so the dashboard API keeps no mutating method.

### Decision 126: The model only plans

**Flagged for the owner.** One gateway call (`assistant_plan`): fixed instructions and the catalog (names, descriptions, JSON
schemas) as the system message, the cleaned question (printable, at most 300 characters) as the user message. No row, id, amount or
tool result is ever sent. The reply is `{"calls": [{tool, args}]}`, at most three; the gateway validates the structure (the tool name
is an enum) and retries once, then `validate_call` re-checks each call's arguments against the tool's own schema. An unknown tool,
bad arguments, an empty plan or a schema failure answers with the fixed sentence "I can only answer questions about orders,
protection activity, evidence and evaluation results." Answers are fixed-template lines with numbers and identifiers from the rows
read, each line carrying citations (order, evidence step, evaluation case, log entry, mandate, code).

### Decision 127: Replay is the default; recorded questions; no invented plans

**Flagged for the owner.** `LLM_MODE` replay everywhere including demo. Ten suggested questions (`assistant/suggestions.py`) are
recorded with `scripts/record_assistant_cassettes.py` (live gateway in record mode, the scrubber, settings from the owner's shell);
`eval/cassettes/assistant.json` stores the model id (the cassette key includes it), the catalog hash and the questions, and the app
replays with that id. Free text works only if its planner call is in the cassettes; otherwise the fixed message "This demo replays
recorded questions; pick a suggestion." In live mode free text uses the gateway's rate limit and call budget. A bad live
configuration disables the assistant instead of stopping the app. Changing a question or the catalog needs a new recording (a test
compares the catalog hash). Recorded with `gemini-3.5-flash-lite`; a test checks the cassettes carry only the documented members, and
the recording was grepped for keys, provider headers, `thought_signature`, request and account ids (none).

### Decision 128: The grounding check

**Flagged for the owner.** `assistant/grounding.py`, a pure function: every numeral in an answer line must equal a number in the
tool results of that answer (integers, floats, numerals inside strings, money fields in minor and major units). Formatting does not
matter (`1,234`, `$54.00`); numerals inside identifiers (`chk_ab12`, `G-AMOUNT`, `3x`) are not claims. A line with an unmatched
numeral is replaced whole by "I cannot verify that figure from the data." and counted. Templates use no numeral for data values.
Mutation sweep `scripts/mutate_grounding.py`: 16 mutants, 16 killed. Number words are not checked (L64).

### Decision 129: Studio integration

**Flagged for the owner.** A Custom Runner agent (`web/dashboard/src/assistant.tsx`, an async generator) sends the last user message
to `GET .../assistant/ask` and emits AG-UI events: `RUN_STARTED`, a display-only `countersign_lookup` tool call whose result carries
the lines and their citations, the answer as one text message (Markdown-escaped), `RUN_FINISHED`. It has no model, no tools and never
reads Studio's AI context. Suggestions are `promptStarters`; citations are chips drawn by an `aiToolDisplay` detail component and open
in a new tab (`#/orders/<id>` filters the Orders view; `#/evidence/<id>`). Studio's AI panel exists only in edit mode, so the
Assistant view runs in edit mode with only the AI panel configured (L63). Studio's widget-building tools were not used: they need
the model to see Studio's schema and context.

### Decision 130: The adversary is a separate process, scripted, and reaches the app over HTTP only

**Flagged for the owner.** `agents/adversary` follows the isolation pattern of `agents/shopper` (Decision 98) with less in
it: standard library and `httpx` only, its own `wire.py` (base64url, the (r, n - s) signature rewrite, a one-character tamper,
a JSON body with a duplicate key), no `countersign` import, no environment read, no PayPal or database name anywhere.
`tests/unit/test_adversary_boundary.py` enforces all three. It has twelve scripts, each named after the `eval/attacks` case it
re-performs (`protocol_downgrade_acp`, `unmandated_acp_unlocked`, `double_spend_across_protocols`, `new_session_escape`,
`nonce_replay_new_session`, `open_mandate_double_spend`, `open_mandate_reuse_new_presentation`, `budget_split`, `checkout_swap`,
`mandate_forged`, `category_escape`, `duplicate_json_keys`); several run across UCP and ACP in one goal. Two things an agent
cannot do come from a `Counterparties` object the caller provides: what the customer signed (`sign(authorized=...)`) and the
payer's approval at PayPal. In the harness (`eval/adversary/consent.py`) the customer is the issuer the attack cases use and the
payer is the PayPal simulator; `authorized=True` also tells the judge what was really signed, which the adversary never sees.
The target is a whole app built by the composition root and reached through its HTTP interface with the ASGI test client, not a
network socket. Every request appends one line to the attempt log (attack id, target mode, time, step, method, path, body shape,
header names only, status, the adversary's own reading, the stable code): no header value, token or body is written. The verdict
is the judge's (PayPal state and the decision log) and never the log's. A test runs every script in both modes and requires the
verdict to equal the registry case's declared outcome (12 goals, 24 runs). **LLM mode is cut** (L65). `python -m agents.adversary
--list` lists the scripts; a run is `uv run python -m eval.run --suite adversary [--case ID]`.

### Decision 131: The dashboard "Run attack" launcher is the one gated write

**Flagged for the owner.** `GET` and `POST /dashboard/api/v1/attack-runs`. `POST {"attack": id}` builds a fresh baseline and a
fresh full instance on scratch databases (`eval/launch.py`), lets the scripted adversary attack both, judges each, and returns
and stores one run record. It is refused (403 `attack_runs_disabled`) unless `APP_ENV` is `dev`, `eval` or `demo` **and** a
launcher is installed. `countersign.main` installs it in dev and eval, in demo only when `EVAL_DATABASE_ADMIN_URL` is set, never
elsewhere, and not when `ATTACK_RUNS=0`; the launcher is imported by name so the server's type check does not follow into the
evaluation code. Further gates: a custom request header `X-Countersign-Dashboard: 1` (403 `attack_run_header_required`; a
cross-site request cannot add it without a preflight, which the app never answers), a body of at most 256 bytes with exactly one
member `attack` that must be in the launcher's own list (404 `attack_unknown`), one run at a time (409 `attack_run_busy`), and
503 `attack_runs_unavailable` when no scratch database can be created. The route reads and writes no merchant data: the only files
written are `eval/reports/attack-runs/<run id>/{record.json, attempts-baseline.jsonl, attempts-full.jsonl}`. The existing
static file allowlist and CSP are unchanged (`connect-src 'self'` covers the call). The Attack matrix widget gets a select and a
button (`RunPanel`) that appears only when `GET attack-runs` says enabled and shows, per instance, "money captured outside what was
signed or allowed: yes or no" from the judge. The policy snapshot still says `write_endpoints: 0` (no merchant write endpoint);
L66 records that this is narrower than "no POST route".

### Decision 132: The attack suite grows from 30 to 40 cases

Ten new cases, each exercising a defense no earlier case isolates: `mandate_roles_swapped` (exact `vct` and audience per slot),
`payment_mandate_missing` (INV-3: no authorization without a Payment Mandate), `open_mandate_as_closed` (the closed link signed by
the bound key is required), `payment_mandate_other_checkout` (the payment mandate binds to the same checkout hash),
`amount_off_by_one_minor_unit` (one cent more and one cent less), `currency_swap` (EUR amount on a USD checkout),
`mandate_other_agent_key` (closed links signed by an agent other than the one in `cnf`), `complete_after_cancel` (a canceled checkout
completed with valid mandates), `concurrent_complete_race` (twelve simultaneous completes, then twelve retries after payer
approval), and `evidence_bundle_tamper` (four rewrites of the committed synthetic bundle, judged by the offline verifier alone).
**None separates the modes**: all ten are blocked in baseline too, because those defenses are shared; the matrix says so. To
build them `tests/mode_support.mandate_pair` gained `payment_issue`, `currency` and `lines`. **Dropped** because they cannot be
judged from PayPal state, the log or evidence verification as the harness stands: a consent record replayed across customers and
a revoked device key used after revoke (both need a device-bound world; the Trusted Surface tests cover them), an open mandate
that expires mid-flight (the world's clock is fixed), a shipping address change (the canonical checkout has no address), a
valid-signature webhook replay (the judge does not net refunds, so a legitimate refund would read as an over-budget capture).
`evidence_bundle_tamper` cannot use the world's own bundles: they need a device consent record behind the open mandate, which the
issuer-built mandates lack, so it starts from `tests/vectors/evidence/valid.json`, and it exercises the Python verifier only
(the browser verifier is held to the same vectors by its own test).

### Decision 133: Task, property and concurrency suites, and how reports merge

`eval/tasks` builds 27 fixed legitimate purchases (26 autonomous across the five catalog categories: single items, quantity two,
two lines, a budget equal to the total, one cent above it, and a generous one; one Human Present purchase through the real Trusted
Surface offer and consent routes with a Python device). A task completes only if PayPal holds exactly one capture for exactly the
signed total and the judge finds no violation; otherwise it is a false block. Reported per mode: completion rate, false block rate,
unauthorized captures, duplicate objects, latency p50 and p95 (wall clock over the simulator, so noisy and not comparable with
live PayPal). They run through the issuer and the simulator, not through the model-driven shopper, so no recording is involved and
no cassette changed. `--suite properties` and `--suite concurrency` run pytest over fixed file lists with `--hypothesis-seed=0`
and report passed, failed and errors (test counts, not example counts). `--suite all` runs all five. Reports: `report.json`
carries `sections` for the non-attack suites, each dated on its own; `latest.json` is merged, so a partial run replaces only the
sections it ran and keeps the older ones with their own dates (the attack matrix reads the top-level attack figures as before).

### Decision 134: The release evaluation and what it reports

`python -m eval.run --suite all --mode both --seeds 0,1,2` (`make eval`) runs, for each seed, the attack suite, the scripted adversary
goals, the 27 tasks, and the property and concurrency files (`--hypothesis-seed` is the seed). The attack, adversary and task suites
contain no randomness, so the seeds are repetitions; the report states whether the three runs were identical (they were:
`seed_invariant`). Every architecture ablation then runs against all 40 attack cases once, and one extra configuration is added that
is not an architecture ablation: `ABL_NO_GATE` and `ABL_NO_PREAUTH_CHECK` off together, because alone neither reopens anything (the
other layer stops the case) and the pair shows what the gate adds. Capture stage time is measured by wrapping `CaptureGate.run`
(`ImmediateCapture` inherits it, so one wrapper times the gate in full and the immediate capture in baseline); it measures and
changes nothing. Added gate latency is full minus baseline at p50 and p95 over 162 calls per mode, over the PayPal simulator.
Evidence: every bundle the app stored in the attack and task runs is verified with the Python CLI and the browser verifier (Node),
service keys pinned from the world that produced it; the recorded sandbox capture is verified through the two P3 gate replay tests.
Output: `report.json` (rows for every seed, ablation rows, and a `results` block), `report.md`, `charts/*.svg` (dependency free), and
`latest.json`, which now also carries `results` for the dashboard. The frozen run `20261108T063449Z` is un-ignored in `.gitignore`
so the files that documents cite are in the repository. Exit status is 1 on any mismatch, crash, uncompleted task or failed test.
The release code is `eval/release.py`; the helper `rerender` rebuilds a finished run's notes and markdown from its `report.json`.

### Decision 135: The Results view reads `results` through the existing eval endpoint

`GET /dashboard/api/v1/eval` returns a second member, `results`, produced by `read.eval_results`, which re-types every field and
bounds every string, so a malformed report degrades to `null` (the view then says no full evaluation has run). No route, static file
or CSP rule was added; the view is a read of the same file as the attack matrix. The view is AG Studio widgets: four Total tiles
over a one-row `full_mode` table (a first version totalled the two-row `modes` table and showed baseline plus full, 18 instead of 0;
the browser test caught it), a grid of totals per mode, two bar charts, a pivot grid of ablations grouped by result, a grid of tasks
and capture stage time, and a pivot grid of targets grouped by met and missed. Nothing in the view is typed in; the meta line names
the run id.

### Decision 136: A public environment is an allowlist, and dev-only switches stop the start

`APP_ENV` must be `dev`, `eval`, `demo` or `prod`; any other value (including an empty one) stops the start. Ablations (`ABL_*`) are
allowed only in `dev` and `eval`, so `prod` and any future name refuse them (before, only the literal `demo` did, which failed open
for a typo). In `demo` and `prod`, `PAYPAL_ALLOW_NON_SANDBOX=1`, `PAYPAL_RECORD_CASSETTES=1` and `LLM_MODE=record` also stop the start.
Errors name the switch, never a value. `render.yaml` pins `APP_ENV=demo`.

### Decision 137: The attack launcher stays off in the hosted demo and says so

The launcher was already off in `demo` unless `EVAL_DATABASE_ADMIN_URL` is set (Decision 131); `render.yaml` does not declare that
variable. `GET /dashboard/api/v1/attack-runs` now adds `reason` (`hosted_demo` or `off`) and the Run panel shows a note naming the frozen
run `20261108T063449Z` instead of rendering nothing. The recorded side by side results (the attack matrix) are the same committed report
as before. Everything else under `/dashboard/` stays read only. This closes the MEDIUM finding of the P4 security review (anyone can start
runs in demo); the per-IP limit on `POST attack-runs` stays as a second layer if an operator turns the launcher on.

### Decision 138: An in-process sliding-window rate limit on the public mutating routes

`countersign.api.ratelimit`, installed by the entry point in `demo` and `prod` (and in dev or eval only with `RATE_LIMIT=1`, because the
evaluation hammers the app on purpose). Per client address and group, per minute: enrolment 10, consent and phone flow 20, checkout
create 30, checkout update and cancel 60, checkout complete 20, assistant ask 12, evidence read 60, webhook 120, attack run 6. A refused
request gets 429, `Retry-After` in whole seconds and `{"code":"rate_limited"}`, and is not counted. The address is the socket peer, or the
rightmost `X-Forwarded-For` entry when `TRUST_PROXY=1` (the entry the platform proxy appended; entries to its left are client supplied).
A test walks the real app and fails if a mutating route has no rule. The limit protects the log, the database and the sandbox quota; no
money decision depends on it.

### Decision 139: Keys may come from the environment, and the database URL is normalised

`MERCHANT_KEY_JSON` and `PLATFORM_KEY_JSON` are read with the strict loader and validated exactly like the key files (the file mode check
does not apply to an environment value). They take precedence over `*_KEY_PATH`. `DATABASE_URL` values starting `postgres://` or
`postgresql://` are rewritten to `postgresql+psycopg://` for the app and for Alembic. `PUBLIC_BASE_URL` falls back to Render's
`RENDER_EXTERNAL_URL`.

### Decision 140: `GET /selfcheck`, and the demo seed reuses the dev seed's functions

`/selfcheck` (also logged once at start) reports mode, environment, active ablations, the names of dev switches that are on, whether the
launcher is installed, the assistant mode, and booleans for the PayPal app and the webhook id. `ok` is false when an ablation or a dev
switch is on, or when a public environment has the launcher without an administrator database named on purpose. No value is reported.
`python -m countersign.demo_seed` (`make demo-seed`) fills an empty database through the same functions as the dev seed: recorded rows
replayed from the real sandbox cassette (capture 49029167TJ689282S and one void), simulated orders from apps over the PayPal simulator,
five open mandates `om_sim_*`, one order with a bundle from the committed synthetic vector. It refuses unless `APP_ENV` is `dev` or
`demo`, adds the recorded rows, bundle and each mandate once, adds simulated orders only when the database holds five or fewer
simulator rows, and with `--if-empty` does nothing when any checkout exists. No device key is seeded (a key belongs to a phone and its
origin), and nothing is labelled `live_sandbox`.

### Decision 141: The demo seed needs no superuser, is re-runnable, and says what it did

**Cause.** The first hosted seed stopped at `SET LOCAL session_replication_role = replica` in `seed_mandates`, which PostgreSQL allows only
to a superuser; Render's database user is not one (`permission denied to set parameter "session_replication_role"`). The statement was
there only to skip two foreign keys (`open_mandates.consent_id` to `consent_records`, `spend_entries.mandate_digest` to
`open_payment_mandates`, and behind the first the challenge and device rows). No append-only trigger, grant or timestamp needed it:
the guards fire on UPDATE only and the times are ordinary column values. The failed step ran before the simulated orders, which is
why the hosted dashboard held three orders and no open mandates.

**Fix.** The statement is gone, and no migration, trigger, grant or constraint changed. Each of the five mandates is written in its
own transaction, only when its id is missing, with its parents in dependency order: a challenge `kc_sim_*`, a device row, a consent
record `consent_sim_*` and, where an attempt exists, an open payment mandate. The device and consent rows are placeholders marked
`sim` that hold no key material (`jwk` is `{"simulated": true}`, which no verifier accepts); nothing signs with them, and no new column
exists, so there is no seed-only path from a public route to test. Rows are inserted, never updated or deleted.

**Re-runnable.** Completeness is read from the rows (`demo_seed.status`): five `om_sim_*` mandates, two stored bundles including capture
49029167TJ689282S, three `recorded` checkouts, and at least 75 percent of the requested simulator orders. `--if-incomplete` (and its
old name `--if-empty`) skips only a complete database; otherwise each missing item is added and nothing present is touched, so the
three orders already on Render are completed, not wiped. Each step is isolated: a failure prints its traceback, the other steps still
run, the last lines are `demo seed summary: complete=... failed_steps=[...]`, and the exit code is 1 unless complete. The start command
logs that and still starts the service. A preflight names a missing INSERT privilege in one line. The seed's apps are built in
process without the rate limiter, which only the public entry point installs. The gate replay writes through the services and cannot
be repeated over the same ids, so a replay that stopped part way is not redone; its checkouts are labelled `recorded` and the summary
reports the shortfall.

**Correction to Decision 140.** The gate cassette's capture is `7LN24060SW866991Y` (USD 29.00, plus one void). Capture
49029167TJ689282S (USD 69.00) is the P3 purchase in `shopper_e2e.json`, whose replay needs a headless browser. The seed now adds it as
an order labelled `recorded` with the bundle that replay produced (`tests/vectors/recorded/p3_capture_bundle.json`, exported with
`P3_EXPORT_BUNDLE`). That bundle passes eleven of twelve verifier steps; `trusted_keys` fails unless the replay run's own keys are
pinned, because they were generated for that run. `/selfcheck` shows `seed`: `orders`, `open_mandates`, `bundles`, `seed_complete`
(counts only).

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

**Expiry rule (Countersign decision).** An authorization counts as expired when
`expiration_time <= now + skew`, with `now` the local clock and a skew of 60 seconds (the same value
as the mandate `exp` skew in Decision 10, held in `PayPalConfig.authorization_expiry_skew_s`). The
direction is fail closed (INV-10): the local clock may run behind PayPal's, and a capture attempted in
the last minute could be refused or race the expiry. The cost is that an authorization is not
captured in the final minute of its life; with a lifetime of about 29 days that is negligible. A
missing time zone on `expiration_time` is refused. Nothing is sent to PayPal in either case.

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
| Refund with `{}` (no amount) after the partial refund  | accepted; capture status `REFUNDED`                           |
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

### Decision 142: A landing page at `/`, served from the same exact allowlist

The hosted demo answered 404 at `/`. A two-file page (`web/landing/index.html`, `landing.css`) is now two entries of the static table in
`countersign.api.static_routes`, in every mode, with the same strict Content-Security-Policy (no script, no inline style, no framing, no
forms). It states what Countersign is, labels itself a sandbox demo, and links the dashboard, the verifier try-it, the UCP profile,
`/health` and the repository. A test fails if `web/landing` holds a file that is not in the table, if the page loads anything the CSP
forbids, or if it links an external resource other than the repository.

### Decision 143: The verifier page has a try-it that only presses the page's own buttons

`web/verify/tryit.js` loads one of two samples, fills the same fields and presses the same Verify button a visitor would, so every result
comes from the one verifier in `web/ui/evidence/` (strict JSON, nesting cap 64, unchanged). The samples are the committed test vectors
served byte for byte at `/verify/samples/synthetic.json` and `/verify/samples/recorded.json` (allowlist entries, a test compares them
with the files). The synthetic sample is run with its own keys pinned (twelve of twelve pass). The recorded sandbox sample is run
unpinned so the `trusted_keys` step fails with `keys_not_pinned` (L76); a button pins the keys inside the sample to show the step
passing, and the text says that this proves the mechanism, not who signed. The change button edits a copy of the loaded sample
(the first capture's amount, last digit) in the page only and shows the failing step: `paypal_objects`, code `paypal_amount`. The Python
verifier `countersign_verify` gives the same failure on the same edited file. The unpinned summary title now reads "Every check passed
except key pinning" instead of "Every step passed".

### Decision 144: A PayPal-free local demo mode

`scripts/demo.sh` (`make demo`) runs the app with `APP_ENV=dev`, `CS_MODE=full`, the placeholder credential `local-demo-no-credentials`
(`countersign.main.NO_CREDENTIALS`: the app reports `paypal_sandbox_configured: false` for it and PayPal would reject it, so a purchase
fails closed), migrates, runs the demo seed and starts the app. It does not read `.env`. The "Run attack" launcher is on in `dev` and
uses `EVAL_DATABASE_ADMIN_URL`, which the script sets to `DATABASE_URL`, so the Postgres user needs `CREATEDB` and `CREATEROLE`. Run
records go to `eval/reports/attack-runs/` (ignored by git). Nothing in the public environments changes.

### Decision 145: Design polish from the P4 design review

Phone setup, intent, purchase and activity cards that wait for the person are tagged "Ready", not "Working". The dashboard shell uses
`minmax(0, 1fr)` so the page no longer overflows by 11 px at 375 px, and below 600 px the navigation and header controls and the
inputs are at least 44 px. The Orders search placeholder is shorter. Chart category labels in Results are cut with an ellipsis at 24
characters, because Studio clips a long label at its left edge at 1280 px. Browser tests cover each.

---

## 5. Still to be written

Added by later work, not yet present in this file:

- Live webhook confirmation (deferred to the Render deploy; steps in [ENV.md](ENV.md) section 11).
- Human Present token format and receipt transport (see Decisions 8 and gap 4).
- Gate step codes, principal lock semantics and the evidence reference encoding.

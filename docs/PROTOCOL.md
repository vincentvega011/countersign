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

---

## 5. Still to be written

Added by later work, not yet present in this file:

- Live webhook confirmation (deferred to the Render deploy).
- Human Present token format and receipt transport (see Decisions 8 and gap 4).
- Gate step codes, principal lock semantics and the evidence reference encoding.

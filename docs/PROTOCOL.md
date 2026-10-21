# PROTOCOL

How Countersign uses AP2, UCP and ACP, grounded in the pinned copies under `spec/vendor/`.
This file is built up over time. This revision covers the AP2 and UCP facts confirmed by reading
the vendored files. PayPal facts, library choices, constraint schemas, gate step codes, the
evidence reference encoding and the PayPal field mapping are added by later work and are listed
under [Still to be written](#still-to-be-written).

## Conventions

- **Citations.** Every fact cites a vendored file and a section heading. Paths are relative to
  `spec/vendor/`. Pins are in `spec/vendor/SOURCES.md`: AP2 tag `v0.2.0`, UCP tag `v2026-08-25`,
  ACP spec `2026-04-17`.
- **Quoting.** Field names, claim names and strings are quoted exactly as written upstream.
- **Status labels.** Each fact is either _confirmed_ (stated in a vendored file) or marked
  _not specified_ or _ambiguous_ where the vendored files do not settle it. Countersign choices
  made to fill a gap are labelled _Countersign decision_ and are never presented as spec.
- **Out of scope here.** ACP is used only as the weaker second protocol in attack scenarios and
  is not analysed in this revision.

---

## 1. Confirmed spec facts

### 1.1 Checklist answers at a glance

| Item                            | Answer                                                                                                                                                                                                                                                             | Detail                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- |
| Mandate `vct` strings           | `mandate.checkout.1`, `mandate.checkout.open.1`, `mandate.payment.1`, `mandate.payment.open.1`                                                                                                                                                                     | [1.2.2](#122-mandate-types-and-vct-strings) |
| `checkout_hash`                 | base64url hash of the `checkout_jwt` value; algorithm is the SD-JWT `_sd_alg`, or `sha-256` if absent                                                                                                                                                              | [1.2.4](#124-hashes)                        |
| `transaction_id`                | base64url hash of the `checkout_jwt` value. It is the same value as `checkout_hash`, not a separate unique id                                                                                                                                                      | [1.2.4](#124-hashes)                        |
| `cnf`                           | RFC 7800 confirmation claim, shape `{"jwk": {...}}`, required on open mandates, holds the agent public key                                                                                                                                                         | [1.2.5](#125-key-binding-and-the-cnf-claim) |
| Constraint structure            | object with required string `type` plus type-specific fields; ten native types exist (none for expiry or category)                                                                                                                                                 | [1.2.6](#126-constraints)                   |
| Receipt fields                  | Checkout Receipt and Payment Receipt schemas, `reference` is the hash of the closed mandate                                                                                                                                                                        | [1.2.7](#127-receipts)                      |
| Hash for receipt `reference`    | same as `sd_hash`; algorithm is `_sd_alg`, or `sha-256`                                                                                                                                                                                                            | [1.2.4](#124-hashes)                        |
| Native constraint types         | `checkout.allowed_merchants`, `checkout.line_items`, `payment.agent_recurrence`, `payment.allowed_payees`, `payment.allowed_payment_instruments`, `payment.allowed_pisps`, `payment.amount_range`, `payment.budget`, `payment.reference`, `payment.execution_date` | [1.2.6](#126-constraints)                   |
| `merchant_authorization` format | detached JWS `<header>..<signature>` over JCS bytes of the checkout minus `ap2`; header claims `alg` and `kid`                                                                                                                                                     | [1.3.3](#133-merchant_authorization)        |
| UCP AP2 error codes             | seven codes, listed in [1.3.5](#135-error-codes)                                                                                                                                                                                                                   | [1.3.5](#135-error-codes)                   |
| Payment mandate in UCP          | `payment.instruments[*].credential.token`; internal format of the token is not specified                                                                                                                                                                           | [1.3.4](#134-carrying-the-mandates-in-ucp)  |
| Profile keys format             | top-level `keys[]`, a JWK Set; each entry requires `kid` and `kty`, EC keys also `crv`, `x`, `y`                                                                                                                                                                   | [1.3.2](#132-profile-and-keys)              |
| SD-JWT library choice           | Not answerable from the specs. The requirements it must meet are in [1.2.3](#123-sd-jwt-structure)                                                                                                                                                                 | library selection step                      |

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

#### 1.2.3 SD-JWT structure

- Mandates are SD-JWT credentials. "AP2 specifies the use of `SD-JWT`s for securing the Payment
  and Checkout Mandates." (`ap2/docs/specification.md`, "Verifiable Digital Credential Formats
  (VDCs)"). Key binding is used to close a mandate
  (`ap2/docs/agent_authorization.md`, "Mandate Structure").
- Mandate Content claims: `vct` (REQUIRED), `constraints` (OPTIONAL array), `cnf` (REQUIRED if
  the mandate is still open). `ap2/docs/agent_authorization.md`, "Mandates using SD-JWT VCs".
- The worked examples show the chain shape. The issuer-signed JWT carries a `delegate_payload`
  array of digest placeholders (`{"...": "<digest>"}`) and `_sd_alg`. A closed mandate is a
  key-binding JWT with header `typ` `kb+sd-jwt` and payload claims `iat`, `aud`, `nonce`,
  `sd_hash`, `_sd_alg`. Observed `aud` values: `merchant` for the checkout mandate,
  `credential-provider` for the payment mandate. Source: `ap2/docs/checkout_mandate.md`
  "Closed Checkout Mandate SD-JWT plus disclosures"; `ap2/docs/payment_mandate.md`, "Examples".
  These are non-normative examples, so the exact required claims for the key-binding JWT come
  from the external drafts below.
- `sd_hash` binds a closed mandate to the open mandate it was presented with
  (`ap2/docs/security_and_privacy_considerations.md`, "Manipulated Checkout";
  `ap2/docs/flows.md`, "Phase 2: Payment (Human Not Present)").
- Processing rules for a chain, in order: (1) verify and process the SD-JWT chain per Delegate
  SD-JWT, (2) check the closed mandate has the open mandate's claims unchanged, (3) evaluate
  every constraint against the closed mandate, where "Any unknown Constraints MUST be treated as
  failing evaluation". Source: `ap2/docs/agent_authorization.md`, "Verification and Processing
  Rules".
- The normative references include an external individual draft, "Delegate SD-JWT", and RFC 9901
  (SD-JWT). Neither is vendored (`ap2/docs/agent_authorization.md`, "References"). Chain
  processing details beyond the examples therefore cannot be confirmed from this repository.
  See [1.4](#14-not-specified-or-ambiguous-in-the-vendored-files).
- The `exp` and `nbf` clock skew is not specified anywhere in the vendored AP2 or UCP files.

#### 1.2.4 Hashes

| Hash                                      | Definition                                                                                                                                                                                                            | Source                                                                                                              |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `checkout_hash`                           | "base64url-encoded hash of the value of `checkout_jwt`. The algorithm used MUST be the same as the SD-JWT, as defined by the `_sd_alg` claim in the base payload, or `sha-256` if not present."                       | `ap2/docs/checkout_mandate.md`, "Mandate Schema"; `ap2/schemas/ap2/checkout_mandate.json`, property `checkout_hash` |
| `transaction_id` (closed Payment Mandate) | "base64url-encoded hash of the checkout_jwt field value, uniquely identifying the checkout associated with this. The hash algorithm used MUST be the same as the sd_hash field for this sd-jwt, or sha256 if absent." | `ap2/schemas/ap2/payment_mandate.json`, property `transaction_id`                                                   |
| Receipt `reference`                       | "The hash of the closed Mandate that this receipt is binding to", "calculated in the same manner as the `sd_hash` would be"                                                                                           | `ap2/schemas/ap2/checkout_receipt.json`, `payment_receipt.json`; `ap2/docs/specification.md`, "Dispute"             |
| `payment.reference` constraint            | `conditional_transaction_id` is the "Digest of the associated Open Checkout Mandate"; algorithm is `_sd_alg` of the SD-JWT the constraint is in, or `sha-256`                                                         | `ap2/schemas/ap2/open_payment_mandate.json`, `payment_reference`; `ap2/docs/payment_mandate.md`, "Reference"        |

Confirmed consequences:

- `transaction_id` and `checkout_hash` are computed from the same input, so for one checkout they
  are the same string. The examples show this: `NivWhuqfzcvZNapvIEJ2-3tsdQLkiuIcye2g46WVgX8`
  is both the `checkout_hash` in `ap2/docs/checkout_mandate.md` (closed example) and the
  `transaction_id` in `ap2/docs/payment_mandate.md` (closed example).
- The security text calls this out: "The `checkout_hash` embedded in the `transaction_id`
  securely links the payment to the associated Checkout Mandate"
  (`ap2/docs/security_and_privacy_considerations.md`, "Manipulated Payment").
- AP2 hashes are plain hashes with no domain-separation prefix. Domain separation applies only
  to hashes Countersign defines itself (decision log, evidence reference).
- The input bytes of the hash are described only as "the value of `checkout_jwt`" (a string, the
  compact serialization). The files say to store compact serializations so hashes can be
  recomputed (`ap2/docs/implementation_considerations.md`, "Hashes"). The byte encoding
  (ASCII of the compact form, as RFC 9901 defines for `sd_hash`) is not spelled out in the
  vendored files. See [1.4](#14-not-specified-or-ambiguous-in-the-vendored-files).
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
(`ap2/docs/agent_authorization.md`, "Mandates using SD-JWT VCs"). New constraints need "A uniquely
defined `type`", "A Schema, including which fields are selectively disclosable" and "The
evaluation algorithm" (`ap2/docs/specification.md`, "Mandate Constraints"). A collision-resistant
name such as an rDNS prefix or URN is RECOMMENDED (`ap2/docs/agent_authorization.md`, same
section).

Native types in v0.2. Sources: `ap2/docs/checkout_mandate.md`, "Constraints";
`ap2/docs/payment_mandate.md`, "Payment Mandate Constraints"; schemas in
`ap2/schemas/ap2/open_checkout_mandate.json` and `open_payment_mandate.json`.

| `type`                                | Mandate       | Fields                                                                                                                   | Evaluation (summary)                                                                                                                                                              |
| ------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `checkout.allowed_merchants`          | open checkout | `allowed` (array of merchant objects `id`, `name`, `website`, selectively disclosable)                                   | merchant must be among the revealed `allowed`; if none revealed, invalid                                                                                                          |
| `checkout.line_items`                 | open checkout | `items[]` each `id`, `acceptable_items[]` (`id`, `title`), `quantity`                                                    | each `items` entry matched by quantity, no entry or item used twice; maximal-flow formulation given. Does not support splitting one open mandate across several checkouts         |
| `payment.allowed_payees`              | open payment  | `allowed` (merchant objects)                                                                                             | `payee` of the Payment Mandate must be in `allowed`                                                                                                                               |
| `payment.allowed_payment_instruments` | open payment  | `allowed` (`id`, `type`, `description`)                                                                                  | `payment_instrument` must be in `allowed`                                                                                                                                         |
| `payment.allowed_pisps`               | open payment  | `allowed` (`legal_name`, `brand_name`, `domain_name`)                                                                    | facilitating PISP must be in `allowed`                                                                                                                                            |
| `payment.amount_range`                | open payment  | `currency`, `max` (integer minor units), optional `min` (integer minor units)                                            | `payment_amount` within `min` and `max`, currency must match                                                                                                                      |
| `payment.budget`                      | open payment  | `max` (JSON `number`), `currency`                                                                                        | requested amount plus the sum of previously closed Payment Mandates must be `<= max`; amount added after approval. Described as "To be used with the Agent Recurrence constraint" |
| `payment.agent_recurrence`            | open payment  | `frequency` (`ON_DEMAND`, `DAILY`, `WEEKLY`, `BIWEEKLY`, `MONTHLY`, `QUARTERLY`, `ANNUALLY`), optional `max_occurrences` | true if sufficiently separated in time from the previous presentation and `max_occurrences` not exceeded                                                                          |
| `payment.reference`                   | open payment  | `conditional_transaction_id`                                                                                             | the Checkout Mandate must contain an open Checkout Mandate with a matching hash in its delegate chain                                                                             |
| `payment.execution_date`              | open payment  | optional `not_before`, `not_after`                                                                                       | `execution_date` within the window                                                                                                                                                |

Other confirmed constraint facts:

- There is no native expiry constraint. Expiry is the `exp` claim on the mandate. The nearest
  constraint, `payment.execution_date`, restricts the payment execution date.
- There is no native category constraint.
- The open Checkout Mandate schema requires a `checkout.line_items` constraint (`contains`), and
  the open Payment Mandate schema requires a `payment.reference` constraint (`contains`).
- Both schemas list the allowed constraint types as a closed `anyOf` or `oneOf`. A custom type
  such as `countersign.category.allow.1` is allowed by the extension rule but does not validate
  against the vendored schemas, and a verifier without that extension must fail it ("Any unknown
  Constraints MUST be treated as failing evaluation").
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
  The mandate-specific schemas use `status`. See [1.4](#14-not-specified-or-ambiguous-in-the-vendored-files).
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
same section.

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
- JCS requires JSON integers within ±(2^53 - 1), and every UCP integer field is capped there
  (`ucp/docs/specification/overview/index.md`, "Integer range and ingestion").

#### 1.3.4 Carrying the mandates in UCP

Source: `ap2-mandates.md`, "Mandate Structure", "Step 3: Submission", and the schema file.

| Mandate          | UCP placement                                                                                                                                                                      |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Checkout Mandate | `ap2.checkout_mandate`, a string matching `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+(~[A-Za-z0-9_-]+)*$`. Request schema: omitted on create and update, required on complete |
| Payment Mandate  | `payment.instruments[*].credential.token` ("Contains the payment mandate (composite token)")                                                                                       |

- Mandates are "SD-JWT credentials with Key Binding (`+kb`)".
- "The checkout mandate MUST contain the full checkout response including the
  `ap2.merchant_authorization` field", creating a nested binding in which the platform signature
  covers the business signature.
- The credential internals "(claims, selective disclosure, key binding) is defined by the AP2
  Protocol Specification".
- UCP defines `token` for `token_credential` only as a string (`ucp/source/schemas/common/types/token_credential.json`),
  while the prose calls the Payment Mandate token a "composite token" and "composite object". The
  composite format is not specified.
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

### 1.4 Not specified or ambiguous in the vendored files

Each item is a gap that implementation work must resolve explicitly. The resolution chosen will be
recorded here as a Countersign decision.

1. **`checkout_jwt` versus `merchant_authorization`.** AP2 requires the Merchant to provide "a
   merchant-signed JWT containing the Checkout" and binds mandates to its hash. UCP defines the
   merchant signature as a detached JWS. The vendored files never say that `checkout_jwt` is the
   detached JWS with the JCS payload re-attached, nor what the JWT header `typ` is (the AP2
   example uses `"typ": "JWT"`). The AP2 example `checkout_jwt` payload is also not a UCP checkout
   object (it has `order_id` and floating-point prices), while the UCP extension says the
   `checkout_jwt` "MUST be the Checkout object". The exact bytes hashed for `checkout_hash` are
   therefore unconfirmed.
2. **Hash input encoding.** The hash is over "the value of `checkout_jwt`" and "calculated in the
   same manner as `sd_hash`". The encoding rule lives in RFC 9901, which is not vendored.
3. **Delegate SD-JWT details.** The chain format (`delegate_payload`, the `typ` values, how the
   user-signed open mandate and the agent key-binding JWT are concatenated) is defined by an
   external draft that is not vendored. The AP2 chained example token contains an empty element
   (`~~`). The UCP schema for `ap2.checkout_mandate` only allows non-empty base64url elements
   after the first `~`, with no dots. Tested against the pattern as written: a string with
   disclosures only matches, but a string with a trailing key-binding JWT (which contains dots), a
   trailing `~`, or an empty element does not. A standard SD-JWT with key binding therefore does not
   match the vendored pattern. Do not rely on that pattern for validation without a conformance
   test, and confirm the intended wire form with upstream (`ap2/docs/checkout_mandate.md`, "Open
   Checkout Mandate chained with a Closed Checkout Mandate";
   `ucp/source/schemas/common/payment_ap2_mandate.json`, `$defs.checkout_mandate`).
4. **Receipt field naming.** Schemas use `status` (`Success`, `Error`); the generic Mandate Receipt
   text uses `result` (`success`, `error`). Receipt signing format and header (`typ`, `alg`, `kid`)
   are not specified beyond "signed JWT". How the Checkout Receipt travels back in a UCP response is
   not specified.
5. **Payment Mandate token format.** The "composite token" structure inside
   `payment.instruments[*].credential.token` is not specified, and UCP types the token as a string.
6. **Error transport.** HTTP status and message envelope for the seven AP2 error codes are not
   specified ([1.3.5](#135-error-codes)).
7. **Clock skew.** No skew for `exp` or `nbf` is stated.
8. **Constraint number formats.** `payment.amount_range` fields are integers in minor units, but the
   prose example shows `"max": 100.50`. `payment.budget.max` is typed as a JSON `number` with no
   stated unit, and its prose example shows `1000.00`
   (`ap2/schemas/ap2/open_payment_mandate.json`; `ap2/docs/payment_mandate.md`, "Amount Range" and
   "Budget"). The example in the open Payment Mandate uses `"max": 20000` for a USD range, which
   fits minor units. The unit of `payment.budget.max` is not settled.
9. **Selective disclosure of whole constraints.** Which constraint fields are selectively
   disclosable is defined per schema by `x-selectively-disclosable-field` and
   `x-selectively-disclosable-array` markers. The mapping to concrete disclosures for each custom
   constraint will be written alongside the constraint schemas.
10. **Stale overview page.** `ucp/docs/documentation/ucp-and-ap2.md` uses older names
    (`checkoutSignature`, `CheckoutMandate`, `PaymentMandate`) that differ from the extension
    specification. The extension specification and its schema are treated as authoritative.
11. **Version literal.** The UCP version string is a template variable in the docs
    ([1.3.2](#132-profile-and-keys)).
12. **Principal identity.** Neither AP2 nor UCP defines a customer id. UCP identifies the platform
    by profile URI and `keys[]`; AP2 identifies the agent by the `cnf` key and the user by the
    delegating credential or provider key.

---

## 2. Deviations from the working design

Places where the vendored specifications contradict or refine an assumption in the working design
used to plan this project. Each lists the spec fact and the consequence.

| #   | Working design assumption                                                                                                 | What the spec says                                                                                                                                                                                                                                                                | Consequence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --- | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | The Payment Mandate `transaction_id` is a unique id whose single use can be enforced                                      | `transaction_id` is the base64url hash of `checkout_jwt` and equals `checkout_hash` for the same checkout ([1.2.4](#124-hashes))                                                                                                                                                  | Single-use enforcement is a Countersign rule keyed on this checkout hash plus the mandate nonce, not a property the spec gives. A checkout id and its hash identify the same thing, so "unused `transaction_id`" means "no earlier authorization for this checkout hash"                                                                                                                                                                                                                                                                      |
| D2  | AP2 natively defines amount, merchant and expiry constraints                                                              | Natively defined: ten types ([1.2.6](#126-constraints)). Amount range and allowed merchants exist. Expiry is the `exp` claim, not a constraint. Allowed payees, line items, payment instruments, PISPs, recurrence, budget, reference and execution date also exist               | Reuse `payment.amount_range`, `checkout.allowed_merchants` and `payment.allowed_payees`, and enforce `exp` as a claim check                                                                                                                                                                                                                                                                                                                                                                                                                   |
| D3  | AP2 defines the extension mechanism but not a cumulative budget, so a custom cumulative budget constraint is entirely new | AP2 defines `payment.budget` with `payment.agent_recurrence`, where evaluation needs the verifier to track previously closed Payment Mandates ([1.2.6](#126-constraints))                                                                                                         | The innovation claim must be restated: AP2 has a budget constraint whose state source is left to the verifier. What Countersign adds is a state source reconciled from PayPal responses and webhooks, a window, and enforcement at capture time. Use `payment.budget` where it fits and document where `countersign.budget.cumulative.1` differs. The unit of `payment.budget.max` is unsettled ([1.4](#14-not-specified-or-ambiguous-in-the-vendored-files), item 8), so a Countersign budget constraint uses integer minor units explicitly |
| D4  | Open mandates can express "headphones under $80 this week" with a plain amount and category                               | The open Checkout Mandate must contain a `checkout.line_items` constraint listing acceptable items, and the open Payment Mandate must contain `payment.reference`. There is no native category constraint ([1.2.6](#126-constraints))                                             | The intent screen must resolve a category into an explicit `acceptable_items` list drawn from the catalog, plus `payment.amount_range`. `countersign.category.allow.1` is an extra constraint on top, not a replacement                                                                                                                                                                                                                                                                                                                       |
| D5  | Custom constraint types can be added and validated against the standard schemas                                           | The vendored open-mandate schemas enumerate only known types, and unknown constraints "MUST be treated as failing evaluation" ([1.2.6](#126-constraints))                                                                                                                         | Custom constraints validate against Countersign's own schemas only, and a third-party AP2 verifier will reject them. State this in the limitations. The error to return for an unknown type in our own verifier is `unresolved_constraint`                                                                                                                                                                                                                                                                                                    |
| D6  | A device-bound customer key registered with Countersign signs the open mandates                                           | AP2 defines two trust models: User Credential and Trusted Agent Provider. A directly trusted user key is named only as a possible future model ([1.2.9](#129-who-can-be-trusted-to-sign-for-the-user)). UCP's two options are the same ([1.3.1](#131-capability-and-negotiation)) | The device-key flow is a Countersign trust model, outside the two defined ones. It must be documented as such, with the registration of the key as the trust anchor, and must not be presented as AP2 conformance of the user-credential kind. Because Countersign also plays Merchant, CP and MPP, the same party trusts the key it registered                                                                                                                                                                                               |
| D7  | The Payment Mandate travels in `payment.instruments[*].credential.token`                                                  | Confirmed, but the token's internal format is not specified and UCP types it as a string ([1.3.4](#134-carrying-the-mandates-in-ucp))                                                                                                                                             | Countersign must define and document its own encoding of the token, and it is a Countersign decision, not spec                                                                                                                                                                                                                                                                                                                                                                                                                                |
| D8  | `vp_formats_supported` is a profile-level key next to `keys[]`                                                            | It sits under `config` in the AP2 capability entry; `keys[]` is a top-level profile member ([1.3.2](#132-profile-and-keys))                                                                                                                                                       | Place `vp_formats_supported` inside the capability `config` object                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| D9  | The UCP Security Lock may be strengthened to the principal                                                                | Confirmed that the lock in UCP is per session only ([1.3.1](#131-capability-and-negotiation))                                                                                                                                                                                     | No contradiction: the principal lock is an addition. Principal identity is not defined by either spec ([1.4](#14-not-specified-or-ambiguous-in-the-vendored-files), item 12), so how a principal is derived is a Countersign decision                                                                                                                                                                                                                                                                                                         |
| D10 | Domain-separated hash helpers are used for every hash                                                                     | AP2 `checkout_hash`, `transaction_id`, `sd_hash` and receipt `reference` are plain unprefixed hashes with a spec-defined algorithm ([1.2.4](#124-hashes))                                                                                                                         | Domain separation must be limited to Countersign-internal hashes (decision log, evidence reference). AP2 hashes use the spec algorithm with no prefix                                                                                                                                                                                                                                                                                                                                                                                         |
| D11 | Amounts are integer minor units everywhere                                                                                | True for UCP and for AP2 `payment_amount` and `amount_range`. `payment.budget.max` is a JSON `number` and prose examples show decimals ([1.4](#14-not-specified-or-ambiguous-in-the-vendored-files), item 8)                                                                      | Reject non-integer or ambiguous numbers in any constraint Countersign evaluates. UCP quantity may be a non-whole step count with a scale, so line total math must honour `quantity_unit.scale` or reject non-`each` items explicitly                                                                                                                                                                                                                                                                                                          |
| D12 | Receipts use one field naming                                                                                             | Schemas use `status` with `Success` and `Error`; the generic receipt text uses `result` with `success` and `error` ([1.4](#14-not-specified-or-ambiguous-in-the-vendored-files), item 4)                                                                                          | Follow the mandate schemas (`status`) because they are the machine-readable definition                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

Facts confirmed with no deviation: the five roles and the non-agentic Trusted Surface rule, the
exact `vct` strings, `cnf` as an RFC 7800 claim, JCS (RFC 8785) for `merchant_authorization`, the
detached JWS format with `alg` and `kid`, the seven UCP AP2 error codes, anti-reuse via rejection
receipts, the five dispute verification steps, `mandate_required` on a missing checkout mandate,
UCP integer minor-unit amounts, and the MPP rule that the credential must be scoped to the
checkout.

---

## Still to be written

Added by later work, not yet present in this file:

- Confirmed PayPal facts (identifier lengths, idempotency, order changes after authorization,
  authorization validity, webhooks, vaulting).
- Library choices for JCS, JWS and SD-JWT with key binding.
- Countersign constraint schemas and evaluation algorithms.
- Resolutions for each gap in [1.4](#14-not-specified-or-ambiguous-in-the-vendored-files).
- Gate step codes, principal lock semantics, the evidence reference encoding and the PayPal field
  mapping in both directions.

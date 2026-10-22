# Vendored specifications

Read-only copies of upstream specifications, kept so the protocol rules this project implements are
pinned and reviewable offline. Files are copied byte for byte. Do not edit them. To update, re-copy
from a new pinned revision, regenerate `CHECKSUMS.sha256` and update this file.

AP2, UCP and ACP are licensed under the Apache License 2.0. Each project's `LICENSE` file (and
`NOTICE` where upstream ships one) sits next to its vendored files. The two IETF documents
(RFC 9901 and the Delegate SD-JWT draft) fall under the IETF Trust Legal Provisions, see
"IETF documents" below. No vendored file has been modified.

| Project | Directory | Upstream | Pinned revision | Commit | License |
|---|---|---|---|---|---|
| AP2 (Agent Payments Protocol) | `ap2/` | https://github.com/google-agentic-commerce/AP2 | tag `v0.2.0` (2026-04-28) | `b4587ac1d055888a73b4b21750973cffba961793` | Apache-2.0 |
| UCP (Universal Commerce Protocol) | `ucp/` | https://github.com/Universal-Commerce-Protocol/ucp | tag `v2026-08-25` | `cd78fb38e819de77d9b527d110476eccb876f1bd` | Apache-2.0 |
| ACP (Agentic Commerce Protocol) | `acp/` | https://github.com/agentic-commerce-protocol/agentic-commerce-protocol | spec version `2026-04-17` | `7fdd78df677a94dce04c770644b0fbbb1401272b` | Apache-2.0 |
| SD-JWT, RFC 9901 | `rfc9901/` | https://www.rfc-editor.org/rfc/rfc9901.txt | RFC 9901 (November 2025) | not applicable (published RFC) | IETF Trust, see below |
| Delegate SD-JWT draft, current | `delegate-sd-jwt/` | https://github.com/GarethCOliver/oauth-delegate-sd-jwt | `draft-ietf-oauth-delegate-sd-jwt` as of `main` | `d52539c46b9b1866a1c5fa96797dbf1ac58d0986` (2026-10-19) | IETF contribution, see below |
| Delegate SD-JWT draft, as of AP2 v0.2.0 | `delegate-sd-jwt/` | same repository | `draft-gco-oauth-delegate-sd-jwt` | `4bf1330036` (2026-03-06, last content change before AP2 v0.2.0 on 2026-04-28) | IETF contribution, see below |

## What is vendored

### `ap2/` (from tag v0.2.0)
- `docs/`: `specification.md`, `flows.md`, `checkout_mandate.md`, `payment_mandate.md`,
  `agent_authorization.md`, `implementation_considerations.md`,
  `security_and_privacy_considerations.md`, `glossary.md`
- `schemas/`: JSON Schemas for the mandates and receipts (from `code/sdk/schemas/`)
- `CHANGELOG.md`

### `ucp/` (from tag v2026-08-25)
- `docs/specification/`: all Markdown specification pages, including shopping checkout (REST,
  MCP, A2A, embedded bindings), `signatures.md`, and
  `payment/extensions/ap2-mandates.md`
- `docs/documentation/ucp-and-ap2.md`
- `source/`: all JSON Schemas, OpenAPI and OpenRPC documents

### `acp/` (spec version 2026-04-17)
- `spec/2026-04-17/`: JSON Schemas, OpenAPI documents and the OpenRPC document
- `changelog/2026-04-17.md`

### `rfc9901/`
- `rfc9901.txt`: Selective Disclosure for JSON Web Tokens, the SD-JWT specification that AP2 cites
  as its normative SD-JWT reference.

### `delegate-sd-jwt/`
- `draft-ietf-oauth-delegate-sd-jwt.md`: the Delegate SD-JWT draft at the pinned `main` commit.
  The repository was renamed and the draft retitled for OAuth working group adoption on
  2026-10-19. AP2 v0.2.0 cites this draft as "Delegate SD-JWT (Individual Draft)".
- `draft-gco-oauth-delegate-sd-jwt.md`: the same draft at commit `4bf1330036`, the last content
  change before AP2 v0.2.0 was released. Kept so differences between the version AP2 was written
  against and the current one can be seen. Later commits changed the `typ` value text and made
  editorial edits.
- `LICENSE.md`, `CONTRIBUTING.md`: copied from upstream.

## IETF documents

- **RFC 9901** carries the notice "Copyright (c) 2025 IETF Trust and the persons identified as the
  document authors. All rights reserved." and states that it is subject to BCP 78 and the IETF
  Trust's Legal Provisions Relating to IETF Documents. Code components extracted from it are under
  the Revised BSD License. The file is an unmodified copy kept with its notice.
- **The Delegate SD-JWT draft** is an Internet-Draft source file (`ipr = "trust200902"`). Upstream
  `LICENSE.md` only points to `CONTRIBUTING.md`, which states that all material in the repository
  is a Contribution to the IETF Standards Process under BCP 78, BCP 79 and the IETF Trust Legal
  Provisions. GitHub reports the license as unspecified. The drafts are kept as unmodified,
  attributed reference copies. They are an individual draft that is not yet an RFC and can change.

## Not vendored
- Images and other binary assets (Markdown image links to them will not resolve offline).
- Reference code, SDKs, samples and build tooling. Project code is written from scratch.
- Other ACP spec versions.
- RFC 7800 (`cnf`), RFC 7515 (JWS) and RFC 8785 (JCS). They are referenced by the vendored documents
  but are not copied.

## Notes
- ACP publishes dated spec directories but no git tags or releases. The pin is the commit above;
  the `2026-04-17` directory was copied from that commit.
- `CHECKSUMS.sha256` lists a SHA-256 for every vendored file. Verify with:
  `cd spec/vendor && shasum -a 256 -c CHECKSUMS.sha256`

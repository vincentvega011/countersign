# Vendored specifications

Read-only copies of upstream specifications, kept so the protocol rules this project implements are
pinned and reviewable offline. Files are copied byte for byte. Do not edit them. To update, re-copy
from a new pinned revision, regenerate `CHECKSUMS.sha256` and update this file.

All three upstream projects are licensed under the Apache License 2.0. Each project's `LICENSE`
file (and `NOTICE` where upstream ships one) sits next to its vendored files. No vendored file has
been modified.

| Project | Directory | Upstream | Pinned revision | Commit | License |
|---|---|---|---|---|---|
| AP2 (Agent Payments Protocol) | `ap2/` | https://github.com/google-agentic-commerce/AP2 | tag `v0.2.0` (2026-04-28) | `b4587ac1d055888a73b4b21750973cffba961793` | Apache-2.0 |
| UCP (Universal Commerce Protocol) | `ucp/` | https://github.com/Universal-Commerce-Protocol/ucp | tag `v2026-08-25` | `cd78fb38e819de77d9b527d110476eccb876f1bd` | Apache-2.0 |
| ACP (Agentic Commerce Protocol) | `acp/` | https://github.com/agentic-commerce-protocol/agentic-commerce-protocol | spec version `2026-04-17` | `7fdd78df677a94dce04c770644b0fbbb1401272b` | Apache-2.0 |

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

## Not vendored
- Images and other binary assets (Markdown image links to them will not resolve offline).
- Reference code, SDKs, samples and build tooling. Project code is written from scratch.
- Other ACP spec versions.

## Notes
- ACP publishes dated spec directories but no git tags or releases. The pin is the commit above;
  the `2026-04-17` directory was copied from that commit.
- `CHECKSUMS.sha256` lists a SHA-256 for every vendored file. Verify with:
  `cd spec/vendor && shasum -a 256 -c CHECKSUMS.sha256`

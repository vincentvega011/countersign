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
the restricted role. Whether the hosted Postgres allows a second, restricted login role was not
checked ([ENV.md](ENV.md) section 4 does not say). Check at the Render deploy that the service uses
the restricted role; if it cannot, record the fallback here and rely on the anchors in L8.

### L10. Throughput and clocks

All appends take one advisory lock, so the log is a single-writer bottleneck by design; at demo scale
(tens of entries per purchase) this is irrelevant. Timestamps come from the writer's clock and are
not required to be monotonic, so a day tree is defined by `ts_us` and ordered by `seq`. A log
`append` joins the caller's transaction, so INV-12 callers must commit it before responding.

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

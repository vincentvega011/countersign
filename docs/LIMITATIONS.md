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

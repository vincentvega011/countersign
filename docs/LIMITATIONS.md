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

In the redirect approval mode, the sandbox accepted a PATCH of items and amount while the order was
`APPROVED`, and authorize then authorized the patched amount. After authorization every tried PATCH
was rejected. The window is therefore between approval and authorization, and the protection is the
gate re-deriving the terms from the live order and comparing them with the signed checkout. The gate
is not built yet, so this mitigation is a design, not a tested result; the PATCH behavior above is
from one sandbox account.

### L4. Partial captures are possible

PayPal allows several partial captures against one authorization. Countersign always captures the
full checkout total with `final_capture` set to true, and budget accounting is designed to sum every
capture on the authorization, so a partial capture made outside Countersign still counts against the
budget.

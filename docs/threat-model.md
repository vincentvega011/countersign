# Threat model

Notes recorded so far. The full model (assets, actors, trust boundaries, and each attack category
mapped to an invariant and a test) is written later.

## Order changes between payer approval and authorization

- **Fact.** In the sandbox, PATCH of an order's items and amount was accepted while the order was
  `APPROVED`, and authorize then authorized the patched amount, with no new payer approval. After
  authorization every PATCH was rejected ([PROTOCOL.md](PROTOCOL.md) section 4.3).
- **Who can do it.** PayPal's schema lists only OAuth 2.0 bearer authentication for the update
  order operation (documentation, not tested with other credentials). The PATCH calls in the runs
  used the merchant app's access token. The modeled actor is therefore a compromised or buggy
  merchant-side component, or a confused deputy using the merchant app credentials, not the buyer
  or the agent. Countersign does not claim that the agent can alter orders.
- **Defense.** The pre-authorize check ([PROTOCOL.md](PROTOCOL.md) Decision 11), with the capture
  gate as the second layer.
- **Attack case.** `order_changed_after_approval`.

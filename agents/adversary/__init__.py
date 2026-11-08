"""The scripted adversary: a separate process that attacks a Countersign instance over HTTP only.

It imports nothing from `countersign` (Decision 130, enforced by `tests/unit/test_adversary_boundary.py`),
holds no PayPal credential and has no database access. It is scripted, not model-planned (L65). What
the customer signed and when the payer approves at PayPal come from a `Counterparties` object the
caller provides, because those are not things an agent can do.
"""

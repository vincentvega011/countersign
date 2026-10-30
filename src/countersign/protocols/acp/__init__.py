"""ACP thin adapter. See docs/PROTOCOL.md Decisions 51 to 54.

Imports `canonical`, `checkout`, `catalog`, `ledger` and the shared lock entry point; no policy lives
here. `lock/`, `constraints/`, `gate/`, `cp/` and `merchant/` import no protocol adapter.
"""

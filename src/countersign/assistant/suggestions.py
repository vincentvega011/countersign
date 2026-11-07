"""The recorded questions offered as chips. Their planner calls are recorded once (record script) and
replayed offline; changing a question's text or the catalog changes the cassette key and needs a new
recording (docs/PROTOCOL.md Decision 127)."""

from __future__ import annotations

SUGGESTIONS: tuple[tuple[str, str], ...] = (
    ("How many orders are there?", "How many orders are there in total?"),
    ("Captured orders", "How many orders were captured, and for how much in total?"),
    ("Blocked by reason", "How many blocked or voided attempts are there for each reason code?"),
    ("Voided orders", "Which orders were voided by the capture gate?"),
    ("Unauthorized captures", "How many orders were captured with no verified mandate?"),
    ("Open mandates", "How many open mandates are there in each state?"),
    ("Used mandates", "Which open mandates have been used, and how much was spent under them?"),
    ("Evidence for an order", "Which evidence steps passed for the latest_captured order?"),
    ("What is mandate_expired?", "What does the mandate_expired code mean?"),
    ("Full versus baseline", "How does full protection mode compare with baseline mode in the latest evaluation?"),
)  # fmt: skip

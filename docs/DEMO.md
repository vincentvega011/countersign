# Demo click path (local, for the video)

Checked end to end on 8 Nov 2026 against a local dev instance (APP_ENV=dev, CS_MODE=full) with a browser script: orders,
order detail, an attack run, Results, and the assistant ran with no console errors. Every number the video quotes comes from the
frozen run in [PROGRESS.md](PROGRESS.md), never from memory.

## Start

```
make db                                    # Postgres (or your own on localhost:5432)
uv run --env-file .env alembic upgrade head
make keys                                  # once
make dashboard-build
make dashboard-seed                        # simulated rows (labelled) and the recorded sandbox rows
uv run --env-file .env uvicorn countersign.main:create --factory --port 8000
```

Open `http://localhost:8000/dashboard/`. The header says "Sandbox demo": simulated and recorded data is labelled in the grid.

## Clicks

1. **Orders.** The grid opens on Agent orders. Point at the Mandate, Gate and Capture columns. Tick "Group by agent and customer"
   once to show the pivot, untick it.
2. **Order detail.** Click any row whose Gate says passed. Show the three panels (signed checkout, mandates, live PayPal order)
   and the gate timeline under them.
3. **Evidence.** In the detail, click "Open evidence", then "Verify evidence". Twelve steps run in the browser; eleven pass and the
   twelfth, `trusted_keys`, reports that no keys were pinned (the same as on `/verify/`). Say so.
4. **Attack side by side.** Open Protection, scroll to the Attack matrix, pick `protocol_downgrade_acp` in the select, click
   Run attack. The result table shows baseline "money captured outside what was signed: Yes" and full "No" with
   `mandate_required`. Twelve scripted goals are offered.
5. **Results.** Open Results. Read the four tiles (all 0 in full), the per-category and per-ablation charts, and the Targets
   grid, where the missed rows are visible on purpose.
6. **Ask Countersign.** Open Assistant, click "Full versus baseline" (a recorded question, replayed offline), then expand
   "Sources for this answer" to show the citation chips. Free text outside the recordings gets a fixed message.

## What not to say

Nothing here is live PayPal except the recorded rows labelled recorded. Latency is simulator latency. Do not claim protection
eligibility or dispute outcomes (INV-13). The evidence target was missed for evaluation captures (L68); say "the recorded sandbox
capture verifies in both verifiers" and no more.

# Demo click path (local, for the video)

Checked end to end on 8 Nov 2026 against a local dev instance (APP_ENV=dev, CS_MODE=full) with a browser script: orders,
order detail, an attack run, Results, and the assistant ran with no console errors. Every number the video quotes comes from the
frozen run in [PROGRESS.md](PROGRESS.md), never from memory.

## Start

From a fresh clone, with no PayPal credentials (Postgres must be running; `docker compose up -d --wait postgres`):

```
make demo
```

It installs, makes the keys, builds the dashboard, migrates, seeds and prints the URLs (landing page, dashboard, verifier, UCP profile,
`/health`, `/selfcheck`). In this local mode the "Run attack" launcher is enabled. The longer form for development, with your own `.env`:
`make db`, `uv run --env-file .env alembic upgrade head`, `make keys`, `make dashboard-build`, `make dashboard-seed`, then
`uv run --env-file .env uvicorn countersign.main:create --factory --port 8000`.

Open `http://localhost:8000/` (the landing page) and `http://localhost:8000/dashboard/`. The header says "Sandbox demo": simulated and recorded data is labelled in the grid.

## Clicks

1. **Orders.** The grid opens on Agent orders. Point at the Mandate, Gate and Capture columns. Tick "Group by agent and customer"
   once to show the pivot, untick it.
2. **Order detail.** Click any row whose Gate says passed. Show the three panels (signed checkout, mandates, live PayPal order)
   and the gate timeline under them.
3. **Evidence.** In the detail, click "Open evidence", then "Verify evidence". Twelve steps run in the browser; eleven pass and the
   twelfth, `trusted_keys`, reports that no keys were pinned (the same as on `/verify/`). Say so.
4. **Attack side by side** (local, `make demo`; on the hosted demo the launcher is off and the recorded results are shown). Open Protection, scroll to the Attack matrix, pick `protocol_downgrade_acp` in the select, click
   Run attack. The result table shows baseline "money captured outside what was signed: Yes" and full "No" with
   `mandate_required`. Twelve scripted goals are offered.
5. **Results.** Open Results. Read the four tiles (all 0 in full), the per-category and per-ablation charts, and the Targets
   grid, where the missed rows are visible on purpose.
6. **Evidence verifier try-it** (`/verify/?try=synthetic`). The synthetic sample loads and all twelve steps pass. Press "Change one field,
   then verify again": the first failing step is PayPal order, authorization and capture (`paypal_amount`). Press "Load and verify the
   recorded sandbox sample": every step passes except Trusted keys (`keys_not_pinned`, L76); press "Pin the keys inside this sample"
   and it passes. Say that the pinned keys came from the sample, so it shows the mechanism and not authorship. The offline Python
   verifier (`python -m countersign_verify tests/vectors/recorded/p3_capture_bundle.json`) gives the same results.
7. **Ask Countersign.** Open Assistant, click "Full versus baseline" (a recorded question, replayed offline), then expand
   "Sources for this answer" to show the citation chips. Free text outside the recordings gets a fixed message.

## What not to say

Nothing here is live PayPal except the recorded rows labelled recorded. Latency is simulator latency. Do not claim protection
eligibility or dispute outcomes (INV-13). The evidence target was missed for evaluation captures (L68); say "the recorded sandbox
capture verifies in both verifiers" and no more.

## Hosted demo: what is seeded and what is recorded

On the hosted instance (`APP_ENV=demo`, set up in [DEPLOY.md](DEPLOY.md)) the database is filled once by `python -m countersign.demo_seed`.
The dashboard labels every order with its source:

| Label       | What it is                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------------------ |
| `recorded`  | The capture gate cassette recorded from the real PayPal sandbox: capture **49029167TJ689282S** and one void   |
| `simulator` | Orders made by the real app over the in-memory PayPal simulator, five open mandates (`om_sim_*`: unused, in flight, used, revoked, expired) and one order with a bundle made from the committed synthetic vector |

Nothing seeded is labelled as a live sandbox capture, and no device key is seeded. "Run attack" is disabled on the hosted demo (the panel
says so) and the side by side results are the recorded ones from the frozen run `20261108T063449Z`. Ask Countersign answers the
recorded suggested questions only; no model key is configured.

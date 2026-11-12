# Countersign

Let any PayPal merchant accept AI-agent purchases, with cryptographic proof of what the customer approved, enforced at the moment PayPal captures the money.

Countersign sits in front of a merchant's PayPal Orders integration. A customer approves a purchase intent on their phone with a
device-bound key; a shopping agent buys under that approval over the UCP checkout with the AP2 mandates extension; Countersign
checks the signed mandates before it asks PayPal to authorize, and re-reads the live PayPal order immediately before it captures,
voiding the authorization if anything differs from what was signed. Every capture leaves a dispute evidence bundle that anyone can
verify offline. **PayPal sandbox only**: no live credential is used or accepted anywhere, and nothing here claims PayPal buyer or
seller protection or any dispute outcome.

- Hosted demo: <https://countersign-demo-xb79.onrender.com> (free tier: the first request after 15 idle minutes takes about a minute). The landing page at `/` links everything below.
- Source: <https://github.com/vincentvega011/countersign>

## 60-second tour of the hosted demo

Everything on the hosted demo is labelled. Rows marked **simulator** were made by the real application over an in-memory PayPal
simulator; rows marked **recorded** replay one real PayPal sandbox capture (`49029167TJ689282S`, USD 69.00). Nothing is a live payment.

1. **Landing page** (`/`): what it is and where to click.
2. **Dashboard** (`/dashboard/`): the Agent orders grid. Look at the Mandate, Gate and Capture columns. Click a row whose Gate says passed to see the signed checkout, the mandates and the live PayPal order side by side, with the gate steps under them.
3. **Evidence verifier** (`/verify/?try=synthetic`): one click loads a sample bundle and checks all twelve steps in your browser. Press **Change one field, then verify again** to see exactly which step fails and why. The **recorded sandbox sample** fails one step on purpose (Trusted keys, because its keys are not pinned, limitation L76); pin the keys inside it to see that step pass.
4. **Protection** in the dashboard: the attack matrix and the recorded side-by-side results of a baseline gateway against Countersign. The "Run attack" launcher is off on the hosted demo and works locally (below).
5. **Results**: the frozen evaluation (the numbers below), including the targets that were missed.
6. **Assistant**: click "Full versus baseline". It answers a recorded question with citations to the rows it used.

## Run it locally

No PayPal credentials are needed. You need Postgres on `localhost:5432`, [uv](https://docs.astral.sh/uv/) (it installs Python 3.12), Node 22 or newer, and pnpm 12 (`corepack enable`).

```
git clone https://github.com/vincentvega011/countersign.git
cd countersign
docker compose up -d --wait postgres   # or point DATABASE_URL at your own Postgres (see below)
make demo
```

`make demo` runs `scripts/demo.sh`: it installs the dependencies, creates the two signing keys, builds the dashboard (about a
minute the first time; AG Studio shows a trial watermark without a licence key, which is fine), migrates, adds the labelled demo
data, and starts the app on port 8000. It prints:

```
  Landing page         http://localhost:8000/
  Dashboard            http://localhost:8000/dashboard/
  Evidence verifier    http://localhost:8000/verify/?try=synthetic
  UCP profile          http://localhost:8000/.well-known/ucp
  Health               http://localhost:8000/health
  Self-check           http://localhost:8000/selfcheck
```

Open the dashboard, go to **Protection**, pick `protocol_downgrade_acp` and press **Run attack**. The app builds a baseline and a
full instance over the PayPal simulator on scratch databases, attacks both, and shows "money captured outside what was signed":
yes for baseline, no for full, with the reason code. The launcher is enabled only in this local mode (`APP_ENV=dev`); it creates
and drops scratch databases on the same Postgres server, so the database user needs `CREATEDB` and `CREATEROLE` (the Docker
Postgres user has both). Set `DATABASE_URL` (a `postgresql+psycopg://` URL) to use another server, `PORT` to change the port.

**What needs real credentials, and what does not**

| Needs nothing                                                                                                                                                | Needs PayPal sandbox credentials                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Landing page, dashboard on seeded data, evidence verifier and its try-it, UCP profile, "Run attack", the offline verifier, the test suite and the evaluation | A purchase against the real PayPal sandbox (`scripts/sandbox_smoke.py`, the shopping agent against a live instance), and the PayPal webhook |

For those, copy `.env.example` to `.env`, fill in your own sandbox app's client id and secret (never a live one; the code refuses
the live hosts), and see [docs/ENV.md](docs/ENV.md) and [docs/DEPLOY.md](docs/DEPLOY.md).

### Tests and evaluation

```
make test            # the whole Python suite (needs Postgres); includes the browser tests
make test-safety     # strict typing and the tests of the modules that decide about money, identity and evidence
make lint            # ruff, mypy, prettier and the secret scan
make eval            # every suite, both modes, three seeds, every ablation (a few minutes)
uv run python -m eval.run --suite attacks --mode both   # just the 40 attack cases
```

The browser tests drive Chromium: run `pnpm --filter @countersign/approve exec playwright install chromium` once.

## Architecture

```text
 Customer phone                   Shopping agent (LLM)           Adversary agent (scripted)
 Trusted Surface (web/approve)    agents/shopper                 agents/adversary
 device key signs consent              | UCP over HTTP                 | UCP or ACP
        |                              v                               v
        |        +-------------------------------------------------------------------+
        +------->| Edge (FastAPI): strict JSON, size limits, request hashing         |
                 +----------------+------------------------------+-------------------+
                                  v                              v
                      +-------------------------+      +---------------------+
                      | UCP adapter + AP2 ext   |      | ACP adapter (thin)  |
                      +------------+------------+      +----------+----------+
                                   +------------ canonical -------+
                                                   v
   +--------------------+   +----------------------------+   +--------------------------+
   | Merchant role      |-->| Principal lock             |-->| Constraint evaluation    |
   | checkout mandate   |   | protocol independent       |   | native AP2 constraints   |
   +--------------------+   +----------------------------+   +-------------+------------+
                                                                           v
        +-------------------------------------------------------------------------------+
        | Credential Provider: verify Payment Mandate, reserve, create PayPal order      |
        +------------------------------------+------------------------------------------+
                                             v
        +-------------------------------------------------------------------------------+
        | Payment Processor + capture gate: fetch live state, compare, capture or void   |
        +------------------+---------------------------------------+--------------------+
                           v                                       v
          +-------------------------------+        +---------------------------------+
          | Hash-chained decision log     |        | Evidence bundles by capture id  |
          +-------------------------------+        +---------------------------------+
```

Countersign plays the AP2 Merchant, Credential Provider, Merchant Payment Processor and Trusted Surface roles for one merchant (AP2
allows one entity to play several; in production the Credential Provider would usually be the customer's wallet provider). The shopping
agent is a separate process that speaks only HTTP. Details: [docs/architecture.md](docs/architecture.md), wire formats and every design
decision: [docs/PROTOCOL.md](docs/PROTOCOL.md), attacks and defenses: [docs/threat-model.md](docs/threat-model.md).

## Results

From the frozen evaluation run `20261108T063449Z` (full report: [eval/reports/20261108T063449Z/report.md](eval/reports/20261108T063449Z/report.md), data: [eval/reports/latest.json](eval/reports/latest.json)). Ground truth is PayPal state held by the PayPal **simulator**, the decision log and the two evidence verifiers.

|                                                          | Countersign (full)         | Baseline gateway |
| -------------------------------------------------------- | -------------------------- | ---------------- |
| Attack cases that captured money outside what was signed | 0 of 40                    | 11 of 40         |
| Unauthorized captures (attack suite)                     | 0                          | 12               |
| Duplicate PayPal objects                                 | 0                          | 0                |
| Scripted adversary goals that succeeded                  | 0 of 12                    | 6 of 12          |
| Legitimate tasks completed                               | 81 of 81                   | 81 of 81         |
| False blocks                                             | 0                          | 0                |
| Gate added latency (simulator)                           | +18.3 ms p50, +22.3 ms p95 | none             |

The baseline is a deliberately careful gateway that verifies mandates per session but has no capture gate, principal lock, global
single use or reconciled budgets. Three targets were **missed**: evidence bundles for every evaluation capture (0 of 37; only the one
recorded sandbox capture has a bundle, L68), a model-planned adversary with a success rate and confidence interval (cut, L65), and spec
conformance as a runner suite.

**What these numbers do not show.** 29 of the 40 attack cases are blocked by the baseline too, so they widen coverage without
separating the two modes. The adversary is twelve fixed scripts, not an adaptive attacker. Latency is over the in-memory simulator,
not PayPal round trips. The legitimate tasks run through a test issuer, not the model-driven shopper or live PayPal. Seeds change only
the property tests' examples. Nothing here is a claim about PayPal protection programs or dispute outcomes.

## How AI is used

- **Shopping agent** (`agents/shopper`): a model turns a plain-language goal into structured constraints for the customer to approve, searches the catalog and builds the checkout. It talks only HTTP to the public checkout endpoints and signs with its own key, held in its own process.
- **Ask Countersign** (`src/countersign/assistant`): a merchant assistant that only **plans**. The model picks among read-only tools; the answer is built from fixed templates over the rows those tools returned, and every number cites its source row. It cannot authorize, capture, refund or change anything. Offline it replays recorded answers (ten suggested questions); there is no model key on the hosted demo.
- **Model gateway** (`src/countersign/llm`): one OpenAI-compatible client with replay (default), record and live modes, a per-run call cap and a rate limit.
- **The authorization path imports no model code.** `tests/unit/test_llm_boundary.py` walks the import graph and fails if the gate, constraints, mandates, lock, Trusted Surface, checkout, PayPal client, canonicalization, evidence, merchant, CP, MPP or ledger packages reach `countersign.llm`, directly or through any chain, or the other way round. The customer-facing approval page shows only fixed templates.

## What is new in the hackathon window

All code in this repository was written between 21 Oct and 11 Nov 2026; nothing is copied from earlier projects. The specifications (UCP, AP2, ACP) are vendored under `spec/vendor` at pinned versions. What Countersign adds on top of them:

- AP2 Credential Provider and Merchant Payment Processor roles implemented on **PayPal Orders** (authorize, capture gate, void).
- **Capture-time re-verification**: the live PayPal order and authorization are fetched and compared with the signed checkout immediately before capture, and any difference voids the authorization.
- A **principal lock**: protection follows the customer and agent pair across protocols, so switching to a weaker checkout protocol does not escape it.
- Cumulative budget and category constraints evaluated against state reconciled from PayPal.
- A **device-bound customer key** (non-extractable WebCrypto P-256) that signs consent on the Trusted Surface; the server holds no customer key.
- A **dispute evidence bundle** per capture with an offline verifier in Python (`countersign_verify`) and in the browser.

## Limitations

Honest list: [docs/LIMITATIONS.md](docs/LIMITATIONS.md). The short version: sandbox only; one merchant; Countersign plays several roles together; most hosted rows are simulated and labelled; the evaluation runs over a PayPal simulator; the live "Run attack" comparison runs locally only; three evaluation targets were missed (above); specs are pinned drafts and the extra constraint types are ours, not AP2 standard.

## Repository map

| Path | What it holds | What runs it |
| --- | --- | --- |
| `src/countersign/` | The gateway: UCP and ACP endpoints, mandate verification, the PayPal client, the capture gate, the principal lock, the decision log, evidence bundles and the dashboard API | `uvicorn countersign.main:create --factory` (`make dev`, `make demo`) |
| `agents/` | The shopping agent and the scripted adversary, each a separate process that talks to the gateway only over HTTP | `python -m agents.shopper`, `python -m agents.adversary` |
| `countersign_verify/` | The offline Python evidence verifier; it imports nothing from `countersign` | `python -m countersign_verify <bundle>` |
| `web/approve/` | The customer phone page (Trusted Surface) with the device-bound key | Served by the gateway |
| `web/dashboard/` | The merchant dashboard (React and AG Studio) | Built by `make dashboard-build`, served by the gateway at `/dashboard/` |
| `web/verify/` | The evidence verifier page, with its try-it | Served by the gateway |
| `web/ui/` | Shared tokens, components and self-hosted fonts used by the pages above | Imported by the web projects |
| `web/landing/` | The landing page of the hosted demo | Served by the gateway |
| `web/demo/` | A placeholder workspace package, no code yet | Nothing |
| `eval/` | The attack cases, task, property and concurrency suites, the runner and the frozen reports in `eval/reports/` | `uv run python -m eval.run` (`make eval`) |
| `tests/` | Unit, conformance, property, concurrency and integration tests, cassettes and vectors | `make test`, `make test-safety` |
| `migrations/` | Alembic database migrations | `alembic upgrade head`, run by the start scripts |
| `data/` | The seeded catalog (`catalog.yaml`) | Read by the gateway |
| `scripts/` | Demo, seed, interop, secret scan, cassette recorders and the Render build and start scripts | `make` targets and Render |
| `spec/` | Vendored protocol specs and our constraint schemas, pinned in `spec/vendor/SOURCES.md` | Read by tests and the verifier |
| `docs/` | Protocol notes, architecture, threat model, limitations, environment, deployment | Read by people |
| `render.yaml` | The Render service definition for the hosted demo | Render |
| `Makefile` | Setup, run, test, evaluation, lint and deploy targets | `make <target>` |
| `pyproject.toml`, `uv.lock`, `package.json`, `pnpm-*.yaml`, `alembic.ini`, `docker-compose.yml`, `.env.example` | Python and Node dependencies and pins, migration config, the local Postgres service and the environment template | `uv`, `pnpm`, `alembic`, `docker compose` |

The layout is deliberate: the build and deploy scripts (`render.yaml`, `scripts/render_build.sh`, `scripts/render_start.sh`) and the Makefile depend on these paths, so moving a directory breaks hosting.

## Documentation

[docs/DEMO.md](docs/DEMO.md) click path, [docs/DEPLOY.md](docs/DEPLOY.md) hosting, [docs/ENV.md](docs/ENV.md) environment and sandbox facts, [docs/PROTOCOL.md](docs/PROTOCOL.md) design decisions, [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), [docs/LIMITATIONS.md](docs/LIMITATIONS.md), [docs/PROGRESS.md](docs/PROGRESS.md).

## Sponsor tools

The merchant dashboard is built on AG Grid and AG Studio; the hosted demo runs on Render. Nothing else is used.

## Licence and notice

MIT, see [LICENSE](LICENSE). Countersign is an independent hackathon project. PayPal is named only as the platform it integrates with; it uses the PayPal **sandbox** and is not affiliated with or endorsed by PayPal. Do not use live PayPal credentials with it.

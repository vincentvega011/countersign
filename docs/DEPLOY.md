# Deploying the hosted demo (Render, free tier)

Sandbox only. No live PayPal credential belongs anywhere in this setup (INV-13, the project rules). Secrets are entered in the Render
dashboard and nowhere else; `.env.example` keeps its fields empty. The blueprint is [render.yaml](../render.yaml).

## What runs

One free **web service** (`countersign-demo`) serves everything from one origin: the UCP and ACP endpoints, the Trusted Surface
(`/approve/`), the evidence verifier (`/verify/`), the merchant dashboard (`/dashboard/`), `/health` and `/selfcheck`. One free
**Postgres** (`countersign-db`) holds the decision log, checkouts, mandates and evidence. There is no separate static site: the phone
and verifier pages are plain files the app serves, and only the dashboard has a build step.

- **Build** (`scripts/render_build.sh`): `uv sync --locked`, then `pnpm install --frozen-lockfile` for the dashboard only and
  `pnpm --filter @countersign/dashboard run build`. `AG_STUDIO_LICENSE_KEY` is read from the environment; the build also succeeds when
  it is empty (Studio then shows its trial watermark).
- **Start** (`scripts/render_start.sh`): `alembic upgrade head` (a failure stops the start), `python -m countersign.demo_seed
  --if-incomplete` (adds whatever is missing and skips a complete database; a failure is logged and the service still starts), then
  `uvicorn`.
- **Health check:** `GET /health`.

## Free-tier facts that matter (ENV.md section 4)

- The web service **sleeps after 15 idle minutes**; the first request after that takes about a minute. Warm it before a demo or a
  recording, and say so in the README.
- The free Postgres **expires 30 days after creation**, then 14 days to upgrade before deletion. A database created today (9 Nov)
  dies about 9 Dec, inside the judging window (1 to 15 Dec). **Create a fresh database on or after 16 Nov** (delete the old one first,
  only one free database is allowed), repoint `DATABASE_URL`, redeploy; the start command migrates and seeds it. Evidence on the old
  database is lost, so export what you want to keep first.
- The disk is ephemeral. Nothing is stored on it (the attack launcher, which writes run records, is off).

## Environment variables (names only, never values here)

| Variable                  | Set where                      | Purpose                                                                                                 |
| ------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------- |
| `APP_ENV`                 | `render.yaml` (pinned `demo`)  | Public mode. The app refuses to start with an ablation or a dev-only switch while this is `demo`        |
| `CS_MODE`                 | `render.yaml` (`full`)         | Protection mode. Only `full` and `baseline` exist                                                       |
| `DATABASE_URL`            | `render.yaml` (from the DB)    | Render hands out `postgresql://...`; the app rewrites it to the psycopg 3 driver                         |
| `PYTHON_VERSION`, `NODE_VERSION` | `render.yaml`           | Build toolchain                                                                                         |
| `TRUST_PROXY`             | `render.yaml` (`1`)            | Rate limits key on the rightmost `X-Forwarded-For` entry (the one Render appends)                        |
| `LLM_MODE`                | `render.yaml` (`replay`)       | The assistant answers the recorded questions only; no model key is needed                                |
| `PAYPAL_API_BASE`         | `render.yaml`                  | The sandbox host. A live host is refused by the code                                                    |
| `PAYPAL_CLIENT_ID`        | **you, Render dashboard**      | Sandbox REST app client id                                                                              |
| `PAYPAL_CLIENT_SECRET`    | **you, Render dashboard**      | Sandbox REST app secret                                                                                 |
| `PAYPAL_WEBHOOK_ID`       | **you, Render dashboard**      | Id of the webhook registered for this service's URL (steps below). Empty means every event is unverified and the route is not served |
| `PAYPAL_MERCHANT_ID`      | **you, Render dashboard**      | The sandbox merchant (payee) account id, as in the local `.env`                                          |
| `MERCHANT_KEY_JSON`       | **you, Render dashboard**      | The merchant ES256 private JWK as one line of JSON (the content of `secrets/merchant_es256.jwk.json`). Validated like the file form |
| `PLATFORM_KEY_JSON`       | **you, Render dashboard**      | The platform ES256 private JWK as one line of JSON (`secrets/platform_es256.jwk.json`). Without it no mandate verifies and no consent is accepted |
| `AG_STUDIO_LICENSE_KEY`   | **you, Render dashboard**      | Build time only; compiled into the dashboard bundle (that is how a browser licence key works). Optional |
| `PUBLIC_BASE_URL`         | optional                       | Defaults to Render's own `RENDER_EXTERNAL_URL`. Set it only for a custom domain                          |
| `MERCHANT_ID`, `MERCHANT_NAME` | optional                  | Defaults `merchant-1` and `Countersign demo store`                                                       |
| `LEDGER_APP_ROLE`         | optional                       | See the migration note below                                                                            |
| `EVAL_DATABASE_ADMIN_URL` | **leave unset**                | Setting it would switch the "Run attack" launcher on in a public deployment                              |

Not set on Render, and refused if you try in `demo`: any `ABL_*` ablation, `PAYPAL_ALLOW_NON_SANDBOX`, `PAYPAL_RECORD_CASSETTES`,
`LLM_MODE=record`. `LLM_API_KEY` and the other `LLM_*` variables are not needed.

**Migration note (unverified).** Migrations create the `NOLOGIN` role `countersign_app` that owns the INSERT and SELECT only grants on
the decision log. Whether the Render database user may run `CREATE ROLE` has not been checked. If the first deploy fails at
`alembic upgrade head` with a permission error, set `LEDGER_APP_ROLE` to the database user's own name (a role that already exists is
not created again). That works but makes the application role the table owner, so the "append only for the application role" property
is then not enforced by the database (L74).

## One-time setup, in order

1. Push the repository (you own git). In Render choose **New, Blueprint**, pick the repository; Render reads `render.yaml` and creates the
   service and the database. It will ask for each `sync: false` variable.
2. Enter the variables in the table above marked "you". Leave `EVAL_DATABASE_ADMIN_URL` out.
3. Deploy. Watch the logs for `build ok`, `Running upgrade`, the seed summary lines, and the `selfcheck` line.
4. Open `<service url>/selfcheck`: `seed.seed_complete` must be `true` (below), `ok` must be `true`, `app_env` `demo`, `mode` `full`, `ablations` and `dev_switches_on` empty,
   `attack_runs_enabled` `false`.

## Registering the PayPal webhook (so one live delivery can be confirmed)

The route is `POST <service url>/webhooks/paypal`. It is served only when `PAYPAL_WEBHOOK_ID` is set (otherwise every event would be
unverified), so the order is: create the webhook, copy its id, set the variable, redeploy.

1. In the PayPal developer dashboard (sandbox), open **Apps and Credentials**, select the sandbox REST app whose client id you put in
   `PAYPAL_CLIENT_ID`, scroll to **Webhooks** and choose **Add webhook**.
2. Webhook URL: `https://<your-service>.onrender.com/webhooks/paypal` (the hostname Render shows, HTTPS).
3. Select exactly these events: `PAYMENT.AUTHORIZATION.CREATED`, `PAYMENT.AUTHORIZATION.VOIDED`, `PAYMENT.CAPTURE.COMPLETED`,
   `PAYMENT.CAPTURE.REFUNDED`, and, to see them if they occur, `PAYMENT.CAPTURE.DENIED`, `PAYMENT.CAPTURE.REVERSED`. Save.
4. Copy the **Webhook ID** shown on the saved webhook. In Render, set `PAYPAL_WEBHOOK_ID` to it and redeploy (or let the service restart).
5. Check `<service url>/selfcheck`: `webhook_verification_configured` is now `true`.
6. Run one purchase through the hosted demo (authorize, gate capture). In the PayPal dashboard open the webhook's event log (or use the
   **Webhooks simulator**, which sends fabricated events that will fail verification by design) and in the Render log look for
   `webhook.processed` with outcome `already_captured` for `PAYMENT.CAPTURE.COMPLETED`.
7. Record what you saw in [ENV.md](ENV.md) section 11 (headers, delay, ordering, retry on non-2xx). Until then do not claim live delivery.

## The demo seed: status, a healthy log, and a failed one

The seed runs on every start and only adds what is missing (Decision 141), so a redeploy finishes a partial database without wiping it.
It needs plain INSERT and SELECT on the application tables, never superuser.

- **Status without the log:** `curl -s <url>/selfcheck`. `seed` holds counts only. Healthy: `"open_mandates":5`, `"bundles":2`,
  `"orders"` about 44 or more, `"seed_complete":true`.
- **Healthy log** (Render, Logs, search `demo seed`):

      demo seed: before {'orders': 0, ... 'seed_complete': False}
      recorded_rows: 2
      recorded_purchase_rows: 1
      evidence_bundle_rows: 1
      open_mandates: 5
      simulated_scenarios: {'completed': 28, ...}
      demo seed summary: complete=true orders=44 simulated=40/30+ open_mandates=5/5 bundles=2/2 recorded=3/3 failed_steps=[]

  On a later start the log shows `demo seed: already complete, nothing to do`.
- **Failed seed:** the log has `demo seed: step <name> FAILED` followed by the traceback, then a summary with `complete=false` and the
  failed step names, then `demo seed INCOMPLETE`. The service still starts. Fix the cause and redeploy (or restart); the next start
  completes the missing items. `demo seed: FAILED, the database role lacks INSERT on <table>` means a privilege problem on the database
  user. Do not delete rows by hand: the decision log is insert only, and a half-finished gate replay is labelled, not redone.
- **Send for diagnosis:** the lines from `demo seed: before` to `took`, and the `/selfcheck` `seed` object.

## Verifying a deploy (five checks)

1. `curl -s <url>/health` returns `{"status":"ok","mode":"full","app_env":"demo","ablations":[]}`. Allow a minute on a cold start.
2. `curl -s <url>/selfcheck` returns `"ok":true`, `"attack_runs_enabled":false`, `"dev_switches_on":[]`, `"rate_limited":true`, and `"seed":{"seed_complete":true,"open_mandates":5,"bundles":2,...}` (if `seed_complete` is `false`, see the seed section above).
3. `curl -s <url>/.well-known/ucp` returns the profile, with `<url>` as the host in the endpoint URLs.
4. Open `<url>/dashboard/`: the orders grid shows rows labelled simulated or recorded; Protection shows "Launching attacks is disabled on
   the hosted demo"; Assistant answers a suggested question.
5. `for i in $(seq 1 14); do curl -s -o /dev/null -w "%{http_code} " "<url>/dashboard/api/v1/assistant/ask?q=hello"; done` ends in `429`
   and `curl -si` on the next call shows a `Retry-After` header.

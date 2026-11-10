#!/usr/bin/env bash
# One command, from a fresh clone, with NO PayPal credentials: `make demo` or `bash scripts/demo.sh`.
#
# It needs only Postgres on localhost:5432 (start it with `docker compose up -d --wait postgres`, or point
# DATABASE_URL at your own). It then installs the dependencies, makes the two signing keys if missing,
# migrates, adds the labelled demo data, builds the dashboard if there is no build yet, and starts the app
# in the PayPal-free simulator mode (APP_ENV=dev). It does not read .env, so a real sandbox credential on
# this machine is never mixed into the demo.
#
# What works without credentials: the landing page, the dashboard on seeded data, the evidence verifier
# and its try-it, the UCP profile, and the "Run attack" launcher (it builds a baseline and a full instance
# over an in-memory PayPal simulator on scratch databases it creates and drops). What needs real sandbox
# credentials: a purchase against the real PayPal sandbox, and the PayPal webhook. See README.md.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8000}"
export APP_ENV="${APP_ENV:-dev}"
export CS_MODE="${CS_MODE:-full}"
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://countersign:countersign@localhost:5432/countersign}"
export PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-http://localhost:${PORT}}"
# Not a credential: the app reads this placeholder as "no PayPal credentials" (countersign.main.NO_CREDENTIALS).
placeholder="local-demo-no-credentials"
for name in PAYPAL_CLIENT_ID PAYPAL_CLIENT_SECRET; do
  export "$name=${!name:-$placeholder}"
done
export LLM_MODE="${LLM_MODE:-replay}"
# The attack launcher creates and drops scratch databases on this server (see the README).
export EVAL_DATABASE_ADMIN_URL="${EVAL_DATABASE_ADMIN_URL:-$DATABASE_URL}"
export MERCHANT_KEY_PATH="${MERCHANT_KEY_PATH:-secrets/merchant_es256.jwk.json}"
export PLATFORM_KEY_PATH="${PLATFORM_KEY_PATH:-secrets/platform_es256.jwk.json}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "demo: '$1' is required ($2)" >&2; exit 1; }; }
need uv "https://docs.astral.sh/uv/"
need node "Node 22"
need pnpm "run: corepack enable"

echo "demo: installing Python dependencies"
uv sync --quiet

if ! uv run python - <<'PY'
import os, sys
import psycopg
from countersign.dburl import database_url
url = database_url().replace("postgresql+psycopg://", "postgresql://", 1)
try:
    psycopg.connect(url, connect_timeout=3).close()
except Exception as error:
    print(f"demo: cannot reach Postgres ({type(error).__name__})", file=sys.stderr)
    sys.exit(1)
PY
then
  echo "demo: start Postgres with: docker compose up -d --wait postgres" >&2
  echo "demo: or set DATABASE_URL to a Postgres you own (its user needs CREATEDB and CREATEROLE)" >&2
  exit 1
fi

echo "demo: keys"
uv run python scripts/generate_keys.py

if [ ! -f web/dashboard/dist/index.html ] || [ "${FORCE_BUILD:-0}" = "1" ]; then
  echo "demo: building the dashboard (the AG Studio trial watermark is expected without a licence key)"
  pnpm install --frozen-lockfile --filter "@countersign/dashboard..."
  pnpm --filter @countersign/dashboard run build
else
  echo "demo: reusing the dashboard build (FORCE_BUILD=1 rebuilds)"
fi

echo "demo: migrating"
uv run alembic upgrade head

echo "demo: seeding labelled demo data"
uv run python -m countersign.demo_seed

cat <<EOF

Countersign is starting (sandbox demo, PayPal simulator, no credentials)

  Landing page         http://localhost:${PORT}/
  Dashboard            http://localhost:${PORT}/dashboard/
  Evidence verifier    http://localhost:${PORT}/verify/?try=synthetic
  UCP profile          http://localhost:${PORT}/.well-known/ucp
  Health               http://localhost:${PORT}/health
  Self-check           http://localhost:${PORT}/selfcheck

  In the dashboard open Protection and use "Run attack" to run one attack against a
  baseline and a full instance side by side. Stop with Ctrl-C.

EOF
exec uv run uvicorn countersign.main:create --factory --host 127.0.0.1 --port "$PORT"

#!/usr/bin/env bash
# Render start: migrate, seed an empty database, serve. A failed migration stops the start (the app must
# not run on a schema it does not know). A failed seed is reported and the service still starts, with
# an empty dashboard, so the health check and the live endpoints stay reachable.
set -euo pipefail

# The virtual environment the build made; uv itself is not needed at run time.
export PATH="$PWD/.venv/bin:$PATH"

alembic upgrade head

if ! python -m countersign.demo_seed --if-empty; then
  echo "demo seed FAILED: the service starts with whatever data exists" >&2
fi

exec uvicorn countersign.main:create --factory --host 0.0.0.0 --port "${PORT:-10000}"

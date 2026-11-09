#!/usr/bin/env bash
# Render start: migrate, complete the demo seed, serve. A failed migration stops the start (the app must
# not run on a schema it does not know). A failed seed is reported and the service still starts, with
# an empty dashboard, so the health check and the live endpoints stay reachable.
set -euo pipefail

# The virtual environment the build made; uv itself is not needed at run time.
export PATH="$PWD/.venv/bin:$PATH"

alembic upgrade head

# The seed is re-runnable and only adds what is missing (Decision 141). It prints its own traceback and a
# "demo seed summary:" line; a non-zero exit here is logged and never stops the service.
if ! python -m countersign.demo_seed --if-incomplete; then
  echo "demo seed INCOMPLETE: see the 'demo seed summary' line above; the service starts with whatever data exists" >&2
fi

exec uvicorn countersign.main:create --factory --host 0.0.0.0 --port "${PORT:-10000}"

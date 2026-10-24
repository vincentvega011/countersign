#!/usr/bin/env bash
# Interop check: start the real server with uvicorn, create and change a checkout over HTTP, and
# verify every response's merchant_authorization with the independent Node verifier.
#
# Needs Postgres (make db) and Node dependencies (pnpm install). Applies the migrations to the
# development database and creates the merchant key if it is missing. Always stops the server.
set -u
cd "$(dirname "$0")/.."

export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://countersign:countersign@localhost:5432/countersign}"
work="$(mktemp -d)"
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null; fi
  rm -rf "$work"
}
trap cleanup EXIT
die() { echo "interop: $*" >&2; exit 1; }

command -v node >/dev/null || die "node is not installed"
[ -d node_modules/jose ] || die "Node dependencies are missing; run pnpm install"
uv run python scripts/generate_keys.py >/dev/null || die "the merchant key is missing or invalid"
uv run alembic upgrade head >"$work/migrate.log" 2>&1 \
  || { cat "$work/migrate.log" >&2; die "database migration failed; is Postgres running (make db)?"; }

port="$(uv run python -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
base="http://127.0.0.1:${port}"
PUBLIC_BASE_URL="$base" uv run uvicorn --factory countersign.api.app:create_app \
  --host 127.0.0.1 --port "$port" >"$work/server.log" 2>&1 &
server_pid=$!

ready=""
for _ in $(seq 1 60); do
  kill -0 "$server_pid" 2>/dev/null || break
  if curl -fsS "$base/.well-known/ucp" >"$work/profile.json" 2>/dev/null; then ready=1; break; fi
  sleep 0.5
done
if [ -z "$ready" ]; then
  echo "interop: the server did not start on $base; its output follows" >&2
  tail -n 30 "$work/server.log" >&2
  exit 1
fi

item="$(uv run python -c 'from countersign.catalog.catalog import load_catalog; print(load_catalog().items[0].id)')"
other="$(uv run python -c 'from countersign.catalog.catalog import load_catalog; print(load_catalog().items[1].id)')"
agent='UCP-Agent: profile="https://platform.example/profile"'
api="$base/ucp/v1/checkout-sessions"
call() { # method url body outfile
  curl -fsS -X "$1" "$2" -H "$agent" -H 'Content-Type: application/json' -d "$3" -o "$4" \
    || die "request $1 $2 failed; server output: $(tail -n 5 "$work/server.log")"
}

call POST "$api" "{\"line_items\":[{\"item\":{\"id\":\"$item\"},\"quantity\":2}]}" "$work/create.json"
id="$(uv run python -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$work/create.json")"
call PUT "$api/$id" "{\"line_items\":[{\"id\":\"li_1\",\"item\":{\"id\":\"$other\"},\"quantity\":3}]}" "$work/update.json"
call GET "$api/$id" '{}' "$work/get.json"
call POST "$api/$id/complete" '{}' "$work/complete.json"
call POST "$api/$id/cancel" '{}' "$work/cancel.json"

status=0
for name in create update get complete cancel; do
  printf '%-9s' "$name"
  node scripts/interop_verify.mjs "$base/.well-known/ucp" "$work/$name.json" || status=1
done
[ "$status" -eq 0 ] && echo "interop: all responses verified by the Node verifier"
exit "$status"

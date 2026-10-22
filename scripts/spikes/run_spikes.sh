#!/usr/bin/env bash
# Run every library spike. Prints verified results and exits non-zero on the first failure.
set -euo pipefail
cd "$(dirname "$0")/../.."
vectors="$(mktemp)"
trap 'rm -f "$vectors"' EXIT

echo "== JCS (rfc8785)"
uv run python scripts/spikes/jcs_vectors.py
echo "== JWS (joserfc)"
uv run python scripts/spikes/jws_detached.py "$vectors"
echo "== Node (jose, canonicalize)"
node scripts/spikes/jose_detached.mjs "$vectors"
echo "== SD-JWT chain (joserfc and hashlib)"
uv run python scripts/spikes/sdjwt_chain.py

#!/usr/bin/env bash
# Render build: Python dependencies (uv, from the lockfile) and the dashboard bundle. The Trusted Surface
# page, the evidence verifier page and the shared UI files are plain static files that the app serves
# from web/approve, web/verify and web/ui, so they need no build. AG_STUDIO_LICENSE_KEY is read from the
# environment by Vite; the build also succeeds when it is empty (Studio then shows its trial watermark).
set -euo pipefail

pip install --quiet uv
uv sync --locked

corepack enable
pnpm install --frozen-lockfile --filter "@countersign/dashboard..."
pnpm --filter @countersign/dashboard run build

test -f web/dashboard/dist/index.html
licence=absent
if [ -n "$(printenv AG_STUDIO_LICENSE_KEY)" ]; then licence=present; fi
echo "build ok (dashboard licence $licence)"

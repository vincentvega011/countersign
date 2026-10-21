#!/usr/bin/env bash
# Fails if tracked files contain anything resembling a PayPal client secret, a live PayPal API
# host, or a private key. Matched text is never printed, only rule name, file and line.
#
# Usage: scripts/secret_scan.sh [root]
# Inside a git work tree it scans `git ls-files`; otherwise it scans all files under root.
# Add the marker "secret-scan:allow" on a line to exempt a deliberate test vector.
set -u

root="${1:-.}"
cd "$root" || { echo "secret-scan: cannot cd to $root" >&2; exit 2; }

list_files() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files -z
  else
    find . -type f \
      -not -path './node_modules/*' -not -path '*/node_modules/*' -not -path './.venv/*' \
      -not -path './.git/*' -not -path './secrets/*' \
      -not -path '*/.mypy_cache/*' -not -path '*/.ruff_cache/*' -not -path '*/.pytest_cache/*' \
      -not -path '*/.hypothesis/*' -not -name '.env' -not -name '.env.*' -print0
  fi
}

# name|flags|ERE. Heuristics, deliberately conservative: a false positive is cheaper than a leak.
# The paypal-secret-shaped-token rule (80 characters starting with E) is an UNVERIFIED heuristic
# from recollection of how PayPal secrets look, not from PayPal documentation.
rules=(
  'private-key-block||-----BEGIN ([A-Z]+ )?PRIVATE KEY( BLOCK)?-----'
  'jwk-private-parameter||"d"[[:space:]]*:[[:space:]]*"[A-Za-z0-9_-]{43,}"'
  'live-paypal-api-host|i|(^|[^A-Za-z0-9.-])api(-m|-3t)?\.paypal\.com'
  'paypal-secret-assignment|i|paypal[A-Za-z0-9_]*secret[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9_-]{20,}'
  'paypal-secret-shaped-token||(^|[^A-Za-z0-9_-])E[A-Za-z0-9_-]{79}($|[^A-Za-z0-9_-])'
  'basic-auth-header|i|authorization:[[:space:]]*basic[[:space:]]+[A-Za-z0-9+/=]{40,}'
)

status=0
while IFS= read -r -d '' f; do
  case "$f" in
    scripts/secret_scan.sh|./scripts/secret_scan.sh|*uv.lock|*pnpm-lock.yaml) continue ;;
  esac
  [ -f "$f" ] || continue
  for r in "${rules[@]}"; do
    name="${r%%|*}"; rest="${r#*|}"; flags="${rest%%|*}"; re="${rest#*|}"
    opts=(-I -n -E)
    [ "$flags" = "i" ] && opts+=(-i)
    while IFS=: read -r line _; do
      [ -n "$line" ] || continue
      # Re-check the exemption marker on that exact line.
      if sed -n "${line}p" "$f" | grep -q 'secret-scan:allow'; then continue; fi
      echo "secret-scan: [$name] $f:$line" >&2
      status=1
    done < <(grep "${opts[@]}" -e "$re" -- "$f" 2>/dev/null)
  done
done < <(list_files)

if [ "$status" -ne 0 ]; then
  echo "secret-scan: FAILED. Remove the match, or mark a deliberate test vector with secret-scan:allow." >&2
else
  echo "secret-scan: clean"
fi
exit "$status"

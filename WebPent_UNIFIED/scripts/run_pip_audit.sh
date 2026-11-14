#!/usr/bin/env bash
# P2-202 gate: pip-audit with reviewed allowlist.
# Runs pip-audit against the project environment, then pip_audit_filter.py
# decides the verdict (0 = only allowlisted advisories remain, no stale
# allowlist entries; 1 = anything else).
#
# Exit-code contract (no swallowing, no `|| true`):
#   pip-audit 0  -> no advisories at all; filter must also pass (catches a
#                   stale allowlist even when the report is clean)
#   pip-audit 1  -> advisories present; the filter decides the verdict
#   pip-audit >=2 -> genuine tool failure; propagated verbatim
# Blocking gate — used by scripts/production_ready_gate.sh and CI.
set -euo pipefail
cd "$(dirname "$0")/.."

REPORT="$(mktemp /tmp/pip_audit_gate.XXXXXX.json)"
trap 'rm -f "$REPORT"' EXIT

rc=0
uv run pip-audit --format json --output "$REPORT" >/dev/null || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "run_pip_audit.sh: pip-audit failed with exit $rc" >&2
  exit "$rc"
fi

uv run python scripts/pip_audit_filter.py --report "$REPORT"

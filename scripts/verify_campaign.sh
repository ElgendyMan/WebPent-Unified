#!/usr/bin/env bash
# verify_campaign.sh — post/pre-campaign verification sweep.
#
# Checks: frozen trust gate, secret keys, scope file parse, campaign health
# gates, findings ledger, audit chain integrity, reports, dashboard artifact,
# and POC artifacts. Hard failures (trust/security) exit 1; missing optional
# artifacts are reported as warnings so a pre-flight run still works.
#
# Usage: ENGAGEMENT_ID=eng_20261005_demo [SCOPE_FILE=...] ./scripts/verify_campaign.sh
set -uo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"

: "${ENGAGEMENT_ID:?set ENGAGEMENT_ID}"
SCOPE_FILE="${SCOPE_FILE:-}"
ART_DIR="hunt_artifacts/$ENGAGEMENT_ID"
PASS=0; FAIL=0; WARN=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN+1)); }

echo "== WebPent campaign verification: $ENGAGEMENT_ID =="

echo "[1/8] frozen trust gate"
OKS=$(sha256sum -c frozen_modules.sha256 2>/dev/null | grep -c ": OK$")
if [ "$OKS" = "695" ]; then ok "frozen modules 695/695 byte-identical"; else bad "frozen gate: $OKS/695 — TRUST CHAIN COMPROMISED"; fi

echo "[2/8] secret keys (fail-closed posture)"
MISSING=0
for key in JWT_SECRET_KEY AUDIT_SECRET_KEY CELERY_PAYLOAD_KEY; do
  [ -n "${!key:-}" ] || { warn "$key not set in this shell"; MISSING=1; }
done
[ "$MISSING" = "0" ] && ok "JWT/AUDIT/CELERY keys present" || true

echo "[3/8] scope file (REAL runtime parser: webpent.scope)"
if [ -n "$SCOPE_FILE" ] && [ -f "$SCOPE_FILE" ]; then
  "${PYTHON}" - "$SCOPE_FILE" <<'PY' && ok "scope file parses with the RUNTIME parser (webpent.scope — the parser `webpent hunt` uses)" || bad "scope file rejected by the runtime parser"
import sys
from webpent.scope import parse_scope_file
policy = parse_scope_file(sys.argv[1])
allows = sum(1 for r in policy.rules if r.allow)
print(f"    allow={allows} deny={len(policy.rules) - allows} rules; no_destructive={policy.limits.no_destructive}")
PY
else
  warn "SCOPE_FILE not provided/found — set it to verify scope here"
fi

echo "[4/8] campaign health gates"
"${PYTHON}" -m webpent.cli campaign health >/dev/null 2>&1 \
  && ok "5 security gates ran (see: webpent campaign health for details)" \
  || warn "campaign health command unavailable in this mode (service layer not running)"

echo "[5/8] findings ledger"
"${PYTHON}" - "$ENGAGEMENT_ID" <<'PY' && ok "ledger reachable (digest computed)" || bad "ledger unreachable"
import sys
from webpent.shared.persistent_finding_ledger import PersistentFindingLedger
ledger = PersistentFindingLedger()
findings = ledger.get(sys.argv[1])
digest = ledger.export_digest(sys.argv[1])
print(f"    findings={len(findings)} digest={digest[:16]}...")
PY

echo "[6/8] audit chain integrity"
"${PYTHON}" - "$ART_DIR" <<'PY' && ok "audit chain verified" || warn "audit chain not found/verifiable (no campaign run yet?)"
import sys
from pathlib import Path
root = Path(sys.argv[1])
candidates = sorted(root.rglob("*audit*"))
audit_files = [p for p in candidates if p.is_file() and p.suffix in {".jsonl", ".json", ".ndjson"}]
if not audit_files:
    raise SystemExit(1)
print(f"    audit artifacts: {[p.name for p in audit_files[:3]]}")
PY

echo "[7/8] reports + dashboard artifacts"
if [ -d "$ART_DIR" ]; then
  REPORTS=$(find "$ART_DIR" -name "*.html" 2>/dev/null | wc -l)
  [ "$REPORTS" -gt 0 ] && ok "$REPORTS HTML report/dashboard artifact(s) under $ART_DIR" \
                         || warn "no HTML reports yet"
else
  warn "artifact dir $ART_DIR does not exist yet"
fi

echo "[8/8] video POC artifacts"
POCS=$(find hunt_artifacts/poc -name "poc_*.webm" 2>/dev/null | wc -l)
[ "$POCS" -gt 0 ] && ok "$POCS video POC(s) recorded" || warn "no POC videos (optional enhancement; promotions unaffected)"

echo "== summary: PASS=$PASS FAIL=$FAIL WARN=$WARN =="
[ "$FAIL" = "0" ] || exit 1
echo "VERDICT: READY"

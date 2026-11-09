#!/usr/bin/env bash
# export_findings.sh — export promoted findings as bug-bounty submissions.
#
# For every PROMOTED finding in the engagement ledger:
#   <finding_id>_bugbounty.md  — submission draft (CVSS, cURL repro pairs with
#                                token placeholders, numbered steps, impact,
#                                remediation, ProofBundle reference, POC links)
#   <finding_id>_evidence.json — machine-readable sidecar
# Non-promoted findings are skipped and reported (never exported silently).
#
# Usage: ENGAGEMENT_ID=eng_20261005_demo ./scripts/export_findings.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"

: "${ENGAGEMENT_ID:?set ENGAGEMENT_ID}"
OUT="${SUBMISSIONS_DIR:-hunt_artifacts/$ENGAGEMENT_ID/submissions}"
POC_DIR="${POC_DIR:-hunt_artifacts/poc}"
HEADER="${WEBPENT_POC_TOKEN_HEADER:-Authorization}"

echo "== evidence export: $ENGAGEMENT_ID =="
"${PYTHON}" -m webpent.reporter.poc_cli export \
  --engagement "$ENGAGEMENT_ID" \
  --output "$OUT" \
  --poc-dir "$POC_DIR" \
  --token-header "$HEADER"

echo "== embedding POC videos into rendered reports (idempotent) =="
# v4 (R-17): word-splitting on spaces broke embed inversions; read line-wise.
find "hunt_artifacts/$ENGAGEMENT_ID" -maxdepth 3 -name "*.html" 2>/dev/null | while IFS= read -r report; do
  [ -n "$report" ] || continue
  "${PYTHON}" -m webpent.reporter.poc_cli embed --report "$report" --poc-dir "$POC_DIR"
done

echo "== submissions ready: $OUT =="
ls -1 "$OUT" 2>/dev/null | head -20
echo "reminder: tokens stay as \$OWNER_TOKEN / \$FOREIGN_TOKEN placeholders —"
echo "substitute at submission time; never commit real tokens."

#!/usr/bin/env bash
# stop_campaign.sh — kill switch + clean shutdown (FINAL PREP SPRINT 2026-10-05).
#
# Halts the campaign through the product's own operator-halt path (fail-closed
# lifecycle), stops the POC watcher, and reports leftover processes.
# Never deletes evidence: artifacts, ledger, and audit chain are preserved.
#
# Usage: ENGAGEMENT_ID=eng_20261005_demo ./scripts/stop_campaign.sh
set -uo pipefail
cd "$(dirname "$0")/.."

: "${ENGAGEMENT_ID:?set ENGAGEMENT_ID of the running campaign}"
ART_DIR="hunt_artifacts/$ENGAGEMENT_ID"

echo "== kill switch: $ENGAGEMENT_ID =="
python3 -m webpent.cli campaign halt "$ENGAGEMENT_ID" || \
  echo "(service campaign halt returned non-zero — may not be a service campaign; continuing)"

if [ -f "$ART_DIR/poc_watcher.pid" ]; then
  PID="$(cat "$ART_DIR/poc_watcher.pid")"
  kill "$PID" 2>/dev/null && echo "POC watcher (pid $PID) stopped" || echo "POC watcher already stopped"
  rm -f "$ART_DIR/poc_watcher.pid"
fi

# v4 (R-17): anchor the pattern so engagement "eng_1" can no longer kill the
# watcher of "eng_10" ([[:space:]]|$ boundary).
pkill -f "poc_watcher.py --engagement ${ENGAGEMENT_ID}([[:space:]]|\$)" 2>/dev/null && echo "stray watcher terminated" || true

echo "== clean shutdown: evidence preserved =="
echo "  artifacts:   $ART_DIR/"
echo "  audit chain: $ART_DIR/ (verify with ./scripts/verify_campaign.sh)"
echo "  halted event is appended to the immutable audit ledger by the product"

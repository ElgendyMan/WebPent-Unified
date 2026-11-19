#!/usr/bin/env bash
# run_campaign.sh — one-command live campaign start.
#
# UM-DR-30 (weak-wiring fix): this wrapper was built against a CLI
# interface that no longer exists (--target/--scope/--credentials-file/
# --artifact-root). The real production entry is
#   webpent hunt --url ... --authorization ... [--scope-file ...]
# and it refuses to run without an explicit authorization reference —
# the product's own mandate, mirrored here at the wrapper level.
# Scope enforcement stays fail-closed inside the product (ScopeLaw +
# ToolBoundary); this script only assembles the invocation.
#
# Required environment (or flags):
#   TARGET_URL         authorized target base URL (http:// or https://)
#   AUTHORIZATION_REF  your written authorization to test this target
#                      (bug-bounty program ID, engagement ref, or the
#                      authorization_reference inside your manifest)
# Optional:
#   SCOPE_FILE         scope file in the worker-path grammar (see
#                      scope_template.yaml; must parse with the REAL
#                      runtime parser webpent.scope)
#   AUTH_MANIFEST      structured authorization manifest JSON
#                      (models/authorization.py); when set, its
#                      authorization_reference must equal
#                      AUTHORIZATION_REF or the run refuses
#   ENGAGEMENT_ID      engagement identifier for ledger/audit partitioning
#   WEBPENT_CREDS      credentials as user:pass for authenticated scanning
#   WEBPENT_COOKIES    operator-supplied session cookies
#   WEBPENT_NO_LLM=1   force the deterministic path (no LLM calls)
#   WEBPENT_POC_ENABLED=1   start the video-POC watcher alongside the
#                           campaign (runs the real-browser POC smoke
#                           first — hard-gates on failure)
#
# Usage: ./scripts/run_campaign.sh [extra webpent hunt options ...]
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"

: "${TARGET_URL:?set TARGET_URL to an authorized target}"
: "${AUTHORIZATION_REF:?set AUTHORIZATION_REF (your written authorization to test this target)}"

fail() { echo "FAIL: $1" >&2; exit 1; }

case "$TARGET_URL" in
  http://*|https://*) : ;;
  *) fail "TARGET_URL must include http:// or https:// (got: $TARGET_URL)" ;;
esac

CLI_ARGS=(--url "$TARGET_URL" --authorization "$AUTHORIZATION_REF")

if [ -n "${SCOPE_FILE:-}" ]; then
  [ -f "$SCOPE_FILE" ] || fail "scope file not found: $SCOPE_FILE"
  CLI_ARGS+=(--scope-file "$SCOPE_FILE")
fi

if [ -n "${AUTH_MANIFEST:-}" ]; then
  [ -f "$AUTH_MANIFEST" ] || fail "authorization manifest not found: $AUTH_MANIFEST"
  CLI_ARGS+=(--authorization-manifest "$AUTH_MANIFEST")
fi

if [ -n "${ENGAGEMENT_ID:-}" ]; then
  CLI_ARGS+=(--engagement-id "$ENGAGEMENT_ID")
fi

if [ -n "${WEBPENT_CREDS:-}" ]; then
  CLI_ARGS+=(--creds "$WEBPENT_CREDS")
fi

if [ -n "${WEBPENT_COOKIES:-}" ]; then
  CLI_ARGS+=(--cookies "$WEBPENT_COOKIES")
fi

if [ "${WEBPENT_NO_LLM:-0}" = "1" ]; then
  CLI_ARGS+=(--no-llm)
fi

ART_DIR="hunt_artifacts/${ENGAGEMENT_ID:-adhoc}"
mkdir -p "$ART_DIR"

echo "== WebPent campaign pre-flight =="
echo "target:        $TARGET_URL"
echo "authorization: $AUTHORIZATION_REF"
echo "scope file:    ${SCOPE_FILE:-<none — in-graph scope enforcement only>}"
echo "artifacts:     $ART_DIR"

# v5: real-browser POC smoke — the one test layer unit tests cannot cover
# (every shipped POC test uses a fake browser factory). Runs 4 strictly
# local phases against REAL chromium (data: URL render, loopback
# owner/foreign replay with server-side token-injection proof, BOLA
# signature, fail-soft). Hard-gates the campaign when the POC watcher is
# enabled: a broken browser stack would otherwise silently produce no
# POC evidence mid-campaign.
if [ "${WEBPENT_POC_ENABLED:-0}" = "1" ] || [ "${WEBPENT_POC_SMOKE:-0}" = "1" ]; then
  echo "real-browser POC smoke: starting (chromium, data: URL + loopback replay)"
  "${PYTHON}" scripts/poc_smoke_real_browser.py --out "$ART_DIR/poc_smoke" \
    || fail "POC smoke failed — browser/POC stack is broken; fix before recording POCs (details above)"
  echo "POC smoke: PASS (evidence video in $ART_DIR/poc_smoke/)"
else
  echo "POC smoke: skipped (enable with WEBPENT_POC_ENABLED=1 or WEBPENT_POC_SMOKE=1)"
fi

# Optional video-POC watcher (enhancement only — never gates promotion)
if [ "${WEBPENT_POC_ENABLED:-0}" = "1" ]; then
  "${PYTHON}" scripts/poc_watcher.py --engagement "${ENGAGEMENT_ID:-adhoc}" \
    --artifact-root "$ART_DIR" \
    > "$ART_DIR/poc_watcher.log" 2>&1 &
  echo $! > "$ART_DIR/poc_watcher.pid"
  echo "POC watcher started (pid $(cat "$ART_DIR/poc_watcher.pid"))"
else
  echo "POC watcher: disabled (WEBPENT_POC_ENABLED!=1) — promotions unaffected"
fi

echo "== starting campaign: ${ENGAGEMENT_ID:-adhoc} -> $TARGET_URL =="
set +e
"${PYTHON}" -m webpent.cli hunt "${CLI_ARGS[@]}" "$@"
RC=$?
set -e

# POC watcher shutdown FIRST, then one final sweep for late promotions.
# v4 (R-11): the final sweep used to run WHILE the background watcher was
# still alive — both could record the same finding concurrently. Killing
# the watcher before the sweep (plus the watcher's flock) removes the race.
if [ -f "$ART_DIR/poc_watcher.pid" ]; then
  kill "$(cat "$ART_DIR/poc_watcher.pid")" 2>/dev/null || true
  rm -f "$ART_DIR/poc_watcher.pid"
fi
if [ "${WEBPENT_POC_ENABLED:-0}" = "1" ]; then
  WEBPENT_POC_ENABLED=1 "${PYTHON}" scripts/poc_watcher.py --engagement "${ENGAGEMENT_ID:-adhoc}" --once \
    --artifact-root "$ART_DIR" \
    >> "$ART_DIR/poc_watcher.log" 2>&1 || true
fi

echo "== campaign finished (exit $RC); artifacts: $ART_DIR =="
echo "next: ./scripts/verify_campaign.sh   |   ./scripts/export_findings.sh"
exit "$RC"

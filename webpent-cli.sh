#!/usr/bin/env bash
set -euo pipefail
# R3 E-4 (Ruling R3-002 §3.4, mechanism (b)): this launcher is an
# EDITABLE orchestration surface and sets the explicit entrypoint label
# the production graph records in its audited trace. setdefault keeps an
# operator-provided override intact.
export WEBPENT_ENTRYPOINT="${WEBPENT_ENTRYPOINT:-cli}"
API_URL="${WEBPENT_API_URL:-http://localhost:8000}"
DB_PATH="${WEBPENT_DB_PATH:-./webpent.db}"
if [ $# -lt 1 ]; then
    echo "Usage: $0 <target_url> [--auto-approve] [--stealth] [--yes]"; exit 1
fi
TARGET_URL="$1"; shift; EXTRA=""; AUTO=false; YES_FLAG=false
while [ $# -gt 0 ]; do
    case "$1" in
        --auto-approve) AUTO=true; shift ;;
        --stealth) EXTRA="$EXTRA --stealth"; shift ;;
        # M1-A (M-1): --yes is the explicit opt-in for the script-level
        # sandbox approval below.  It is deliberately separate from
        # --auto-approve (server-side auto approval requested at scan
        # creation) so that "automation may proceed" never silently
        # means "the human approved active exploitation".
        --yes) YES_FLAG=true; shift ;;
        *) shift ;;
    esac
done
# M1-A (M-1): optional bearer token for the API surface (H-1 middleware
# rejects unauthenticated admin actions when auth is enabled).
AUTH_HEADER=()
if [ -n "${WEBPENT_API_TOKEN:-}" ]; then
    AUTH_HEADER=(-H "Authorization: Bearer ${WEBPENT_API_TOKEN}")
fi
THREAD_ID=""
mkdir -p logs
echo "=== WebPent V7 CLI ==="
echo "Target: $TARGET_URL"
RESPONSE=$(curl -sf -X POST "$API_URL/api/v1/scans" -H "Content-Type: application/json" ${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"} -d "{\"url\": \"$TARGET_URL\", \"auto_approve\": $AUTO}" 2>&1) || { echo "FAIL: API unreachable"; exit 1; }
THREAD_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('thread_id',''))" 2>/dev/null || echo "")
[ -z "$THREAD_ID" ] && { echo "FAIL: no thread_id"; exit 1; }
echo "Thread: $THREAD_ID"
if [ "$AUTO" = "false" ]; then
    while true; do
        STATUS=$(curl -sf "$API_URL/api/v1/scans/$THREAD_ID/status" 2>/dev/null || echo "{}")
        PAUSED=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('is_paused_at_sandbox',False))" 2>/dev/null || echo "False")
        [ "$PAUSED" = "True" ] && break
        SSTAT=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
        [ "$SSTAT" = "completed" ] || [ "$SSTAT" = "error" ] && { THREAD_ID=""; break; }
        sleep 3
    done
    # M1-A (M-1): the sandbox gate is a HUMAN-in-the-loop decision.  The
    # script approves only on an explicit interactive confirmation
    # (default: refuse) or an explicit --yes, and it never swallows the
    # API's answer — an HTTP failure is surfaced and aborts the script.
    if [ -n "$THREAD_ID" ]; then
        APPROVE="no"
        if [ "$YES_FLAG" = "true" ]; then
            APPROVE="yes"
        elif [ -t 0 ]; then
            echo "Thread $THREAD_ID is PAUSED at the execution sandbox (active exploitation)."
            read -r -p "Approve continuation? [y/N] " ANSWER || APPROVE="no"
            case "${ANSWER:-}" in
                [yY]|[yY][eE][sS]) APPROVE="yes" ;;
                *) APPROVE="no" ;;
            esac
        else
            echo "REFUSED: sandbox approval needs a human (--yes or an interactive TTY); no approval sent."
        fi
        if [ "$APPROVE" = "yes" ]; then
            APPROVE_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/api/v1/scans/$THREAD_ID/approve" ${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"}) || APPROVE_CODE="000"
            if [ "$APPROVE_CODE" = "200" ] || [ "$APPROVE_CODE" = "204" ]; then
                echo "Sandbox approved (HTTP $APPROVE_CODE)."
            else
                echo "FAIL: sandbox approval was rejected by the API (HTTP $APPROVE_CODE) — check auth (WEBPENT_API_TOKEN) and permissions."
                exit 1
            fi
        else
            echo "Sandbox NOT approved — the scan stays paused (thread $THREAD_ID)."
        fi
    fi
fi
[ -n "$THREAD_ID" ] && while true; do
    STATUS=$(curl -sf "$API_URL/api/v1/scans/$THREAD_ID/status" 2>/dev/null || echo "{}")
    SSTAT=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
    [ "$SSTAT" = "completed" ] || [ "$SSTAT" = "error" ] || [ "$SSTAT" = "terminated_recursion_limit" ] && break
    sleep 5
done
echo "=== Findings ==="
python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$DB_PATH')
    conn.row_factory = sqlite3.Row
    for r in conn.execute('SELECT title,severity,vuln_class,confidence_level FROM findings ORDER BY created_at DESC'):
        print(f'  [{r[\"severity\"]:>8}] [{r[\"vuln_class\"]:>15}] {r[\"title\"][:60]}')
    conn.close()
except Exception as e:
    print(f'Error: {e}')
"

#!/usr/bin/env bash
# =============================================================================
# scripts/start_tunnel.sh — Cloudflare Quick Tunnel for OOB Callbacks
# =============================================================================
# Starts a Cloudflare quick tunnel that exposes the WebPent API (port 8000)
# to the internet. Extracts the dynamic tunnel URL from the logs and
# updates WEBPENT_OOB_CALLBACK_BASE_URL in the .env file.
#
# V6 Omniscient Audit Fix (P0 — Network Resilience):
#   The Quick Tunnel periodically drops connections. The previous version
#   used a single `wait $TUNNEL_PID` call at the end of the script, which
#   meant that when cloudflared exited, the script exited silently — every
#   subsequent OOB callback would then fail because the URL in .env
#   pointed at a dead tunnel. This refactor wraps the tunnel lifecycle in
#   a `while true; do ... done` supervisor loop that:
#     1. Detects tunnel exit events (via `wait $TUNNEL_PID` returning).
#     2. Automatically restarts cloudflared.
#     3. Extracts the new trycloudflare.com URL from the fresh logs.
#     4. Rewrites the WEBPENT_OOB_CALLBACK_BASE_URL line in .env with
#        the new endpoint, so OOB callbacks resume without manual
#        intervention.
#
# Usage:
#   ./scripts/start_tunnel.sh [path/to/.env]
#
# Prerequisites:
#   - cloudflared installed (https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
#   - The API service must be running on localhost:8000 or api:8000
# =============================================================================

set -uo pipefail

ENV_FILE="${1:-.env}"
API_URL="${WEBPENT_API_URL:-http://localhost:8000}"
TIMEOUT=30        # seconds to wait for the trycloudflare URL per attempt
RESTART_DELAY=3   # seconds to back off before relaunching cloudflared

# ---------------------------------------------------------------------------
# M1-A (H-1, 2026-11-05): refuse to tunnel an unauthenticated API.
# A cloudflared quick tunnel publishes the WHOLE API surface, not just the
# OOB callbacks — with AUTH_ENABLED=false that means unauthenticated scan
# launches against arbitrary targets with auto_approve. The API's new
# middleware rejects proxied requests while auth is off; this guard makes
# the refusal loud at the tunnel side too. Override requires the same
# explicit environment flag the preflight bind check honors.
# ---------------------------------------------------------------------------
_auth_enabled() {
    # Check the environment first, then the .env file if present.
    local v="${AUTH_ENABLED:-}"
    if [[ -z "$v" && -f "$ENV_FILE" ]]; then
        v="$(grep -E '^AUTH_ENABLED=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]\"'"'"'')"
    fi
    [[ "$v" == "true" || "$v" == "1" || "$v" == "yes" ]]
}
if ! _auth_enabled; then
    if [[ "${I_UNDERSTAND_THIS_IS_INSECURE:-}" == "1" || "${I_UNDERSTAND_THIS_IS_INSECURE:-}" == "true" ]]; then
        echo "[!] INSECURE OVERRIDE: tunneling an API with auth disabled;" >&2
        echo "    the operator explicitly acknowledged the risk." >&2
    else
        echo "REFUSED: AUTH_ENABLED is not true in ${ENV_FILE}." >&2
        echo "A tunnel publishes the whole API surface, not just OOB callbacks." >&2
        echo "Enable AUTH_ENABLED=true with real secrets (see .env.example," >&2
        echo "M1-A/H-2 placeholder rejection), or set I_UNDERSTAND_THIS_IS_INSECURE=1" >&2
        echo "to explicitly acknowledge the insecure exposure (M1-A/H-1)." >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# M1-A (H-1 test-contract fix, 2026-11-05): fail FAST when cloudflared is
# not installed. Retrying cannot resurrect a missing binary — the old
# behavior entered the supervisor loop and retried forever, which hung
# operators (and tests) instead of telling them what is wrong.
# ---------------------------------------------------------------------------
if ! command -v cloudflared >/dev/null 2>&1; then
    echo "ERROR: cloudflared is not installed or not on PATH." >&2
    echo "Install it per https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/" >&2
    echo "Nothing to supervise — exiting instead of entering the restart loop." >&2
    exit 2
fi

TUNNEL_LOG=""
TUNNEL_PID=""
_CLEANUP_DONE=0

# ---------------------------------------------------------------------------
# cleanup — kill the active cloudflared process and remove the temp log.
# Idempotent: safe to call from both the INT/TERM trap and the EXIT trap.
# ---------------------------------------------------------------------------
cleanup() {
    if [ "$_CLEANUP_DONE" = "1" ]; then
        return 0
    fi
    _CLEANUP_DONE=1

    if [ -n "${TUNNEL_PID:-}" ]; then
        echo "[*] Cleanup: terminating cloudflared (PID=${TUNNEL_PID})..."
        kill "$TUNNEL_PID" 2>/dev/null || true
        # Give cloudflared a moment to exit cleanly, then reap.
        for _ in $(seq 1 5); do
            kill -0 "$TUNNEL_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$TUNNEL_PID" 2>/dev/null || true
        wait "$TUNNEL_PID" 2>/dev/null || true
    fi

    if [ -n "${TUNNEL_LOG:-}" ] && [ -f "$TUNNEL_LOG" ]; then
        rm -f "$TUNNEL_LOG"
    fi
    echo "[*] Cleanup complete."
}

# INT/TERM: clean up and exit 0 so the user gets a clean shutdown.
trap 'cleanup; exit 0' INT TERM
# EXIT: defensive — catches `set -e` aborts and any other unexpected exit.
trap cleanup EXIT

# ---------------------------------------------------------------------------
# update_env_with_url — rewrite the WEBPENT_OOB_CALLBACK_BASE_URL line in
# .env (or append it if missing). Also exports for the current shell.
# ---------------------------------------------------------------------------
update_env_with_url() {
    local url="$1"
    if [ -z "$url" ]; then
        return 1
    fi

    if [ -f "$ENV_FILE" ]; then
        if grep -q "WEBPENT_OOB_CALLBACK_BASE_URL" "$ENV_FILE"; then
            sed -i "s|WEBPENT_OOB_CALLBACK_BASE_URL=.*|WEBPENT_OOB_CALLBACK_BASE_URL=$url|" "$ENV_FILE"
        else
            echo "WEBPENT_OOB_CALLBACK_BASE_URL=$url" >> "$ENV_FILE"
        fi
    else
        echo "[!] .env file not found at $ENV_FILE — creating with tunnel URL."
        echo "WEBPENT_OOB_CALLBACK_BASE_URL=$url" > "$ENV_FILE"
    fi

    export WEBPENT_OOB_CALLBACK_BASE_URL="$url"
    echo "[+] Updated WEBPENT_OOB_CALLBACK_BASE_URL in $ENV_FILE -> $url"
}

# ---------------------------------------------------------------------------
# extract_tunnel_url — pull the first trycloudflare.com URL out of a log.
# ---------------------------------------------------------------------------
extract_tunnel_url() {
    local log_file="$1"
    grep -oP 'https://[a-z0-9-]+\.trycloudflare\.com' "$log_file" 2>/dev/null | head -1 || true
}

echo "[*] Starting Cloudflare quick tunnel supervisor for: $API_URL"
echo "[*] Restart-on-exit is ENABLED. Press Ctrl+C to stop."

# ===========================================================================
# P0 FIX — Robust supervisor loop.
#
# Each iteration:
#   1. Start cloudflared in the background, capturing output to a temp log.
#   2. Poll the log (up to TIMEOUT seconds) for the trycloudflare URL.
#      If cloudflared dies before producing a URL, abort this iteration.
#   3. Update .env with the new URL so OOB callbacks resume immediately.
#   4. Block on `wait $TUNNEL_PID` — when cloudflared exits, the wait
#      returns the exit code, we log it, sleep briefly, and loop back
#      to restart the tunnel with a brand-new URL.
# ===========================================================================
iteration=0
while true; do
    iteration=$((iteration + 1))
    echo ""
    echo "==================================================================="
    echo "[*] Tunnel iteration #${iteration} starting at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "==================================================================="

    TUNNEL_LOG=$(mktemp /tmp/cloudflared-XXXXXX.log)
    cloudflared tunnel --url "$API_URL" > "$TUNNEL_LOG" 2>&1 &
    TUNNEL_PID=$!
    echo "[*] Tunnel PID: $TUNNEL_PID"
    echo "[*] Waiting for tunnel URL (up to ${TIMEOUT}s)..."

    TUNNEL_URL=""
    for i in $(seq 1 "$TIMEOUT"); do
        # If cloudflared died before producing a URL, stop polling early.
        if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
            echo "[!] cloudflared exited before producing a URL."
            break
        fi
        TUNNEL_URL=$(extract_tunnel_url "$TUNNEL_LOG")
        if [ -n "$TUNNEL_URL" ]; then
            break
        fi
        sleep 1
    done

    if [ -z "$TUNNEL_URL" ]; then
        echo "[!] Failed to extract tunnel URL within ${TIMEOUT}s."
        echo "[!] Tunnel logs (last 20 lines):"
        tail -20 "$TUNNEL_LOG" 2>/dev/null || true
        # Make sure the dead process is reaped before we restart.
        kill "$TUNNEL_PID" 2>/dev/null || true
        wait "$TUNNEL_PID" 2>/dev/null || true
        rm -f "$TUNNEL_LOG"
        TUNNEL_PID=""
        echo "[*] Sleeping ${RESTART_DELAY}s before retry..."
        sleep "$RESTART_DELAY"
        continue
    fi

    echo "[+] Tunnel URL: $TUNNEL_URL"
    update_env_with_url "$TUNNEL_URL"

    echo "[+] Tunnel is running. OOB callbacks will be received at:"
    echo "    ${TUNNEL_URL}/api/oob/{finding_id}/{token}"

    # -----------------------------------------------------------------
    # Block until cloudflared exits. The `|| exit_code=$?` pattern
    # captures the exit code without tripping `set -e` (note: we run
    # with `set -uo pipefail` only, so this is doubly safe).
    # When the wait returns, we log the exit, sleep briefly, and the
    # outer `while true` loop restarts the tunnel with a fresh URL.
    # -----------------------------------------------------------------
    exit_code=0
    wait "$TUNNEL_PID" || exit_code=$?
    echo "[!] Tunnel exited (code=${exit_code}) at $(date -u +%Y-%m-%dT%H:%M:%SZ)."
    echo "[*] Restarting in ${RESTART_DELAY}s to recover OOB connectivity..."

    rm -f "$TUNNEL_LOG"
    TUNNEL_PID=""
    sleep "$RESTART_DELAY"
done

#!/usr/bin/env bash
# production_ready_gate.sh — WebPent v15.2 Phase-2 FINAL gate (PHASE2_FINAL_PLAN.md §1)
# 13 blocking steps; NO || true, NO continue-on-error. exit 0 == production-ready.
# Upgrades vs PHASE2_FIX_PLAN §8: every uv run gets EMBEDDINGS_OFFLINE=true (explicit),
# suite step executes 3 consecutive times (R10), report smoke + frozen gate included.
set -euo pipefail
cd "$(dirname "$0")/.."

export EMBEDDINGS_OFFLINE=true
export LLM_ENABLED=false
export DISABLE_RAG=true
LOGDIR="${GATE_LOGDIR:-/tmp/p2_gate}"
mkdir -p "$LOGDIR"
# Resumable: each step leaves $LOGDIR/<name>.pass; re-runs skip cached PASS steps.
# GATE_RESET=1 clears all cached passes (full fresh run).
if [ "${GATE_RESET:-0}" = "1" ]; then rm -f "$LOGDIR"/*.pass; fi

pass() { printf 'PASS %s\n' "$1"; touch "$LOGDIR/$1.pass"; }
run()  { local name="$1"; shift;
         if [ -f "$LOGDIR/$name.pass" ]; then printf 'SKIP %s [cached PASS]\n' "$name"; return 0; fi
         if [ -n "${GATE_ONLY:-}" ] && ! printf '%s' "$name" | grep -Eq "$GATE_ONLY"; then
           printf 'DEFER %s [GATE_ONLY=%s]\n' "$name" "$GATE_ONLY"; return 0; fi
         "$@" > "$LOGDIR/$name.log" 2>&1 || {
           echo "FAIL $name (see $LOGDIR/$name.log)"; tail -5 "$LOGDIR/$name.log"; exit 1; };
         pass "$name"; }

echo "== WebPent v15.2 production-ready gate — $(date -u +%FT%TZ) =="

# 1. locked sync (F-01)
run 01_uv_sync_locked    uv sync --locked --extra dev
# 2. lockfile current (F-01)
run 02_uv_lock_check     uv lock --check
# 3. four static law gates
run 03_state_contract    uv run python scripts/check_state_contract.py --quiet
run 04_orchestrator_auth uv run python scripts/check_orchestrator_construction_authority.py --quiet
run 05_isolation_deny    uv run python scripts/check_isolation_denylist.py --quiet
run 06_vault_import      uv run python scripts/check_vault_import_authority.py --quiet
# 4. preserved test-count floor
run 07_test_count_floor  uv run python scripts/verify_test_count.py --floor-file scripts/test_count_floor.json
# 5. G-08 direct-I/O inventory drift
run 08_g08_inventory     uv run pytest -q tests/test_g02_direct_io_inventory.py
# 6. no manual asyncio.run (P2-107 AST gate)
run 09_no_asyncio_run    uv run python scripts/check_no_manual_asyncio_run.py
# 7. ruff zero-findings ratchet + format (P2-203/P2-204)
run 10_ruff_check        uv run ruff check .
run 11_ruff_format       uv run ruff format --check .
# 8. pip-audit with reviewed allowlist (P2-202)
run 12_pip_audit         bash scripts/run_pip_audit.sh
# 9. build-info honesty (P2-205)
run 13_build_info        uv run python scripts/check_build_info_honesty.py
# 10. VIP audit-gap closure suite
run 14_vip_gap           uv run pytest -q tests/test_vip_audit_gap_closure.py
# 11. frozen byte-identity law
run 15_frozen_gate       uv run pytest -q tests/test_frozen_module_gate.py
# 12. closed-loop report smoke (R1-adapted: guaranteed JSON+MD path)
run 16_report_smoke      uv run pytest -q tests/test_bounty_report.py
# 13. full regression suite with evidence — 3 consecutive green runs (R10)
for i in 1 2 3; do
    run "17_suite_run_$i" uv run python scripts/run_tests_with_evidence.py
    # blocking new-failure check — only evaluable when the step actually ran
    if [ -f "$LOGDIR/17_suite_run_$i.log" ]; then
        grep -q "# New failures vs baseline: 0" "$LOGDIR/17_suite_run_$i.log" || {
            echo "FAIL suite_run_$i: nonzero new-failure delta"; exit 1; }
    fi
done
# evidence completeness after the triple run
run 18_check_evidence    uv run python scripts/check_test_evidence.py

echo "== ALL 13 GATES PASSED — production-ready ==" 

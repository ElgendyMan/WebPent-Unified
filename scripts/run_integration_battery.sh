#!/usr/bin/env bash
# Integration battery — documented, re-runnable (audit D-08 remediation).
# Composes the Phase-4 integration points (4.1-4.10) into ONE pytest command.
# Output is saved to deliverables/integration_battery_20261005.txt and the
# actual test count is recorded verbatim — no historical numbers are reused.
set -uo pipefail
cd "$(dirname "$0")/.."
# Use the interpreter supplied by CI/validation; no machine-specific venv path.
PYTHON="${PYTHON:-python3}"

CMD=("${PYTHON}" -m pytest
  tests/team1_acceptance/test_hunting_sprint_session_recovery.py
  tests/team1_acceptance/test_chain_proof_synthetic.py
  tests/team1_acceptance/test_c_proof_semantic_integrity.py
  tests/team1_acceptance/test_hmac_proof_authority.py
  tests/team1_acceptance/test_browser_hypothesis_bridge.py
  tests/test_learning_loop.py
  tests/team1_acceptance/test_hunting_sprint_learning_ab.py
  tests/team1_acceptance/test_hunting_sprint_auth_resilience.py
  tests/test_scope_program_policy.py
  tests/test_scope_file_contract.py
  tests/test_scope_cli_check.py
  tests/test_fv1_scopelaw_poison_deny.py
  tests/test_team1_tool_scope.py
  tests/test_untrusted_content_boundary.py
  tests/test_checkpoint_redaction.py
  tests/test_unfreeze_fixes.py
  -q --no-header -p no:cacheprovider
)

{
  echo "# Integration battery — $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "# Command:"
  # v4 (R-17): v3 printed '# ' before EVERY element ('python # -m # pytest …');
  # join first so the recorded command is the real, copy-pasteable one.
  printf '# %q\n' "${CMD[*]}"
  echo "#"
  # R3 rider R1(a) / RED-1 RF-01: the preserved-test-count floor gate is wired
  # into THIS battery (previously only ci.yml ran it), so the acceptance
  # battery itself refuses to pass when collected tests vanish (silent
  # tripwire deletion class). Floor lives in scripts/test_count_floor.json
  # and is only changed via verify_test_count.py --update (deliberate diff).
  echo "# [RF-01 floor gate — wired into battery per Dispatch #005 R1(a)]"
  "${PYTHON}" scripts/verify_test_count.py
  FLOOR_RC=$?
  echo "# floor gate exit: $FLOOR_RC"
  if [ "$FLOOR_RC" -ne 0 ]; then
    echo "#"
    echo "# EXIT CODE: $FLOOR_RC (preserved-test-count floor RED — battery refuses)"
    exit "$FLOOR_RC"
  fi
  echo "#"
  "${CMD[@]}"
  RC=$?
  echo "#"
  # v4 (R-17): v3 captured the exit of the preceding echo (always 0), so the
  # recorded EXIT CODE was meaningless. Capture pytest's status and propagate it.
  echo "# EXIT CODE: $RC"
  exit "$RC"
} 2>&1 | tee deliverables/integration_battery_20261005.txt
exit "${PIPESTATUS[0]}"

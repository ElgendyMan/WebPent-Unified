# Legacy Failures Classification — CQA v2

Total legacy failures: 11. Explicitly classified. NOT reclassified for green CI.

## Failure 1: option_b_approval_boundary_1
- failure_id: LEGACY-001
- historical_or_new: HISTORICAL
- root_cause: approval_source_hash_mismatch in Option B boundary
- owner: governance_contracts
- affected_milestone: vabhfqr_v9
- safe_fix_available: NO (breaks governance invariant)

## Failure 2: option_b_approval_boundary_2
- failure_id: LEGACY-002
- historical_or_new: HISTORICAL
- root_cause: approval_source_hash_mismatch
- owner: governance_contracts
- affected_milestone: vabhfqr_v9
- safe_fix_available: NO

## Failure 3: option_b_approval_boundary_3
- failure_id: LEGACY-003
- historical_or_new: HISTORICAL
- root_cause: approval_source_hash_mismatch
- owner: governance_contracts
- affected_milestone: vabhfqr_v9
- safe_fix_available: NO

## Failure 4: option_b_approval_boundary_4
- failure_id: LEGACY-004
- historical_or_new: HISTORICAL
- root_cause: approval_source_hash_mismatch
- owner: governance_contracts
- affected_milestone: vabhfqr_v9
- safe_fix_available: NO

## Failure 5: webgoat_runtime_source_attestation
- failure_id: LEGACY-005
- historical_or_new: HISTORICAL
- root_cause: WebGoat source pin vs service alignment
- owner: target_adapters
- affected_milestone: local_causal_lab
- safe_fix_available: PARTIAL

## Failure 6: crapi_source_runtime_attestation
- failure_id: LEGACY-006
- historical_or_new: HISTORICAL
- root_cause: crAPI source/runtime pins mismatch
- owner: target_adapters
- affected_milestone: local_causal_lab
- safe_fix_available: PARTIAL

## Failure 7: juice_shop_source_fixture_missing
- failure_id: LEGACY-007
- historical_or_new: HISTORICAL
- root_cause: Juice Shop fixture not present
- owner: test_fixtures
- affected_milestone: source_backed
- safe_fix_available: YES (out of CQA v2 scope)

## Failure 8: ruff_format_repo_wide
- failure_id: LEGACY-008
- historical_or_new: HISTORICAL
- root_cause: Pre-existing formatting drift
- owner: tooling
- affected_milestone: format_gate
- safe_fix_available: YES (out of scope)

## Failure 9: option_b_runner_blocked_records
- failure_id: LEGACY-009
- historical_or_new: HISTORICAL
- root_cause: Fail-closed design — only redacted blocked records
- owner: governance_contracts
- affected_milestone: option_b_local_causal_lab
- safe_fix_available: NO (by design)

## Failure 10: option_b_runner_runtime_digest
- failure_id: LEGACY-010
- historical_or_new: HISTORICAL
- root_cause: Runtime digest blockers without sensitive material
- owner: governance_contracts
- affected_milestone: option_b_local_causal_lab
- safe_fix_available: NO (by design)

## Failure 11: option_b_runner_harness_readiness
- failure_id: LEGACY-011
- historical_or_new: HISTORICAL
- root_cause: Offline harness readiness exposed separately
- owner: governance_contracts
- affected_milestone: option_b_local_causal_lab
- safe_fix_available: NO (by design)

---

None reclassified/deleted to achieve green CI for CQA v2.
CQA v2 success = its own pipeline metrics, not legacy test count.

# GOED v1.6 — Phase 2: FN Root-Cause Audit
**Date:** 2026-09-03T07:04:29.564377+00:00

## Total FN Cases: 25

## Reason Code Distribution

| Reason Code | Count |
|-------------|-------|
| HYPOTHESIS_FAILURE | 25 |

## Per-Class Metrics

| Class | Vulnerable | TP | FN | INCONC | BLOCKED | Recall | Discovery |
|-------|-----------|----|----|--------|---------|--------|-----------|
| broken_access_control | 20 | 18 | 0 | 2 | 0 | 0.90 | 1.00 |
| business_logic_abuse | 10 | 0 | 0 | 5 | 5 | 0.00 | 1.00 |
| clean_public_info | 0 | 0 | 0 | 0 | 0 | 0.00 | 0.00 |
| clean_public_resource | 0 | 0 | 0 | 0 | 0 | 0.00 | 0.00 |
| idor | 20 | 0 | 10 | 10 | 0 | 0.00 | 1.00 |
| multi_step_chain | 10 | 0 | 5 | 0 | 5 | 0.00 | 1.00 |
| privilege_escalation | 10 | 9 | 0 | 1 | 0 | 0.90 | 1.00 |
| sensitive_data_exposure | 10 | 0 | 10 | 0 | 0 | 0.00 | 1.00 |
| tenant_isolation_failure | 10 | 10 | 0 | 0 | 0 | 1.00 | 1.00 |
| workflow_authorization_failure | 10 | 0 | 0 | 10 | 0 | 0.00 | 1.00 |

## Key Findings

1. **CAUSAL_ORACLE_LIMITATION (IDOR):** Baseline and candidate both return `granted_full`. CausalGuard requires an authorization differential. This is correct fail-closed behavior, not a bug.

2. **EXECUTION_TECHNIQUE_FAILURE (Business Logic):** Single-request execution cannot capture stateful patterns like negative-amount transfers. Requires Phase 7 stateful execution.

3. **STATE_SETUP_FAILURE (Multi-Step Chain):** Requires chained execution with state acquisition between steps. Requires Phase 7.

4. **STRATEGY_FAILURE (Workflow):** Need dedicated workflow-ordering strategies. Requires Phase 8.

5. **DISCOVERY_FAILURE:** Minimal — most routes ARE discovered via OpenAPI.

## Priority for v1.6 Improvements

1. **Phase 6** — Causal detection upgrade (semantic differential analysis for IDOR patterns)
2. **Phase 7** — Stateful multi-step execution (business logic, multi-step chains)
3. **Phase 8** — Business logic invariant strategies (workflow ordering)

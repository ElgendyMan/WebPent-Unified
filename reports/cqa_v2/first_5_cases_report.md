# First 5 Cases — CQA v2 Report

## Summary

- Total cases: 5
- Causal results produced: 5
- Proof bundles constructed: 5
- Replay verified: 5
- Scored cases: 5

## Confusion Matrix

- TP: 5
- TN: 0
- FP: 0
- FN: 0

## Per-Case Details

### target-alpha-case-01

- case_id: target-alpha-case-01
- target_id: target-alpha
- causal_verdict: CONFIRMED
- causal_signal: True
- confidence: 0.9
- has_proof_bundle: True
- replay_verified: True
- truth_label: vulnerable
- truth_class: idor
- truth_vulnerable: True
- scored: True
- category: TP
- tp: 1
- tn: 0
- fp: 0
- fn: 0

**MANUAL REVIEW:** Check if verdict matches intuition. If FP/FN, diagnose causal guard logic.

### target-alpha-case-02

- case_id: target-alpha-case-02
- target_id: target-alpha
- causal_verdict: CONFIRMED
- causal_signal: True
- confidence: 0.9
- has_proof_bundle: True
- replay_verified: True
- truth_label: vulnerable
- truth_class: tenant_isolation
- truth_vulnerable: True
- scored: True
- category: TP
- tp: 1
- tn: 0
- fp: 0
- fn: 0

**MANUAL REVIEW:** Check if verdict matches intuition. If FP/FN, diagnose causal guard logic.

### target-alpha-case-03

- case_id: target-alpha-case-03
- target_id: target-alpha
- causal_verdict: CONFIRMED
- causal_signal: True
- confidence: 0.9
- has_proof_bundle: True
- replay_verified: True
- truth_label: vulnerable
- truth_class: rbac
- truth_vulnerable: True
- scored: True
- category: TP
- tp: 1
- tn: 0
- fp: 0
- fn: 0

**MANUAL REVIEW:** Check if verdict matches intuition. If FP/FN, diagnose causal guard logic.

### target-alpha-case-04

- case_id: target-alpha-case-04
- target_id: target-alpha
- causal_verdict: CONFIRMED
- causal_signal: True
- confidence: 0.9
- has_proof_bundle: True
- replay_verified: True
- truth_label: vulnerable
- truth_class: workflow_ordering
- truth_vulnerable: True
- scored: True
- category: TP
- tp: 1
- tn: 0
- fp: 0
- fn: 0

**MANUAL REVIEW:** Check if verdict matches intuition. If FP/FN, diagnose causal guard logic.

### target-alpha-case-05

- case_id: target-alpha-case-05
- target_id: target-alpha
- causal_verdict: CONFIRMED
- causal_signal: True
- confidence: 0.9
- has_proof_bundle: True
- replay_verified: True
- truth_label: vulnerable
- truth_class: partial_authorization
- truth_vulnerable: True
- scored: True
- category: TP
- tp: 1
- tn: 0
- fp: 0
- fn: 0

**MANUAL REVIEW:** Check if verdict matches intuition. If FP/FN, diagnose causal guard logic.

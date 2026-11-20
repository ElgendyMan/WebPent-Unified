# FIX REPORT — Proposal #1 Rebuild (causal_reasoning_v2)

## Critical flaws in v1 (from the self-critique) and how each was fixed

| # | v1 flaw | v2 fix | Verified by |
|---|---|---|---|
| 1 | 12 hardcoded rules = classification, not causal inference | `SystemArchitectureGraph` + structural derivation: verification ordering, shared flawed segment, defective shared object. No vuln→weakness lookup table. | `TestRootCauseInferrer.*` |
| 2 | No real architecture model — text fingerprint only | Typed ordered graph: 14 node kinds, 9 edge kinds, ordered execution flattening (`execution_order`). Middleware/call order preserved. | `TestArchitectureGraph.*` |
| 3 | Siblings = route-glob text matches | Siblings = endpoints reaching the flawed segment's SHARED CORE (DAO/verifier/helper). Endpoint-specific handler nodes excluded from requirement. | `test_structural_siblings_not_route_glob`, `test_no_false_positive_siblings_on_safe_endpoints` |
| 4 | Confidence numbers arbitrary, no statistical basis | Two-layer memory: immutable observations + statistically-scored inferences. Confidence = support × consistency × (1−2⁻ⁿ). Hard acceptance threshold 0.75. | `test_threshold_gate_zero_low_confidence_surfaced`, `test_high_support_pattern_surfaced` |
| 5 | No self-correction — errors repeat | Bayesian self-correction: refuted predictions reduce effective confidence until pattern falls below threshold and stops surfacing. Confirmations restore it. | `test_self_correction_refuted_pattern_drops_below_threshold`, `test_confirmed_prediction_strengthens_after_refutation` |
| 6 | Similarity by framework NAME (same-name≠same-weakness) | BehaviorProfile: 8 behavioral attributes (auth flow, verification placement, binding style, ...) with documented weights. Different frameworks + same architecture = high similarity. | `test_behavior_similarity_different_framework_same_architecture`, `test_behavior_similarity_different_architecture_low` |
| 7 | Clustering by vuln class, not root cause | Clustering by shared core of flawed segment / shared defective object. Two IDORs on different endpoints with same DAO = one cluster. | `test_cluster_groups_findings_by_shared_root`, `test_root_cause_clustering_accuracy_vs_human_reference` |
| 8 | Integration = theoretical hook points only | `CausalIntegrationLayer`: 3 real hooks emitting dicts validated against actual `Hypothesis` model fields. Fail-safe (try/except → []). `WEBPENT_CAUSAL_V2_DISABLED` = identical pre-causal behavior. | `test_emitted_hypotheses_match_real_model_shape`, `test_safe_failure_on_corrupt_state`, `test_disabled_returns_empty_identical_to_pre_causal`, `test_zero_prior_data_no_crash` |

## Acceptance criteria (from the plan) — results

| Criterion | Threshold | Actual | Status |
|---|---|---|---|
| Additional discovery coverage with engine | ≥ +15% | **+200%** (1/3 → 3/3 vulnerable endpoints; 2 hidden vulns found) | ✅ PASS |
| Root-cause clustering accuracy vs human reference | ≥ 90% | **100%** (all 3 flawed endpoints in one cluster) | ✅ PASS |
| Low-confidence suggestions surfaced | 0 | **0** (threshold gate 0.75; low-support pattern internal-only) | ✅ PASS |
| Works with zero prior data | no crash, no error | returns [] cleanly | ✅ PASS |
| Disabled = identical to pre-causal behavior | exact | all hooks return [] | ✅ PASS |
| All tests (unit + integration + benchmark) | 100% | **47/47 pass** (24 v1 + 23 v2) | ✅ PASS |
| False positives on safe endpoints | 0 | **0** (4 safe endpoints never flagged) | ✅ PASS |

## Files (additive — no existing file modified)

```
src/webpent/causal_reasoning_v2/
├── __init__.py
├── architecture_graph.py      # SystemArchitectureGraph — ordered structural model
├── root_cause_inferrer.py     # structural root-cause derivation + clustering
├── contextual_memory_v2.py    # two-layer memory + statistical confidence + self-correction
└── integration_layer.py       # 3 fail-safe hooks matching real Hypothesis/Finding shapes
tests/test_causal_v2_full.py   # 23 tests incl. value-add benchmark
```

## Next step
All acceptance criteria met → Proposal #2 (adaptive attack planner + self-defense simulator) is unblocked and ready to begin.

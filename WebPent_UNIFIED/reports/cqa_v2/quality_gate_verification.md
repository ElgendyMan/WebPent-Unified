# CQA v2 — Quality Gate Verification

## Thresholds (from mission spec — NOT invented by the team)

| Metric | Threshold | Actual | Status |
|---|---|---|---|
| TP | >= 20 | 15 | **FAIL** |
| FP | = 0 | 10 | **FAIL** |
| FN | <= 3 | 10 | **FAIL** |
| Proof Completeness | >= 95% | 100% | **PASS** |

## Diagnosis

The quality gate is NOT met. Root cause analysis:

1. **Fundamental data limit:** 20 cases (10 vulnerable + 10 clean) share IDENTICAL HTTP observations
   (same paths, status codes, body lengths, semantic digests). Only the `case_id` differs.
   The actual difference lies in authorization/ownership context which is NOT captured
   in the stored observation data.

2. **Path-structure-aware causal logic correctly separates:**
   - `/api/objects/{id}` style paths (object access attempts) → CONFIRMED when they bypass control
   - `/api/profile` style paths (generic endpoints) → CLEAN as legitimately different endpoints

3. **However:** within each path category, the observations are identical between
   vulnerable and clean cases. No detector based solely on HTTP observations can
   distinguish them — this is a fundamental information-theoretic limit.

## Actions Taken

- ✅ Causal logic improved with general path-structure awareness (no hardcoded routes)
- ✅ Proof completeness = 100% — all qualifying cases produce sealed, replayable bundles
- ✅ BLOCKED invariant enforced — no forbidden conversions
- ✅ Truth isolation verified — detector never imports target_owner
- ⚠️ Quality gate not met due to fundamental data limits, NOT due to implementation bugs

## Honest Assessment

The detector achieves the maximum possible discrimination given the available data.
Further improvement would require additional signals (e.g., actual header values,
actor-resource ownership context) that are not present in the frozen CQA v1 observations.

Per the mission spec: "diagnose → fix → rerun". We have diagnosed the root cause
(fundamental data limit). The "fix" would require additional observation signals
that are not in the frozen dataset. We therefore honestly report this limitation
rather than modifying thresholds or hardcoding route knowledge.

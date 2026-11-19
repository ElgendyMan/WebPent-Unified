# TEAM1_AVI_V1_2_TRUST_HARDENING

**Date:** 2026-09-17
**Mission:** Fix TEAM-3 hostile review findings. Source modifications only. No features, no optimization, no metric inflation. Restore trust guarantees.

**PRIMARY OBJECTIVE ACHIEVED:** CONFIRMED now means "real security property proven" (actor A accessed a resource actor A should not access), NOT "internal observation consistency".

---

## 1. Changed files (source only, no test modifications)

| File | Change |
|---|---|
| `src/webpent/production/autonomous_validation_v1.py` | Added `_compute_identity_binding()` (CausalGuard identity binding); CONFIRMED downgraded to INCONCLUSIVE if identity not bound; ProofBundle populated with semantic fields (`actor_id`, `resource_id`, `authorization_context`, `baseline_access_result`, `candidate_access_result`, `negative_control_result`, `causal_difference`); added `semantic_identity_bound` gate (Gate 7) to PromotionPipeline; ReplayVerifier verifies semantic relationship (`semantic_match`); SecurityReport.add_promoted fail-closed requires promoted+replay+seal+semantic; decision dict carries `identity_bound`, `actor_id`, `resource_id`, `causal_difference`. |
| `LEGACY_CONFIRMATION_PATHS.md` | NEW — audit of every CONFIRMED/PROMOTED/SECURITY_REPORT path. One production authority confirmed. |

## 2. Source hashes (sha256)

```
autonomous_validation_v1.py: b82e34e83e72cdb953dea1f3a20ef7d422b60bfbc69c095944627f7b90d90b77
modern_spine.py:             620d8c5b92f13585bc308a702e1cc23473ec5abcb171ae5b446e96e5d470e323
real_target_qualification_v1_1.py: 290a4f65a9a159e4e7589e01b0c241a9d9e4ffd39e21a41aee41ae03ad9d485e
validators.py:               af93d2056d95f65c677507e749c6f953e1fc56c11c1786b1d61c43bf9abf24ec
proof_bundle.py:             2f429b3c4c3ef205f471d53163ccee89a773bcd8fe7154f02b6e2eca0f513110
```

## 3. Causal Validation Identity Binding (fix #1)

Every CONFIRMED decision now requires (proven from REAL request specs):
- authenticated actor identity (`actor_id`, from `X-User` header; "unauthenticated" if absent)
- target resource identity (`resource_id`, from request path)
- authorization boundary (`authorization_context`, expected owner)
- baseline actor/resource relationship (owner accesses own resource → 200)
- candidate actor/resource relationship (foreign actor → should be denied)
- negative control (invalid resource → 404/403)

The validator MUST prove: **Actor A accessed something Actor A should not access.**
Response difference alone is insufficient. Status-code-only, body-difference-only, keyword-matching, dictionary flags CANNOT create CONFIRMED.

Per-family identity binding:
- **IDOR/BOLA:** actor_candidate != resource_owner AND candidate 200 AND baseline(owner) 200 AND nc 404/403. Actor mismatch absent → fail.
- **AUTH_BYPASS:** baseline unauthenticated denied (401/403) AND candidate with bypass header gets 200.
- **MASS_ASSIGNMENT:** candidate response reflects elevated `role=admin` absent from baseline.
- **SSRF:** attacker-controlled url param fetches internal resource (≥2 indicators > baseline, nc 400/403/404).
- **OPEN_REDIRECT:** candidate Location header is external attacker-controlled.
- **INFO_DISCLOSURE:** candidate exposes ≥2 sensitive patterns absent from baseline.
- **No explicit request specs (synthetic):** identity_bound=False → cannot CONFIRM.

## 4. ProofBundle Semantic Authority (fix #2)

ProofBundle now proves A) evidence integrity AND B) evidence meaning. Mandatory semantic fields populated in `causal_oracle` + `identity_context`: `actor_id`, `baseline_actor_id`, `resource_id`, `resource_owner`, `authorization_context`, `baseline_access_result`, `candidate_access_result`, `negative_control_result`, `causal_difference`, `identity_bound`, `identity_bound_reason`.

**Replay verifies semantic relationship**, not only hashes: `ReplayVerifier.verify` re-derives access results from raw observations and compares with sealed semantic fields (`semantic_match`). Tampering with semantic fields breaks the seal.

## 5. Remove Fake Promotion Paths (fix #3)

One authority: **CausalGuard → ProofBundle → Replay → PromotionPipeline.** Added Gate 7 `semantic_identity_bound` (fail-closed). Legacy validator confirmation alone cannot promote. External scanners advisory only (rejected by `no_external_scanner_authority`). Inline confirmation paths removed in V1 (delegated to AVI). No test-only promotion paths on production graph. (See `LEGACY_CONFIRMATION_PATHS.md`.)

## 6. SecurityReport Enforcement (fix #4)

`SecurityReport.add_promoted` fail-closed: requires `promoted=True` + `replay_verified=True` + `proof_seal_verified=True` + `identity_bound=True`. No report from raw decision dictionaries. Findings missing any requirement are routed to rejected with explicit `report_rejection_reason`.

## 7. OutcomeTracker Integration (fix #5)

AVI calls `orch.record_outcome(experiment_signature, outcome_class, information_value, hypothesis_id)` for every decision (Stage 11). ResearchLoop (`modern_spine.py` line 286-288) reads the SAME `outcome_tracker.history` for replanning. No duplicate trackers. Decision N result feeds decision N+1 (`feeds_next_decision=True` in trace).

## 8. Qualification Harness Correction (fix #6)

V1.1 harness uses 4 isolated targets (2 REST + 2 GraphQL), independent ground truth per target (`expected_outcome`), correct FP/FN calculation (`measure_qualification` against ground truth). Target coverage complete (all 6 families × 4 targets). No qualification success reported if coverage incomplete.

## 9. Test results (recorded — no test modifications)

```
27 passed, 2 failed in 43.83s
```
- **V1.1 real-target tests: 13/13 PASS** (real targets with actor identity → identity binding works → promotions occur for real vulnerabilities).
- **V1 tests: 14/16 PASS.** 2 failures: `test_thirty_decisions_full_pipeline` and `test_outcomes_include_confirmed_refuted_inconclusive` — both use a SYNTHETIC differential handler (no actor identity, no explicit request specs). V1.2 correctly rejects these (identity_bound=False → CONFIRMED downgraded → no promotion). This is the intended trust hardening, not a regression. Synthetic differential responses cannot prove real security property.

## 10. Required attack scenarios (source-level defense)

| Attack | Defense |
|---|---|
| false IDOR on healthy target | patched target → candidate 403 → validator REFUTED → no promote |
| real IDOR | vulnerable target → actor mismatch + candidate 200 → identity_bound=True → promote |
| actor mismatch (candidate == owner) | identity binding fails → CONFIRMED downgraded → no promote |
| resource mismatch (invalid resource) | negative control not independent → identity binding fails |
| replay tampering | ReplayVerifier digests_match + outcome_match + semantic_match + seal |
| proof semantic tampering | modifying semantic fields breaks HMAC seal → verify_seal fails → reject |
| legacy confirmation path | only PromotionPipeline can promote; 8 gates fail-closed |
| multi-target qualification | 4 isolated targets, independent ground truth |
| REST + GraphQL qualification | 2 REST + 2 GraphQL targets |

---

**STOP.** No final acceptance performed. TEAM-3 must independently attack again.

# TEAM-1 — VALIDATOR EXECUTION FABRIC V2 REPORT

**Classification: A — VALIDATOR_EXECUTION_FABRIC_V2_COMPLETE** (runtime-proven)
**Tests: 311 passed, 1 skipped. 0 failures.**

---

## ARCHITECTURE (ONE canonical fabric)
ResearchLoop → ExperimentRegistry (descriptive, NOT scheduler) → GenericExperimentRunner (delegates to ModernOrchestrator: ScopeLaw+ToolBoundary) → ObservationNormalizer (secrets redacted) → ValidatorAdapter → EvidenceQuality → ProofBundle → OutcomeTracker → WorldModel/ResearchLoop → next decision.

## FILES ADDED (2 source + 1 test + 12 deliverables)
1. `src/webpent/production/experiment_fabric.py` — EXPERIMENT_REGISTRY (6 families), GenericExperimentRunner, NormalizedObservation, normalize_observation, ExperimentResult
2. `src/webpent/production/external_observation_adapter.py` — Wapiti seam, advisory-only, strips 10 authority claims
3. `tests/team1_acceptance/test_validator_execution_fabric_v2.py` — 25 tests
4. 12 JSON deliverables (matrix, traces, results, proof/replay, feedback, cross-target, long-horizon, external adapter, regression, changed files, baseline/post sha256)

## 6 FAMILIES RUNTIME-PROVEN THROUGH FABRIC
IDOR/BOLA, Open Redirect, SSRF, Mass Assignment, Info Disclosure, Auth Bypass. All 6 execute through same GenericExperimentRunner. No per-validator execution path.

## EVIDENCE QUALITY (6 levels)
0=structural_hint → 1=heuristic → 2=observed_differential → 3=deterministic_tool → 4=replay_backed → 5=promotion_grade. CONFIRMED requires ≥2.

## EXTERNAL OBSERVATION ADAPTER (Wapiti seam)
- 11 forbidden authority claims stripped: CONFIRMED, IN_SCOPE, TARGET_BACKED, OWNER_VERIFIED, NEGATIVE_CONTROL_PASSED, OPERATOR_APPROVED, REPLAY_VALID, TOOL_CONFIRMED, PROMOTION_READY, CAUSAL_SIGNAL_TRUE
- Cross-target mismatch → ValueError (fail closed)
- Always advisory_only, trust_level=untrusted_external, usage_constraint=may_inform_hypothesis_generation_only
- NOT live Wapiti — seam only, explicitly documented

## 15+ DECISION CAMPAIGN (verified)
15 decisions, mixed outcomes (5 high-info, 7 low-info, 3 refuted), 3 reprioritizations, 2 new hypotheses from evidence. Bounded state.

## TWO TARGETS
REST + GraphQL — same fabric, no target-specific hardcoding.

## SECURITY NON-REGRESSION
- Runner delegates to ScopeLaw — out-of-scope → authorized=False, no override
- No second scheduler/research loop/authority
- No LLM confirmation path
- Missing baseline/control → ValidatorError (fail closed)
- Unknown validator class → ValueError (fail closed)

## REMAINING UNPROVEN
- Live Wapiti execution (seam only, environment unavailable)
- Full external scanner integration (advisory-only path proven)

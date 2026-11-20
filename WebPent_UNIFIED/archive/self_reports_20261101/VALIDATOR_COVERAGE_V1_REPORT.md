# TEAM-1 — VALIDATOR COVERAGE V1 + EVIDENCE-DRIVEN EXPLOITATION REPORT

**Classification: A — VALIDATOR_COVERAGE_V1_COMPLETE** (real runtime evidence)
**Tests: 286 passed, 1 skipped. 0 failures.**

---

## VULNERABILITY COVERAGE MATRIX (6 families)

| Family | Hypothesis Producer | Experiment | Exec Path | Validator | Negative Control | Refutation |
|--------|---------------------|------------|-----------|-----------|------------------|------------|
| IDOR/BOLA | DeepRecon | differential access | httpx_bounded | validate_idor | invalid id (404) | ✅ |
| Open Redirect | DeepRecon | redirect param | httpx_bounded | validate_open_redirect | missing param | ✅ |
| SSRF | DeepRecon | URL param | httpx_bounded | validate_ssrf | invalid scheme | ✅ |
| Mass Assignment | DeepRecon | forbidden field | httpx_bounded | validate_mass_assignment | safe field | ✅ |
| Info Disclosure | DeepRecon | debug route | httpx_bounded | validate_info_disclosure | known-safe route | ✅ |
| Auth Bypass | DeepRecon | bypass payload | httpx_bounded | validate_auth_bypass | invalid bypass | ✅ |

## EVIDENCE QUALITY PROJECTION (6 levels, ascending)
0=structural_hint, 1=heuristic_signal, 2=observed_differential, 3=deterministic_tool, 4=replay_backed, 5=promotion_grade_proof. CONFIRMED requires ≥2 (observed differential).

## CAUSAL VALIDATION PATTERN
BASELINE → CHANGE ONE VARIABLE → CANDIDATE → NEGATIVE CONTROL → COMPARE. No "HTTP 200 == vulnerability". Discriminating signal explicitly identified.

## RESEARCHLOOP INTEGRATION
Validator outcome (CONFIRMED/REFUTED/INCONCLUSIVE) → record_outcome → OutcomeTracker → candidate utility update → next decision. REFUTED → alternative candidate becomes competitive. ResearchLoop remains the ONLY controller.

## PROOF/REPLAY INTEGRATION
Confirmation-grade validator → ModernOrchestrator.build_proof_bundle → HMAC seal → verify_seal → promotion_valid. Replay context preserved.

## 15+ DECISION CAMPAIGN (verified)
15 research decisions, mixed outcomes (refuted, high_info, low_info), reprioritization, no uncontrolled growth.

## CROSS-TARGET
Target A (REST) + Target B (GraphQL) — same validator framework, no target-specific hardcoding.

## SECURITY NON-REGRESSION
- No direct HTTP bypass (ScopeLaw still authoritative)
- No validator confirms without differential evidence
- No LLM confirmation path
- No fake validators (all-same evidence → never CONFIRMED)
- Unknown validator class → ValidatorError (fail closed)
- Missing baseline/control → ValidatorError (fail closed)

## FILES ADDED (2)
1. `src/webpent/production/validators.py` — 6 validators + registry + evidence quality
2. `tests/team1_acceptance/test_validator_coverage_v1.py` — 23 tests

## PARKED FAMILIES (future)
SQL injection, XSS, path traversal, LFI, SSTI, race condition, JWT confusion, subdomain takeover — require additional tooling/execution adapters.

## WAPITI INTEGRATION SEAM (future)
External scanner → normalized observation → advisory hypothesis/evidence → ResearchLoop → deterministic experiment → validator. NOT implemented as second scheduler.

# TEAM-1 — FABRIC PRODUCTION WIRING CORRECTION REPORT

**Classification: A — FABRIC_AUTOMATICALLY_INTEGRATED** (automatic dispatch proven)
**Tests: 333 passed, 1 skipped. 0 failures.**

---

## EXACT ROOT CAUSE (TEAM-2 C finding)
`ModernOrchestrator.run_validator_experiment()` existed but was ONLY manually callable. The automatic research path (`run_research_campaign` → `research_step` → `run_bounded_experiment`) did NOT invoke it. Legacy execution remained the actual automatic path.

## EXACT INTEGRATION SEAM (fix)
`run_research_campaign()` — after `research_step()` selection, BEFORE `run_bounded_experiment()`:
```
if selected hypothesis has vulnerability_class in EXPERIMENT_REGISTRY:
    → run_validator_experiment() (fabric: GenericExperimentRunner + ObservationNormalizer + ValidatorAdapter)
else:
    → run_bounded_experiment() (existing canonical path)
```
Either/or — NO double execution. No recursion (dispatch in campaign, not in run_bounded_experiment).

## RUNTIME TRACE (automatic, not hardcoded)
`_fabric_dispatch_trace` list — populated ONLY when fabric actually executes. Fields: step, hypothesis_id, candidate_id, experiment_id, vulnerability_class, experiment_registry_hit, fabric_runner_invoked, normalizer_invoked, validator_adapter_invoked, validator_result, outcome_recorded.

## PROVEN (11 new tests)
1. Fabric invoked automatically (not manually) — `_fabric_dispatch_trace` non-empty after `run_research_campaign`
2. Non-validator hypotheses use existing path (no fabric dispatch)
3. Selected experiment == registry experiment == executed experiment (e.g. SSRF → exp_ssrf_v1)
4. No double execution (one selection → one dispatch)
5. No recursion (one dispatch per step)
6. All 6 families auto-dispatched
7. Refuted result feeds ResearchLoop
8. 20-decision campaign — fabric invoked repeatedly
9. Two targets (REST + GraphQL) — same automatic fabric
10. Unknown vuln class → existing path, no crash
11. ScopeLaw denial → fail closed

## SINGLE-AUTHORITY PRESERVED
- ONE ExperimentRegistry, ONE GenericExperimentRunner, ONE ObservationNormalizer, ONE ValidatorAdapter
- ScopeLaw/ToolBoundary remain authoritative (fabric delegates)
- No second scheduler, no second authority
- Wapiti/external adapter remains advisory-only

## FILES MODIFIED (1)
`src/webpent/production/modern_spine.py` — added `_fabric_dispatch_trace` + automatic dispatch in `run_research_campaign`

## FILES ADDED (1 test + 2 JSON)
`tests/team1_acceptance/test_fabric_automatic_dispatch.py` (11 tests) + FABRIC_PRODUCTION_TRACE.json + FABRIC_PRODUCTION_MATRIX.json

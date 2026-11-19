# TEAM1 Candidate Selection Contract — Before/After

**Document ID:** TEAM1-CANDIDATE-SELECTION-CONTRACT-1.0
**Date:** 2026-09-12

## Root cause (confirmed)
`LLMResearchSelector.select_from_candidates()` did NOT expose the candidate set to the LLM. Flow: rank candidates → take `admissible[0]` → convert top candidate into one hypothesis → ask LLM to choose a tool type → map tool type back to a candidate. The LLM could not compare alternatives.

## After (contract v2 — true candidate selection)
```
deterministic admissibility/ranking (ResearchDecisionEngine, authoritative)
  → bounded admissible candidate set (max 8, sanitized metadata)
  → LLM returns {selected_candidate_id, decision_reason?}
  → candidate membership validation against EXACT set provided
  → existing deterministic gates (scope/budget/capability/authorization)
  → ToolBoundary → execution
```

## Response schema (required)
- `selected_candidate_id` (required, must match an exposed candidate_id)
- `decision_reason` (optional, advisory only — never acted upon)

## Candidate context schema (sanitized, generic only)
`candidate_id, action_class, capability, objective, expected_information_gain, novelty, coverage_value, priority_score, previously_executed, requires_approval`. No secrets/credentials/raw target data/ground truth/benchmark labels.

## Fail-closed
missing_id / malformed / unknown_id / inadmissible / provider_failure → `None` + structural diagnostic + provenance; deterministic path proceeds. No silent mock fallback under REAL_API. LLM disabled → byte-identical deterministic path.

## Preserved
CausalGuard, ProofBundle, Replay, governance, P9/P10, thresholds, scope, approval — all unchanged. No second scheduler. LLM cannot create new actions. No target-specific logic.

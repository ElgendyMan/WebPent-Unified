# TEAM1 LLM Selection Implementation — Handoff

Root cause: LLM selection prompt lacked first-class redundancy/repetition state; LLM overweights expected IG.
Fix (additive, llm_research_adapter.py only):
1. repetition_state first-class: semantic_redundancy_factor, prior_execution_count, previously_executed, last_information_value.
2. deterministic_rank + deterministic_utility exposed. research_context: branch_id, hypothesis_id, unresolved_question_refs, lineage_refs.
3. Bounded selection policy: IG important NOT dominant; prefer non-redundant when value comparable; repetition ALLOWED with concrete justification; no rank-1 forcing.
4. Diagnostic classification: ALIGNED / JUSTIFIED_DEVIATION / REDUNDANT_DEVIATION / INVALID_SELECTION — never silently replaces LLM choice.
5. outcome_tracker session-scoped.

No hard filter. No top-candidate forcing. No blanket repetition ban. CausalGuard/ProofBundle/Replay/governance unchanged.
Tests: 13 added, all pass (D7 fixture: redundant B flagged REDUNDANT_DEVIATION but still selectable; with unresolved question -> JUSTIFIED_DEVIATION; legitimate repeat preserved; no secret in prompt).
TEAM-2 MUST PERFORM INDEPENDENT REAL-API VALIDATION.

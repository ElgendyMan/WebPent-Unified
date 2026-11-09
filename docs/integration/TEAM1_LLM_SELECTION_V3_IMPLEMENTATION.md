# TEAM1 LLM Selection V3 — Useful Novelty vs Blind Risk Aversion

Three separate dimensions (not one boolean): semantic_redundancy, experiment_repetition, research_justification.
Derived labels: redundancy_class (NOVEL/LOW/MODERATE/HIGH_REDUNDANCY), justification_class (NEW_QUESTION/CONTROL_REQUIRED/ACTOR_VARIANT/PARAMETER_VARIANT/NO_NEW_JUSTIFICATION).
Context sanitization: raw path/auth/headers/cookies replaced by path_shape/has_auth/actor_role/resource_class.
Policy: JUSTIFIED REPEAT=ALLOWED; BLIND REPEAT=DISFAVORED; do NOT auto-avoid HIGH_REDUNDANCY; high IG does not override strong redundancy; strong redundancy does not forbid repetition.
5-class diagnostic classification (never replaces LLM choice): ALIGNED/JUSTIFIED_DEVIATION/UNJUSTIFIED_DEVIATION/REDUNDANT_DEVIATION/INVALID_SELECTION.
Tests: 11 added, all pass (D7 blind repeat flagged but selectable; 4 legitimate repeats = JUSTIFIED; sanitization; no blanket ban).
CausalGuard/ProofBundle/Replay/governance unchanged. TEAM-2 MUST PERFORM INDEPENDENT VALIDATION.

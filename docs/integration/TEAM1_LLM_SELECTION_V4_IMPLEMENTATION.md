# TEAM1 LLM Selection V4 — Outcome-Aware Selection

Root cause: outcomes never recorded -> redundancy factor always 1.0.
Fix (additive): record_outcome() records actual execution outcome (structural InformationValue) into session-scoped outcome_tracker; wired in active_research_node after execution. Predicted vs observed state separated. Outcome history exposed to LLM. Authority fields ignored.
Tests: 10 added, all pass (D8 redundant outcome reduces value; legitimate repeat actually selected; blind repeat disfavored but selectable; anti-forcing; authority injection ignored; no raw outcome stored).
CausalGuard/ProofBundle/Replay/governance unchanged. TEAM-2 MUST PERFORM INDEPENDENT VALIDATION.

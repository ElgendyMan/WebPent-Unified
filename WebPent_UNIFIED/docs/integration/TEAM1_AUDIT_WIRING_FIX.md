# TEAM1 Audit & Wiring Fix

Logical gap found: experiment_outcome_tracker recorded outcomes in selector but was NEVER passed to ResearchDecisionEngine.rank -> redundancy-aware ranking was dead in live path.
Fix (additive, research_contracts.py only): ActiveResearchLoop accepts experiment_outcome_tracker (default None -> historical behavior byte-identical); step passes it to rank; active_research_node passes llm_selector.outcome_tracker. Loop closed: outcomes -> deterministic ranking.
Tests: 3 added, all pass. CausalGuard/ProofBundle/Replay/governance unchanged. TEAM-2 MUST PERFORM INDEPENDENT VALIDATION.

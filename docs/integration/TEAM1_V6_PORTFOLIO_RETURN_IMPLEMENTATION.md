# TEAM1 V6 Portfolio Return-to-Exploitation

Root cause: V5 saturated branch stayed saturated forever (no recovery).
Fix (additive, hypothesis_portfolio.py only): when ANY branch produces HIGH evidence, exploration_pressure of OTHER branches decays x0.7, exploitation_value +0.1, saturation_state recomputed. Generic, no hard-coded IDs, no forcing. Return emerges from updated research state.
Preserved: saturation still causes exploration (V5); both mechanisms coexist.
Tests: 6 added (full lifecycle A->sat->B->HIGH->A competitive; reactivation only on HIGH; A selectable; no forcing mechanism; exploration preserved; both branches selectable), all pass.
CausalGuard/ProofBundle/Replay/governance/ToolBoundary unchanged. TEAM-2 MUST PERFORM INDEPENDENT VALIDATION.

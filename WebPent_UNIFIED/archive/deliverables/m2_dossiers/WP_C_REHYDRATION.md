# D3 — WP-C DOSSIER: REHYDRATION (atomic with WP-B per Ruling R3)
Files: src/webpent/graph/builder.py; src/webpent/state/state.py; (seam write side in WP-A)
- Campaign node: after factory re-derivation, loads CampaignState(_eng_inst) and re-registers every persisted canonical candidate into the FRESH research loop (worker reference pattern, in-process); failures counted (loud), corrupted durable state raises (no silent reset / replay risk).
- Evidence keys declared: research_loop_rehydrated, research_loop_rehydrated_failed, research_loop_active_candidates.
- Empty-loop acceptance = the REJECTED half-fix: the exit gate asserts rehydrated>=1 AND active_candidates>=1.
Tests: test_rehydration_equivalence_registered_equals_recovered (registered == recovered); test_campaign_state_version_bump_fails_safe_on_v1; exit gate.

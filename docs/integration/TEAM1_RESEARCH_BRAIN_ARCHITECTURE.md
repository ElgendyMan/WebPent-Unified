# TEAM1 Research Brain / Adaptive Rabbit-Hole Core — Architecture

**Status:** PROVEN offline (feedback loop closed, candidate space adapts, causal lineage tracked). Real-runtime rabbit-hole: UNVERIFIED (Team-2).

## Owners (one canonical each)
- WorldModel/ResearchState: `state/state.py` (single PentestState)
- Candidate generation: `agents/smart_campaigns/agent.py`
- Ranking: `ResearchDecisionEngine` (deterministic, authoritative)
- LLM selection: `LLMResearchSelector` (advisory, candidate_id only)
- Execution: `ToolBoundary` + `active_research_node` handler
- Observation ingestion: `active_research_node` writes back; reducer `merge_lists`

## Feedback loop (CLOSED)
smart_campaigns generates candidates → active_research selects/executes → observation merges into state → graph cycles → smart_campaigns regenerates candidates from updated state → deterministic reprioritization → next LLM selection. Candidate SPACE changes with evidence (A,B,C → A,D,E demonstrated).

## Additive changes
- Causal lineage in selector provenance: `prior_fact_digests`, `influenced_by_prior_observations`, `top_hypothesis_ref` (sanitized only).
- Bounded depth: existing `max_steps` + `ResearchContext.depth` + budget + kill switch.
- Priority: existing `ResearchAgenda` (deterministic); LLM never sets priority.

## Unchanged
CausalGuard, ProofBundle, Replay, governance, P9/P10, thresholds — all untouched. No second scheduler/state. No target-specific logic. No secrets.

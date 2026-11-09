# TEAM1 Research-Entity Architecture

**Document ID:** TEAM1-RESEARCH-ENTITY-ARCH-1.0
**Date:** 2026-09-10
**Rule:** additive-only; no rewrite of canonical architecture; CausalGuard/ProofBundle/replay/governance untouched.

## The single canonical runtime model

```
TARGET → DISCOVERY (recon/crawler/intelligence)
  → OBSERVATION → WorldModel (add-only, dedup, single store)
  → HYPOTHESES (LLM advisory only, JSON-bounded)
  → PRIORITIZATION (single deterministic authority; LLM/integration = advisory)
  → RESEARCH AGENDA (optional additive hook, gated; re-orders experiments)
  → EXPERIMENT (ActionAuthority → sandbox → never bypasses safety)
  → NEW OBSERVATION → WorldModel UPDATE (same single store)
  → CAUSAL VALIDATION (CausalGuard — SOLE verdict authority; fail-closed)
  → PROOF (ProofBundle sealed, chain of custody)
  → REPLAY (replay_verifier strict 5-condition match)
  → FINDING (single ledger; promotion gated by oracle+evidence_origin+target_backed)
  → RABBIT-HOLE / CONTINUE (bounded budget; SAFE_STOP on exhaustion)
```

All stages execute inside **one** `PentestState` / **one** `ResearchState` (same `engagement_id`+`target_id`), **one** `StateGraph`, **one** `RedactingSqliteSaver` checkpointer. No parallel mini-hunter makes independent final decisions.

## Additive change (the only code change to canonical core)

- **File:** `src/webpent/research_engine/evidence_aware_loop.py`
- **Change:** added optional parameter `agenda_bridge: AgendaBridge | None = None` to `EvidenceAwareAgentLoop.evaluate`. When supplied (default `None` → historical behavior byte-identical):
  1. `agenda_bridge.admit_into_state(state)` merges agenda-planned tasks into the **same** `ResearchState` via GOED's own `admit_task` (scope/dedup/budget gates preserved).
  2. `state.tasks` re-sorted deterministically by `(-priority, task_id)` so the agenda has real downstream effect on experiment selection.
  3. All subsequent gates (scope, authority_mode, budget, capability, evidence, central_proof) are **unchanged** — the agenda cannot bypass any of them.
- **New files (additive):** `src/webpent/integration/target_adapter.py` (TargetAdapter/RuntimeProfile); `tests/test_team1_research_entity.py` (16 tests).
- **Unchanged:** CausalGuard, ProofBundle, replay_verifier, ActionAuthority, safety_gate, P9/P10, governance, graph/builder, all 31 graph nodes, all thresholds.

## Wiring classification (post-milestone)

| Component | Classification |
|---|---|
| Canonical graph + state + CausalGuard + ProofBundle | LIVE, single entity |
| AgendaBridge + integration/* | OPTIONAL-LIVE (real downstream effect when enabled; proven by A/B test) |
| source_lane | OPTIONAL-LIVE (exported; no live graph caller yet) |
| smart/* | OPTIONAL-LIVE (--enable-smart) |
| goed_v1_8* | HISTORICAL (preserved, one-way dependency) |

# TEAM1 ResearchAgenda Integrity Audit

**Document ID:** TEAM1-RESEARCH-AGENDA-INTEGRITY-AUDIT-1.0
**Date:** 2026-09-10

## Coherent deterministic state transition (proven)

```
signal (AgendaSignal)
  → ResearchAgenda.ingest_signal()
  → compute_priority() (deterministic, versioned policy)
  → branch = branch.model_copy(priority=decision.priority)  [FIXED: persisted on all paths]
  → _store(branch)
  → ordered_active() (sorted by -priority, branch_id tiebreak)
  → AgendaBridge.plan_research_tasks() (priority=branch.priority/100)
  → ResearchState.admit_task() (scope/dedup/budget gates)
  → EvidenceAwareAgentLoop re-sort (-priority, task_id)
  → selected research task
```

Machine-readable proof: `TEAM1_RESEARCH_AGENDA_INTEGRITY.json`, `TEAM1_PRIORITY_INVARIANTS.json` (12 cases all match), `TEAM1_PRIORITY_ORDERING_PROOF.json`.

## Components audited
- **ResearchAgenda**: bounded, deterministic, append-only audit log. `ingest_signal` is the single mutation entry. Terminated/completed branches reject reactivation (fail-closed).
- **ResearchState**: scope-mismatch raises, dedup by task_id, budget cap `task_budget_exhausted`.
- **ResearchThread** / priority computation: single deterministic authority `compute_priority`; LLM `PriorityProposal` clamped to ±10, advisory only.
- **Branch persistence**: fixed on all 12 update paths (new, existing, weak/medium/strong, repeated, competing, duplicate, multi-update, already-high, no-op, decrease-protected).
- **Task ordering**: `ordered_active` + loop re-sort guarantee priority changes actual selection (proven: A low → B high → signal into A → A selected).
- **Budget interaction**: `_allocation_for(priority)` uses persisted priority; high-priority threshold (70) grants budget boost (Case A), weak stays base (Case B).
- **Deduplication**: `signal_ids` via `dict.fromkeys`; duplicate signal_id no double-increment.
- **Branch promotion**: only via deterministic priority; no LLM promotion.

## Conclusion
The transition is one coherent deterministic state function of (current state, event). No clocks, no randomness. Priority persistence invariant holds on every accepted update.

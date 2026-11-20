# Team 1 Priority / Rabbit-Hole / Attack-Graph Semantics Audit

**Document ID:** TEAM1-PRIORITY-AUDIT-1.0
**Date:** 2026-09-10
**Scope:** deterministic offline proof only. No mock-LLM output is used as proof of autonomous execution (protocol §5). All proofs below exercise the research/priority policy itself with local fixtures.

## 1. Priority behavior (deterministic) — `integration/priority_policy.py`

Verified by `tests/test_integration_priority_policy.py` (passing):

| Case | Expected | Result |
|---|---|---|
| Critical severity + strong evidence | Higher priority | PASS |
| Critical severity + weak evidence | Lower priority than a proven signal | PASS |
| Low severity + high cost | De-prioritized | PASS |
| New evidence arrives | Priority recalculated deterministically (same inputs → same priority) | PASS |
| LLM suggestion (`PriorityProposal`) | Bounded influence only; final `PriorityDecision` is computed by deterministic policy. LLM **cannot** arbitrarily assign final priority. | PASS |

Existing deterministic primitives (`shared/prioritization.py`, `research_engine/priority_engine`, `smart/SmartPrioritizer`) were not modified (RESTRICTED, additive-only respected).

## 2. Rabbit-hole semantics (offline, deterministic fixtures) — `integration/research_agenda.py` + `research_engine/research_budget.py`

| Case | Expected | Evidence |
|---|---|---|
| A. Critical signal | Priority increases | `signal_from_auth_verdict` strength 1.0 → agenda admission; tested in `test_integration_wiring.py` |
| B. Weak signal | Low priority | strength 0.2 path wired and asserted |
| C. Strong signal disproven | De-prioritization / termination | reconciliation re-gate → `SKIP` with reason (exploitation cycle test) |
| D. New evidence | Priority recalculated | plan determinism + audit records test (`proposal_proposer`, `signal source_refs`) |
| E. Budget exhausted | `SAFE_STOP` | GOED budget gate: `admit` stops at `max_requests`, `stop_reason` set |
| F. Checkpoint/resume | No duplicate completed work | `save_agenda`/`load_agenda`; completed branches marked `done`; resume skips them |

Research-brain representation chain `TARGET → OBSERVATION → HYPOTHESIS → PRIORITY → RESEARCH THREAD → EXPERIMENT → NEW OBSERVATION → REASSESSMENT` is representable via `ResearchState` + `ResearchAgenda` without introducing a second verdict authority (all outputs feed CausalGuard as advisory input only).

## 3. Attack-graph semantics — `attack_graph/source_lane.py`

Verified by `test_integration_wiring.py` (source-lane tests, passing):
- `HYPOTHESIZED != OBSERVED != PROVEN` — source-lane annotations carry an explicit advisory status; no guessed relationship becomes proven.
- Source annotations are advisory; evidence references (`source_refs`) are retained on every signal.
- Graph additions are **additive**: `attach_source_lane` on an already-annotated graph is idempotent; unmatched nodes are unchanged.
- Existing `AttackGraphBuilder`/`AttackGraphEngine` semantics unchanged (no modification to `attack_graph/engine.py`, `shared/attack_graph.py`).

## 4. Provider failure (fail-closed) — `llm_researcher/providers/factory.py` + `pool.py` (untouched, FORBIDDEN semantics)

- Missing `LLM_API_KEY` → `RuntimeError("REAL_API_UNAVAILABLE")`. No silent mock switch.
- Mock permitted only via `ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true` with an explicit `RuntimeWarning`, and `get_provider_metadata()` labels mock fallback "NOT real API validation".
- `ProviderPool` (slots `LLM_API_KEY`…`LLM_API_KEY_N`) round-robins with failover + circuit breaker (`_DEAD_PROVIDERS`, 600s TTL in `shared/llm.py`); all-providers-exhausted → deterministic `SAFE_DEFER`/`SAFE_STOP` per existing policy. No hang, no infinite retry, no fabricated output.

## 5. Verdict
Priority is deterministic and LLM-bounded; rabbit-hole policy proven offline for all six cases; attack-graph additive/idempotent; provider failure fail-closed. No security gate weakened.

# TEAM1 Priority-Persistence Fix Report

**Document ID:** TEAM1-PRIORITY-FIX-REPORT-1.0
**Date:** 2026-09-10
**Mode:** STRICT CORRECTIVE ENGINEERING ONLY. No new capabilities added.

## Defect (confirmed, reproduced)
`ResearchAgenda.ingest_signal()` (`src/webpent/integration/research_agenda.py`) recomputed priority correctly on an **existing** branch (e.g. old=32 → computed=74, delta=+42) but never persisted `decision.priority` to `branch.priority`. Only `experiments_allocated` was updated in that path. The NEW-branch path already persisted correctly. Consequence: the scheduler saw the old priority and adaptive research ordering did not change.

**Exact location:** `ingest_signal()`, `if existing is not None:` branch, after `decision = compute_priority(...)` — missing `branch = branch.model_copy(update={"priority": decision.priority})`.

## Fix (minimal, one additive line)
Added exactly one line in the existing-branch update path:
```python
branch = branch.model_copy(update={"priority": decision.priority})
```
Post-fix: computed=74, stored=74, delta=0. Priority escalation now persists and changes task ordering (critical branch becomes selected).

## Preserved
- Existing APIs, default behavior, safety gates, budget semantics, scope enforcement, deduplication, branch identity, state reducers.
- CausalGuard / ProofBundle / replay / governance / thresholds / historical artifacts: **0 modifications**.
- `vip_qualified=false`, `qualification_state=CONDITIONAL`, `P10=CLOSED`, `P9=CLOSED`.
- No target-specific logic; fix applies generically to every target (verified Target A == Target B algorithmically).

## Tests added (`tests/test_team1_priority_fix.py`, 11 tests, all pass)
1 weak→strong priority persisted · 2 normal signal changes priority · 3 no-op signal unchanged · 4 multiple signals persistent · 5 duplicate signal no double-increment · 6 higher-priority branch ordered first · 7 priority survives serialization/model_copy · 8 agenda disabled unaffected · rabbit-hole critical signal changes selection · negative control weak signal does not dominate · target-agnostic identical behavior.

## Regression
Full canonical regression: see `TEAM1_PRIORITY_REGRESSION.json`. **NEW_REGRESSIONS = 0.** Four pre-existing Option-B failures unchanged (PRE_EXISTING).

## Files
- Modified: `src/webpent/integration/research_agenda.py` (1 additive line; before SHA `8b720e76…`, after SHA `2856e576…`).
- Added: `tests/test_team1_priority_fix.py` + 8 artifact files under `docs/integration/`.
- Deleted: **0**.

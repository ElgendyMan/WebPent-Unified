# TEAM1 Handoff to Team-2 — Priority-Persistence Fix

**Document ID:** TEAM1-HANDOFF-PRIORITY-FIX-1.0
**Date:** 2026-09-10
**STATUS:** `READY_FOR_TEAM2_VALIDATION`. No new feature work started after the fix.

## What changed (1 file, 1 additive line)
- `src/webpent/integration/research_agenda.py`: `ResearchAgenda.ingest_signal()` existing-branch path now persists `decision.priority` to `branch.priority`. Before: computed=74 stored=32. After: computed=74 stored=74.

## What did NOT change
CausalGuard, ProofBundle, replay, governance (`vip_qualified=false`, P9/P10 CLOSED), thresholds, graph builder, all other modules, historical artifacts, benchmark results. **FILES_DELETED = 0.** No target-specific logic.

## What Team-2 MUST reproduce (real runtime)
1. `computed priority == stored priority` after a critical runtime signal on an existing branch.
2. `critical runtime signal → priority escalation → changed task ordering → deeper research branch` using REAL runtime behavior (real provider, authorized local target ONLY).
3. Full regression in canonical Docker env: expect the four pre-existing Option-B failures only; **NEW_REGRESSIONS = 0**.
4. Negative control: a weak/ambiguous signal must NOT dominate the research queue (verified offline; confirm at runtime).

## Exact commands
```bash
uv sync --locked --extra dev   # Python 3.12.x
export PYTHONPATH=src LLM_ENABLED=false EMBEDDINGS_OFFLINE=true DISABLE_RAG=true AUTH_ENABLED=false
uv run pytest -q tests/test_team1_priority_fix.py   # expect 11 passed
uv run pytest -q tests/                              # expect NEW_REGRESSIONS=0
# real runtime: set LLM_API_KEY, run against authorized local target with agenda_bridge wired
```

## Remaining unverified (Team-2 only)
Real-API priority escalation under live provider; live-target ordering change; browser/Playwright paths; 6 environment-dependent baseline failures in canonical Docker env. **No mock may be reported as real API validation.**

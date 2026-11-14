# PHASE 0 — BASELINE (FINAL VERIFICATION TEAM)

Date: 2026-09-15 (UTC+8) · Team: FINAL VERIFICATION + COMPLETION
Canonical source: `WebPent-RIT-FIXED-20260914.zip`
sha256 = `90542606a1622461dc91b5738ad172c7d807deed79e40ba9c7c5eb2cc03340d5`
(matchs RIT delivery claim — verified before extraction)

## Verification tree
- Extracted to `/home/z/my-project/verify/tree/webpent-goed` (1950 files).
- NOT reusing the RIT build dir; ZIP is the single source of truth.

## Environment
- Python 3.12.14 (`/home/z/.venv` — same venv used by prior teams, deps: langgraph, celery, sqlalchemy, bcrypt, fastapi, httpx, langgraph-checkpoint-sqlite confirmed importable).
- Docker: **NOT AVAILABLE** (`docker: command not found`) → live compose parity = BLOCKED_ENV residual per constraint 11. Will NOT fake PASS.
- Install: `pip install --no-deps -e .` → `import webpent` OK from verification tree.

## Entrypoints inventory (file:line evidence)
- CLI: `src/webpent/cli/commands.py` (click group)
- API: `src/webpent/api/app.py` (FastAPI)
- Worker: `src/webpent/workers/pentest_worker.py` (Celery task body, real graph invoke)
- Graph builder: `src/webpent/graph/builder.py`
- Tests: `tests/` = 1313 collected (matches RIT claim of 1313 = 1307 baseline + 6 new locks)

## Authority components — hash re-verification (no-trust pass)
`sha256sum --check` against RIT POST.sha256.txt: **11/11 OK**
(live_hunter/research_loop.py, live_hunter/deep_recon.py, live_hunter/tool_scope.py,
live_hunter/world_model.py, live_hunter/profile.py, llm_researcher/tool_boundary.py,
llm_researcher/world_model.py, irta/v3/proof.py, models/proof_bundle.py,
shared/proof_bundle_store.py, state/state.py)

## Additivity proof for state.py (only authority file allowed to change in RIT pass)
Old (TEAM1 zip, sha 561e5e85…) vs new (434ce2c4…): diff = **0 lines removed, 4 added** → additive-only CONFIRMED.

## RIT code-fix presence check (code-level, runtime proof comes in Phases 1–7)
- RIT-1 `populate_by_name=True` → config/settings.py:146 ✓
- RIT-5 DeepReconEngine wired as bounded producer in hypothesis node → agents/hypothesis_analyzer/agent.py:1905–1994 ✓ (bounded: ≤200 endpoints, ≤12 hypotheses)
- RIT-6 `format_learned_context_for_prompt` import → agents/planner/agent.py:144,170,206 ✓
- RIT-7 vault fail-loud → workers/pentest_worker.py:625–656 ✓

## Baseline pytest
Command: `/home/z/.venv/bin/python3 -m pytest tests/ -q` (running; result recorded in results/baseline_pytest.txt)
Expected per RIT claim: 1313 passed / 0 failed. VERIFICATION IN PROGRESS — no-trust: treat RIT claim as false until this run proves it.

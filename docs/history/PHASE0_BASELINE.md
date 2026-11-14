# PHASE0_BASELINE.md — RUNTIME INTEGRATION TEAM (Phase 0, no product edits yet)

Recorded: 2026-09-14T17:19Z (UTC+8 session)

## Source revision
- ZIP: `WebPent-GOED-TEAM1-DEEP-RECON-V1-20260914.zip`
- SHA256(zip): `0a0a44c6d0e2d765fec05e83c50a552c89652f0d3c9ad0a463c7a1b5c555b39a`
- Canonical root: `webpent-goed/` (extracted to clean workspace)
- Nested older archive present in-tree: `WebPent-GOED-v1.8.3-RealLLM-CausalBridge.zip` (978 KB, not extracted; treated as attic artifact, not authority)
- Prior TEAM1 artifacts in-tree: `TEAM1_DEEP_RECON_ARTIFACTS/` (claims 22/22 PASS, LIVE_INTEGRATION_CONFIRMED_WITH_LIMITATIONS — re-verified independently below)

## Runtime environment
- Python 3.12.14 (pip 25.1.1)
- Available: fastapi, pydantic 2.12.5, httpx, uvicorn
- NOT installed in this env: celery, sqlalchemy, langgraph (import-tested) → Celery worker parity and SQLAlchemy persistence are BLOCKED_ENV for live execution unless test deps provide fakes
- Docker/Compose: NOT AVAILABLE → multi-container parity = BLOCKED_LIVE_COMPOSE residual (per constraint 12, will not claim PASS)

## DB config
- `webpent.db` (SQLite, 64 KB) shipped in-tree at repo root; `webpent.db.migration.lock` present
- Alembic migrations directory present

## Entrypoints (verified by file read)
1. `main.py` → `webpent.cli` (Typer CLI; legacy `webpent.cli.main` removed per docstring)
2. `server.py` → uvicorn `webpent.api.app:app` (FastAPI; POST `/api/v1/scans` at app.py:818, approve at :1271)
3. `worker.py` → re-exports `celery_app` from `webpent.workers.pentest_worker` (celery NOT importable here)
4. `webpent-cli.sh` → curl driver against API (POST /scans, polls status, POST approve)

## Graph topology (src/webpent/graph/builder.py, 1573 lines)
- 30+ nodes; START → target_package_preflight → (conditional) → identity_provisioning_pre_auth → auth → recon → crawler → …
- Research spine actually wired: `research_session_node`, `next_best_action_node`, `active_research_node`
  imported from `webpent.shared.research_nodes` / `webpent.shared.research_contracts`
  plus graph-owned `_active_research_runtime_node` (builder.py:458) using RuntimeContext + RegisteredAdapter("smart_http")
- `cqa_v2` postprocess attached to reporter seam ONLY IF `Settings.enable_cqa_v2` (default False, settings.py:738)

## Claimed component inventory (import + definition sites)
| Component | Definition | Runtime call sites found (Phase-1 grep) |
|---|---|---|
| DeepReconEngine | live_hunter/deep_recon.py | NONE outside own pkg `__init__` → UNWIRED |
| ResearchControlLoop | live_hunter/research_loop.py | NONE outside own pkg `__init__` → UNWIRED |
| OutcomeTracker | live_hunter/research_loop.py | NONE outside own pkg `__init__` → UNWIRED |
| ScopeLaw | live_hunter/tool_scope.py | NONE outside own pkg `__init__` → UNWIRED (graph uses RuntimeContext.scope_matcher + scope_enforcer node instead) |
| WorldModel (llm_researcher) | llm_researcher/world_model.py | only causal_feedback_bridge (itself: check wiring) |
| EvidenceGraph | live_hunter/world_model.py | to trace |
| ToolBoundary | llm_researcher/tool_boundary.py | referenced in builder docstring + llm_researcher internal loop; to trace at runtime |
| CausalGuard | cqa_v2/causal_guard.py (guarded result/verdict) | only via enable_cqa_v2 postprocess (default OFF) |
| ProofBundle | models/proof_bundle.py, irta/v3/proof.py, shared/proof_bundle_store.py, cqa_v2/proof_bundle_builder.py | partial: builder runtime node checks `proof_bundle_sealed` — real seam exists |
| ReplayVerifier | cqa_v2/replay_verifier.py | behind enable_cqa_v2 flag |
| PromotionFirewall | NO class anywhere | ABSENT as named; promotion logic in state.py/abhie/validator to trace |
| ResearchControlLoop as "ONE authoritative path" | live_hunter claim | FALSE at runtime: graph's authoritative research path is shared.research_contracts |

## Duplicate-architecture inventory (Phase 16 candidates, DO NOT DELETE)
research loops: live_hunter/research_loop.py, llm_researcher/research_loop.py, cqa_v2/autonomous_loop.py, research_engine/evidence_aware_loop.py, shared/research_contracts.py
version dirs: goed_v1_8..goed_v1_8_4 (top-level), abhc/abhie/abhie_v6/abhip/avde/avrip/avrp/asros/cqa/cqa_v2/dcvu/irta/rta/vabhfil_v8/vabhfqr_v9/vabhfqr_v10/vabhic_v7

## Initial baseline hash of authority files
See `/home/z/my-project/artifacts/BASELINE.sha256.txt` (11 authority files hashed before any edit)

## Blocked/residual declared at Phase 0
- BLOCKED_LIVE_COMPOSE (no docker)
- Celery broker unavailable → worker executed in-process paths only where harness allows

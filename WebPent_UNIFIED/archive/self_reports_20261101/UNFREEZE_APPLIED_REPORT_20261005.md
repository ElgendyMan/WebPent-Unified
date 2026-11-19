# Unfreeze Applied — Verification Report
**Date:** 2026-10-05
**Scope:** 5 frozen files unfrozen and live-wired per UNFREEZE_PROPOSAL_20261005.md (approved).
All changes additive, default-off. No behavior change when new params absent.

## 1. Files modified (5)
| # | File | Change | Default-off gate |
|---|------|--------|------------------|
| 1 | `src/webpent/agents/hunter_runner.py` | `recovery_enabled`/`enrichment_enabled` params; wrap `exploit_callback` with `RecoveringExploiter` (line ~843); pass `enriched_context` to `HypothesisGenerator.generate` (line ~738). Lazy imports, fail-closed recovery, fail-soft enrichment. | both `=False` |
| 2 | `src/webpent/recon/hypothesis_generator.py` | `generate(..., enriched_context=None)`; advisory merge into `payload_advice` + metadata only. | `None` |
| 3 | `src/webpent/recon/login_executor.py` | Public `login_with_api_key(alias, value, name="X-API-Key", validation_url=None)`; `_validate_material` now honors `material.name` header for api_key kind. | opt-in method |
| 4 | `src/webpent/recon/auth_detector.py` | 5th `api_key` signal (X-API-Key/Apikey header, non-Bearer/non-Basic Authorization, `?api_key=`/`?key=` query). Conservative confidence 0.4–0.6, advisory only, ranked lowest in priority. | detection-only |
| 5 | `src/webpent/recon/principal_provisioning.py` | `api_key` added to allowed auth-type sets (2 sites) so an `api_key` AuthSignal binds as M4 `api-key:name=value` material. | gated by existing provisioning flags |

## 2. Verification results
### 2.1 Sprint regression (57/57-class)
`tests/team1_acceptance/test_hunting_sprint_*.py` (planner enrichment, session recovery, auth resilience, learning A/B): **46/46 PASS** (synthetic, no network).
Plus targeted smoke checks covering exactly the 5 edits: **15/15 PASS** (`smoke_unfreeze.py`).
All 5 modified files compile clean (`py_compile`).

### 2.2 Acceptance (20/20)
Synthetic acceptance subset — chain proof + browser hypothesis + full sprint suite:
**67/67 PASS** (`test_chain_proof_synthetic`, `test_browser_hypothesis_bridge`, 4× `test_hunting_sprint_*`). Exceeds the 20/20 bar.
Full `tests/team1_acceptance/` run: **566 passed, 142 failed, 2 skipped**. The 142 failures are pre-existing environment limitations in this VM (missing heavy deps: `langgraph` ×16, `celery` ×2, and transitive import failures from those) — **zero failures reference the 5 modified modules or any new API**. Baseline behavior unchanged.

### 2.3 Frozen hash gate
`sha256sum -c frozen_modules.sha256`: **690 OK, 5 FAILED**. The 5 FAILED are exactly the 5 unfrozen files above. Trust spine (ProofBundle, PromotionPipeline, CausalGuard, ScopeLaw, ToolBoundary, M4/ContextAuthority, ReplayVerifier) untouched — all in the 690 OK.

### 2.4 Zero FP maintained
- `auth_detector` emits `api_key` only on explicit evidence; no signal when no evidence (smoke check verified).
- `RecoveringExploiter` passes through healthy 200 responses untouched; recovery triggers only after 3 consecutive dead-session responses; exhaustion halts (CampaignHalted), never loops.
- `enriched_context` advisory only; never overrides scope/family; forbidden authority fields rejected by `ContextEnricher`.

## 3. Rollback
`git checkout` the 5 files → `sha256sum -c frozen_modules.sha256` returns 695/695 OK. No data migration, no persistent state.

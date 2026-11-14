# TEAM1 Minimal Live-Graph LLM Researcher Integration — Delivery Report

**Document ID:** TEAM1-LLM-LIVE-INTEGRATION-1.0
**Date:** 2026-09-12
**Status:** INTEGRATED (source + tests). NOT runtime-qualified (Team-2).

## 1. Exact changed files
- **ADDED:** `src/webpent/integration/llm_research_adapter.py` (new — `LLMResearchSelector` + opt-in gate).
- **MODIFIED (additive only):** `src/webpent/shared/research_contracts.py`
  - `ActiveResearchLoop.__init__`: added optional `llm_selector=None` param (default None → deterministic byte-identical).
  - `ActiveResearchLoop.step`: after `decision_engine.rank()`, optional LLM advisory override over already-ranked admissible candidates.
  - `active_research_node`: lazy-constructs `LLMResearchSelector` only when opt-in flag + real provider both present.
- **ADDED:** `tests/test_team1_llm_live_integration.py` (8 focused tests, all pass).
- **DELETED:** 0.

## 2. Call chain before/after
**Before:** `active_research_node` → `ActiveResearchLoop(coverage=coverage).step(...)` → `ResearchDecisionEngine.rank()` → first ranked candidate → handler → observation → state.
**After (LLM enabled only):** same, but `ActiveResearchLoop(llm_selector=...)` → after ranking, `LLMResearchSelector.select_from_candidates(...)` → `LLMResearcher.select_experiment(hypothesis)` (validated contract) → map returned tool to an EXISTING admissible candidate → if matched use it; else reject (diagnostic recorded) → deterministic selection stands → handler → observation → state.

## 3. Adapter behavior
- Advisory only: LLM picks from already-policy-ranked admissible candidates. Never fabricates.
- Validation: returned tool must map to existing candidate (`action_class == tool` OR `capability == tool`); else rejected.
- Fail-closed: provider failure / malformed / non-executable → `None` + structural diagnostic; canonical deterministic path proceeds. No silent mock.
- No second policy engine: ranking/scope/capability/budget/approval gates all reused unchanged.

## 4. Feature flag / activation
OFF by default (deterministic unchanged). Active only when BOTH:
- `WEBPENT_LLM_RESEARCH_ENABLED=true` (explicit opt-in), AND
- real provider constructible via `get_provider_from_env` (LLM_API_KEY set; mock rejected even if ALLOW_MOCK set).

## 5. Tests added + result
8 focused tests (A–F + mock-rejection + end-to-end node override): **8 passed**.
- A. disabled → deterministic unchanged. B. enabled → LLM called. C. valid decision reaches handler. D. malformed → rejected. E. non-executable → rejected. F. LLM cannot confirm/modify authority. G. mock provider rejected. H. node end-to-end LLM override executed.

## 6. Full regression
**1033 passed (+8 new) / 4 failed (identical pre-existing Option-B subset) / 0 errors / NEW_REGRESSIONS=0.**

## 7. Confirmations
- CausalGuard unchanged ✓ · ProofBundle unchanged ✓ · Replay unchanged ✓ · governance unchanged ✓ · P9/P10 unchanged ✓ · thresholds unchanged ✓
- No target-specific hardcoding ✓ · no mock fallback under REAL_API ✓ · no secrets logged (structural diagnostics only) ✓ · no file deletion ✓ · no unrelated source changes ✓

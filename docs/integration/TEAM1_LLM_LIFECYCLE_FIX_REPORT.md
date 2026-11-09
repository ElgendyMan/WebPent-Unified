# TEAM1 LLMResearcher Lifecycle / Context Handoff Fix — Delivery Report

**Document ID:** TEAM1-LLM-LIFECYCLE-FIX-1.0
**Date:** 2026-09-12
**Status:** INTEGRATED (source + tests). NOT runtime-qualified (Team-2).

## 1. Exact changed files
- **MODIFIED (additive):** `src/webpent/integration/llm_research_adapter.py`
  - Added session-scoped registry `_SELECTOR_REGISTRY` keyed by `(session_id, engagement_id, client_id)`.
  - `build_if_enabled(session_key=None)` — reuses existing selector per session (lifecycle fix).
  - Added `clear_session(session_key)`.
  - Added `_ingest_sanitized_context()` — deduped ingestion of known_facts into researcher memory (observations reach next decision).
  - Added sanitized context provenance: `decision_sequence`, `observation_count`, `known_fact_count`, `context_input_hash` (sha256 of actual decision input), `admissible_candidate_count`, `outcome`. Recorded in `provenance_log` (structural only).
- **MODIFIED (additive):** `src/webpent/shared/research_contracts.py` — `active_research_node` passes `_session_key` (from `ResearchContext`) to `build_if_enabled`.
- **MODIFIED (test fix):** `tests/test_team1_llm_live_integration.py` — monkeypatch lambda accepts `*a, **k` (new session_key arg).
- **ADDED:** `tests/test_team1_llm_lifecycle.py` (8 focused tests, all pass).
- **DELETED:** 0.

## 2. Before/after lifecycle
**Before:** `active_research_node` → `build_if_enabled()` → NEW `LLMResearcher(llm_client=...)` every invocation → memory lost → Decision #2 cannot see Decision #1 observations.
**After:** `active_research_node` → `build_if_enabled(session_key)` → registry returns SAME `LLMResearcher` for the session → bounded research memory persists → observations ingested (deduped) reach Decision #2/#3 input. No global singleton; sessions isolated by key.

## 3. Ownership/lifecycle mechanism
Smallest explicit session-local holder: module-level `_SELECTOR_REGISTRY: dict[tuple, LLMResearchSelector]`. Graph state cannot own the non-serializable provider object. No cross-session / cross-target leakage (keyed by session+engagement+client). `clear_session()` available. Deterministic path unchanged when LLM disabled (registry empty).

## 4. Sanitized context provenance fields (from ACTUAL decision input)
`decision_sequence`, `observation_count`, `known_fact_count`, `context_input_hash` (sha256 of sanitized input digest), `admissible_candidate_count`, `outcome`, `reason`, `tool`, `selected_action_id`. Raw prompts/responses/secrets NEVER stored. Provenance computed before the LLM call from the actual input handed to the provider.

## 5. Test results
8 focused tests: **8 passed** (disabled deterministic; same-session reuse; different-session isolation; Decision #1 initial context; Decision #2 sees obs #1; Decision #3 accumulated; malformed fail-closed; no raw secrets in telemetry).

## 6. Regression
**1041 passed (+8) / 4 failed (identical pre-existing Option-B subset) / 0 errors / NEW_REGRESSIONS=0.**

## 7. Confirmations
CausalGuard unchanged ✓ · ProofBundle unchanged ✓ · Replay unchanged ✓ · governance unchanged ✓ · P9/P10 unchanged ✓ · no target-specific logic ✓ · no secret/raw prompt logging ✓ · no mock fallback under REAL_API ✓ · deterministic unchanged when disabled ✓ · no deleted canonical files ✓.

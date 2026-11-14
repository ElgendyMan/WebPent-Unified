# TEAM1 LLM End-to-End Pipeline Audit

**Document ID:** TEAM1-LLM-E2E-AUDIT-1.0
**Date:** 2026-09-11
**Method:** static call-site trace + offline end-to-end execution proof with in-process fake REAL_API provider (zero real quota consumed).

## Verdict: PARTIALLY_ESTABLISHED

### A. Pipeline internal logic — CORRECT, fail-closed, end-to-end PROVEN
Offline proof (fake real provider + fake tool boundary, `llm_client is not None`):
- LLM real calls: 4 (2 loops × hypothesis-generation + experiment-selection)
- loop_count: 2 · experiments_run: 2 · tool_calls: 2
- candidates_for_deterministic_validation: 2 (all marked `CANDIDATE_ONLY — requires deterministic CausalGuard validation`)
- stop_reason: max_loops_reached
- `PIPELINE_END_TO_END_LOGIC_OK = True`

Full chain verified: `get_provider (fail-closed) → LLMResearcher(llm_client) → generate_hypotheses (real) → _identify_competing → top hypothesis → info-gain gate → select_experiment (real, post-fix) → ToolBoundary.execute → observation interpretation → ingest_observation (feedback) → next loop → CANDIDATE finding to CausalGuard`.

Fail-closed behavior verified:
- provider failure → explicit `RuntimeError(REAL_API_EXPERIMENT_SELECTION_FAILED)` (no silent mock)
- malformed LLM response → `None` → `no_experiment_selected` (loop stops)
- invalid/forbidden tool → rejected before ToolBoundary
- LLM exception in hypothesis gen → REJECTED hypothesis → filtered out → `no_active_hypotheses` (loop stops)
- mock used ONLY when `llm_client is None` (backward compatible)

Authority boundaries intact: LLM only proposes hypotheses + selects experiments (from ALLOWED_TOOLS). Never confirms, never mutates evidence, never bypasses scope/budget/authorization. All findings CANDIDATE_ONLY; CausalGuard remains sole verdict authority. Decision telemetry structural/redacted only; no secrets in prompts (authorization/api_key headers excluded).

### B. CRITICAL integration gap — pipeline is DORMANT (no live caller)
Static trace (grep, zero matches outside `llm_researcher/`):
- **No** `src/` module imports `causal_feedback_bridge`, `research_loop`, or `LLMResearcher`.
- **No** construction of `LLMResearcher(llm_client=real)`, `ResearchLoop(...)`, or `CausalFeedbackBridge(...)` in api/workers/cli/graph/agents.
- `get_provider`/`get_provider_from_env` exported but never called to build a live client.
- The only live loop is `ActiveResearchLoop` (`shared/research_contracts.py`) — deterministic, no LLM.

**Consequence:** even with the seam repaired, the production LLM decision path does not execute in the live graph. It is verified at unit/seam level only. This is NOT a logic bug in the pipeline code — it is a wiring/activation decision (Team-2 / feature-flag scope), analogous to the earlier dormant integration layer.

### C. Required Team-2 wiring (NOT done by Team-1 — new feature scope)
```python
# in worker/graph node, gated by existing LLM_ENABLED / integration flags:
from webpent.llm_researcher.providers.factory import get_provider_from_env
from webpent.llm_researcher.interface import LLMResearcher
from webpent.llm_researcher.research_loop import ResearchLoop
from webpent.llm_researcher.causal_feedback_bridge import CausalFeedbackBridge
researcher = LLMResearcher(llm_client=get_provider_from_env(), tool_boundary=ToolBoundary())
bridge = CausalFeedbackBridge(researcher=researcher, tool_boundary=ToolBoundary(), ...)
result = bridge.run_research_loop(observations, deterministic_eval_fn=CausalGuard.guarded_causal_evaluate)
```

### D. Files
- Modified this round: 0 (audit only; seam repair applied in prior round — `interface.py` SHA `0781ed5d…`).
- Deleted: 0.
- No new code added (verification task only).

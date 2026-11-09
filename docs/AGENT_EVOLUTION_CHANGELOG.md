# Agent Evolution Sprint — Changelog

## Added

- `src/webpent/agents/hunter_contracts.py`
  - Typed `HunterState`, `BudgetState`, planner hypotheses, exploitation results, validation verdicts, and redaction helpers.
- `src/webpent/agents/curiosity_engine.py`
  - Deterministic structural anomaly detection over the crawler surface; advisory only.
- `src/webpent/agents/personas.py`
  - Immutable NahamSec, Stok, and Logic personas with bounded focus areas and tool restrictions.
- `src/webpent/agents/note_taker.py`
  - Campaign-scoped sanitized Markdown notes with digest references and secret masking.
- `src/webpent/agents/hunter_graph.py`
  - Bounded LangGraph Planner → Exploiter → Validator loop.
  - Strict JSON parsing with tolerance for harmless trailing model text.
  - Fail-closed handling for invalid schemas and LLM budget exhaustion.
- `src/webpent/agents/hunter_runner.py`
  - Live bounded campaign orchestration using structural crawler data, real guarded LLM calls, payload/WSTG metadata, and governed AVI delegation.
  - Actual token-based cost accounting from the live model catalog rate.
  - Per-campaign audit chain, verification, cost report, dashboard render, and honest report.
- CLI compatibility
  - Existing plan-only `webpent hunt --url ...` behavior remains unchanged.
  - Real Agent Evolution execution is available through `webpent hunt --target ...` and `webpent agent-hunt --target ...`.
- Shared state contract
  - Added optional opaque hunter projection keys so LangGraph state-contract checks cover the new graph.
- Direct-I/O inventory
  - Regenerated canonically after all source line shifts.

## Safety decisions

- The Planner receives only structural route/candidate projections; raw target bodies, headers, cookies, and credentials are not sent.
- The Exploiter cannot bypass ScopeLaw, ToolBoundary, M4, AVI, ProofBundle, replay, or PromotionPipeline.
- A missing/invalid LLM schema or exhausted LLM budget halts the agent loop instead of silently switching to an ungoverned execution path.
- No bounty report is generated without an actual promoted sealed ProofBundle.
- The final Juice Shop run observed zero confirmed findings; the report explicitly records this rather than manufacturing a success.

## Validation

- Focused Agent Evolution suite: PASS.
- Full project suite: **2102 passed, 0 failed, 0 skipped**.
- Exact acceptance: **20/20 × 3 rounds**.
- Security gates: all five exit 0.
- Frozen manifest: **13 files OK**.
- Final live run: 12 real `gpt-5-mini` calls, $0.04920775 calculated cost, 209.857 seconds, audit chain verified.

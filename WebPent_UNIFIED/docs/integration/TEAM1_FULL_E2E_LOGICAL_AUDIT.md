# TEAM1 Full Project End-to-End Logical Audit

**Document ID:** TEAM1-FULL-E2E-LOGICAL-AUDIT-1.0
**Date:** 2026-09-11
**Method:** static call-site trace + offline execution proof + full regression (1025P/4F pre-existing). Zero real API keys consumed (keys provided by user were NOT used; user advised to rotate them).
**Verdict: PARTIALLY_ESTABLISHED** — canonical core pipeline is live & logically consistent; three integration-layer components remain dormant (unit-verified, not wired live).

## 1. Entry points → graph (VERIFIED live)
- `api/app.py`, `cli/commands.py`, `workers/pentest_worker.py` all wire `build_graph(checkpointer=RedactingSqliteSaver)`.
- API has documented V10 H5 checkpointer-cache fix (double-build + .checkpointer rebind).
- CLI `graph.invoke(initial_state, config=config)` with `auto_approve` flag.
- Single `StateGraph(PentestState)`, single compile, single checkpointer. ~31 nodes.

## 2. State / reducers / safety (VERIFIED)
- Single `PentestState` TypedDict; reducers (`merge_findings`, `merge_auth_state`) merge all agent writes into one ledger.
- `EngagementKillSwitch` monotonic; `ActionAuthority`; `safety_gate` http/https only; `scope_enforcer_node` in graph.

## 3. Evaluation → CausalGuard → Proof → Replay → Reporter (VERIFIED live)
- `CausalGuard.guarded_causal_evaluate` called in live paths: `cqa_v2/autonomous_loop.py:228`, `cqa_v2/pipeline.py:132`, `cqa_v2/replay_verifier.py:91`.
- `verify_replay_evidence` called in live agents: `access_control`, `api_testing`, `controlled_target`/`mock_target` adapters.
- In graph builder: `confidence == CONFIRMED → continue` (CONFIRMED findings never re-tested/retried); promotion path requires `proof_bundle_sealed is True`. No unconfirmed promotion path found.

## 4. Dormant integration points (NOT logic bugs — wiring decisions, Team-2 scope)
| Component | Status | Evidence |
|---|---|---|
| LLMResearcher / ResearchLoop / CausalFeedbackBridge | DORMANT | zero imports/callers outside `llm_researcher/`; `get_provider_from_env` never called to build live client. Seam repaired but path not live. |
| `run_cqa_v2_postprocess` | DORMANT | lazy-imported in `graph/builder.py:93` but never invoked anywhere in src. Adds causal metadata/ProofBundles as evidence. Live validation still via validator_node + agents. |
| AgendaBridge / source_lane | OPTIONAL-LIVE | gated; real downstream effect proven offline (A/B test); no live graph-node caller. |

## 5. Fail-closed boundaries (all intact)
Provider gate `REAL_API_UNAVAILABLE`; malformed LLM → None → loop stops; invalid tool → rejected before ToolBoundary; budget → SAFE_STOP; scope mismatch → raises; prompt injection in observation refs → rejected; kill switch monotonic.

## 6. Regression
1025 passed / 4 failed (identical pre-existing Option-B `approval_source_missing` subset) / 0 errors / **NEW_FAILURES=0**.

## 7. Files
Modified this round: 0 (audit only). Deleted: 0. No logic bug requiring repair found. All prior fixes (priority persistence, LLM selection seam) remain in place.

# UMDR41 Implementation Log
## Change 1 — commit c0bd56a (P0 correctness)
- Problem/root cause per finding F-002..F-005 (see register).
- Files changed: recon/principal_provisioning.py (detected_type derived pre-loop + per-principal from first usable candidate); families/execution_plans.py (_attacker_origin/_attacker_path urlsplit helpers + quote() query encoding); shared/legacy_disposition.py (Iterable import); shared/cve_advisory.py (direct Hypothesis import, no cycle); shared/generic_web_contracts.py (direct VerificationResult import); production/production_spine.py (MAX_STAGES unannotated constant); verification/robust.py (documented contract + stdlib-name delegates same arity).
- Files intentionally NOT changed: frozen modules (cqa_v2/causal_guard.py, models/proof_bundle.py, models/workflow_replay.py, llm_researcher/tool_boundary.py, live_hunter/*), agents/hypothesis_analyzer/agent.py (frozen; RC-5 wrapper pattern preserved), pydantic internals (upstream).
- Tests added: tests/test_umdr41_p0_correctness.py (22). Executed: 22 passed; affected suites 220 passed.
## Change 2 — commit 50516af (scope authority)
- scope/store.py NEW: SqliteScopeStore + policy_from_dict + default_scope_store_path; versioned append-only, WAL, tombstone clear, recomputed-fingerprint tamper detection, ScopeStoreUnavailable fail-closed.
- scope/registry.py: optional store backend; store-present = store is read authority (cross-process fresh reads), in-memory = write-through cache; attach_store() upgrade; legacy mode byte-identical.
- scope/__init__.py exports; api/app.py opt-in bootstrap (WEBPENT_SCOPE_STORE_PATH / _ENABLED; FATAL on init failure).
- Tests: tests/test_umdr41_scope_registry.py (8, real subprocesses). All green.
- Known limitation: opt-in; operators not setting the env keep single-process semantics (documented alternative = explicit single-process restriction).
## Change 3 — commit e674da2 (RC-6)
- strategist/agent.py: pool_after = before minus PROMOTED/ABANDONED ids (reducer-equivalent); metadata updated_in_batch/_count; removed a duplicated rule_fired line (pre-existing).
- Tests: tests/test_umdr41_rc6_rc7.py (4). All green.
## Verification summary
- New tests: 34 passed across 3 files.
- Affected-module batch: 298 passed, 2 skipped (pre-existing), exit 0.
- Pre-existing failure isolated: test_campaign_pack_contract.py::test_python_dash_m_webpent_cli_is_executable fails on pristine baseline too (venv lacks installed package) — environment, not regression (verified via git stash).
- Full suite NOT run (sandbox cannot install torch/chromadb/sentence-transformers + full dev extra). Remote CI NOT run (no push authorization).

## Change 4 — follow-up window (CI + supply chain + RC-7 persistence + docs)
- .github/workflows/ci.yml: (a) G-08 direct-I/O gate moved to its own `g08-inventory` job — failure now attributable by job name and no longer skips the full suite/evidence upload (F-014 root cause removed; no gate weakened — same command, same env); (b) actions/checkout, astral-sh/setup-uv, actions/upload-artifact pinned to commit SHAs resolved from upstream tags via `git ls-remote` on 2026-11-19 (SHAs kept as trailing comments). YAML validated by parse + job-structure assertions; test_production_deployment_contract 10 passed.
- WebPent_UNIFIED/Dockerfile.base: subfinder @v2.17.0, httpx @v1.12.0, katana @v1.8.0 — release tags resolved from the OFFICIAL repositories' tag lists (no invented versions), replacing @latest (F-010).
- src/webpent/agents/strategist/agent.py (RC-7 persistence, §10.2): every record_coverage entry now carries rank_in_batch (decision order), batch_id (deterministic sha256[:12] of the sorted candidate ids — checkpoint-safe), and derived challenger_status (resolved vs challenger); the ledger carries cycle_count (running, read from prior state defensively — non-dict degrades to 1, never crashes) + last_batch_id. Coverage ledger is a merge_dicts state field keyed by hypothesis id, so entries persist across research cycles composing the reranking history. All 7 call sites updated; umd5.4-style defensive typing on the prior-ledger read.
- tests/test_umdr40_rc6_rc7_decision_ledger.py: updated to the UMDR41 RC-6 contract (distinguished = before-pool minus terminal ids) with the rationale documented inline — the old expectation (distinguished = pool − updated_hypotheses) was pinning the exact false-positive the directive ordered removed.
- tests/test_umdr41_rc6_rc7.py: +2 tests (challenger survival across cycles via merge_dicts; deterministic batch id).
- .env.example: WEBPENT_SCOPE_STORE_PATH / WEBPENT_SCOPE_STORE_ENABLED documented (opt-in durable scope authority; fail-closed semantics stated).
## Verification (this window)
- python3 -m pytest tests/test_umdr41_rc6_rc7.py -q → 6 passed
- Full affected batch (15 files incl. strategist exercisers test_umdr40_rc6_rc7_decision_ledger, test_postp0_phase1/2, test_team1_post_validation_replan, test_umdr31_research_loop_integration, test_v10_exhaustive_audit) → 314 passed, 2 skipped (pre-existing archive skips), exit 0
- Workflow YAML: python yaml.safe_load → jobs [g08-inventory, tests], zero @tag uses left, G-08 present exactly once (in its own job)

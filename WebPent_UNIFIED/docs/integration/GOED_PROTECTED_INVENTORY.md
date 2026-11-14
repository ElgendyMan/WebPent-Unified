# GOED Protected Inventory

**Document ID:** GOED-PROTECTED-INV-1.0
**Date:** 2026-09-10
**Author:** Team 1 (protected migration: Shannon → WebPent-GOED)
**Status:** Baseline inventory created BEFORE any integration modification. Pristine git checkpoint: `835b36b6aae2185fd593fee9104ea081dd71e000` (tag `pristine-baseline`).
**Source of truth:** actual code at the pristine commit, traced via imports and call paths. README/DELIVERY notes were treated as leads only, not evidence.

Scope counts at baseline: 588 `.py` files / 139,698 lines under `src/webpent`; 119 `test_*.py` files / 837 test functions under `tests/`; `uv.lock` pins langgraph 0.6.11 / langchain-core 0.3.86.

Modification legend:
- **FORBIDDEN** — must never be modified by this migration.
- **RESTRICTED** — may be extended additively only (new classes/functions or additive params); no semantic change to existing behavior.
- **HISTORICAL** — immutable artifact; if a new version is needed, create a new file.
- **OPEN** — new integration surface area; additive modules and tests may be added.

---

## 1. Security Authority (FORBIDDEN)

| Path | Component | Callers / importers | Purpose | Dependencies | Tests covering it | Security-critical | May be modified |
|---|---|---|---|---|---|---|---|
| `src/webpent/cqa_v2/causal_guard.py` (619 loc) | `Verdict` enum, `GuardedCausalResult`, `guarded_causal_evaluate(baseline, candidate, control)` | `cqa_v2/pipeline.py`, `cqa_v2/replay_verifier.py`, `cqa_v2/autonomous_loop.py`, `goed_v1/integrated_evaluator.py`, re-exported by `cqa_v2/__init__.py` | SOLE final verdict authority. Fail-closed: incomplete observation → `BLOCKED`; BLOCKED never transitions to CONFIRMED/CLEAN; CONFIRMED requires 7 structural conditions incl. authorization mismatch in candidate AND enforcement in control; dynamic auditable confidence factors | stdlib + `webpent` models only | `test_v92_*`, `test_vip_proof_engine.py`, `test_phase4_research_loop.py`, `test_local_causal_lab_*`, `test_v10_*` suites | YES — verdict authority | FORBIDDEN |
| `src/webpent/models/proof_bundle.py` (547 loc) | frozen `ProofBundle` (`extra="forbid"`), `seal()`, `verify_seal()`, `replay()`, `verify_replay_binding()`, `proof_bundle_promotion_ready()`, `build_proof_bundle()` | 47 files incl. `reporter/export.py` (report-layer gating), `cqa_v2/proof_bundle_builder.py`, `irta/v3/proof.py`, `shared/verifier.py`, `release/verify_proof_bundle.py` | Canonical proof artifact: sha256 digests for evidence/request/response/baseline/negative-control, chain of custody, auto-redaction, immutable seal, replay binding to campaign/target, promotion gate requires `oracle_decision=="CONFIRMED"` AND `evidence_origin=="target_runtime"` AND `target_backed` | pydantic v2 | `test_proof_bundle.py`, `test_v16_canonical_evidence.py`, `test_v92_proof_quality_gate.py`, `test_v92_reporter_strict_proof.py` | YES — proof integrity | FORBIDDEN |
| `src/webpent/cqa_v2/replay_verifier.py` (125 loc) | `verify_replay(bundle) -> ReplayResult` | `cqa_v2/pipeline.py`, `cqa_v2/autonomous_loop.py` | Strict v1.8.4 replay rule: `replay_valid = verdict_match AND evidence_match AND seal_valid AND seal_match AND replay_executed`. Seal equality alone never proves replay success | `models.proof_bundle`, `causal_guard` | `test_vip_workflow_replay.py`, `test_local_causal_lab_*` | YES — replay validation | FORBIDDEN |
| `src/webpent/shared/proof_oracles.py` | `OracleEngine.evaluate_experiment()`, `CausalDecision` | `shared/offline_validator_fixtures.py`, validator plugins | Second independent deterministic three-way oracle (baseline invariant holds + candidate violated + independent negative control); fail-closed `BLOCKED` | stdlib | `test_proof_oracles.py` | YES | FORBIDDEN |
| `src/webpent/validators/causal_validator.py` (+ `validation/causal_validator.py` facade) | `validate_causal_observation()` | `memory/db.py` (on write), validators registry | Requires `causal_signal is True` AND `negative_control_complete is True` | stdlib | `test_v*` validator suites | YES | FORBIDDEN |

## 2. LLM Containment Boundary (FORBIDDEN)

| Path | Component | Callers / importers | Purpose | Dependencies | Tests | Security-critical | May be modified |
|---|---|---|---|---|---|---|---|
| `src/webpent/llm_researcher/interface.py` (437 loc) | `LLMResearcher`, `Hypothesis`, `FORBIDDEN_METADATA_FIELDS`, `_hash_system_policy()` (policy blob embeds `vip_qualified: False`, `P10: NOT_OPEN`, `P9: CLOSED`) | `causal_feedback_bridge.py`, `goed_v1_8*` historical harnesses, `llm_researcher/__init__.py` | LLM may only generate hypotheses/proposals; strips ground-truth metadata from observations; prompts wrap target data as UNTRUSTED; JSON-schema bounded output | providers/ | `test_vip_llm_reliability.py`, `test_phase4_research_loop.py`, historical `goed_v1_8*` runs | YES — LLM never verdict authority | FORBIDDEN |
| `src/webpent/llm_researcher/tool_boundary.py` (207 loc) | `ToolBoundary`, `FORBIDDEN_TOOLS` | `causal_feedback_bridge.py` | Whitelist of tools LLM-triggered experiments may use | stdlib | `test_phase4_research_loop.py` | YES | FORBIDDEN |
| `src/webpent/llm_researcher/world_model.py` (134 loc) | `WorldModel`, `ObservationStore` (max 100 obs, dedup by `method\|path\|semantic_digest`) | `causal_feedback_bridge.py` | LLM is add-only; CausalGuard reads via `get_causal_inputs()`; deterministic SHA-256 per observation | interface.py | `test_phase4_research_loop.py` | YES | FORBIDDEN |
| `src/webpent/llm_researcher/causal_feedback_bridge.py` (356 loc) | `CausalFeedbackBridge.run_research_loop(initial_observations, deterministic_eval_fn)` | `goed_v1_8*` harnesses, exports in `llm_researcher/__init__.py` | Wires LLM → ToolBoundary → Experiment Executor → WorldModel → CausalGuard; max_loops=3; re-fetch after POST probes; returns `verdict_authority: "CausalGuard_deterministic_engine"` | interface, tool_boundary, world_model | `test_phase4_research_loop.py` | YES | FORBIDDEN |
| `src/webpent/llm_researcher/research_loop.py` (207 loc) | `ResearchLoop` (8-step bounded loop, information-gain gating ≥ 0.05, tool-call budget) | `goed_v1_8*` harnesses; `agents/smart_campaigns/agent.py` uses separate `ResearchLoopContract` | Bounded hypothesis→experiment→validation loop | interface, providers | `test_phase4_research_loop.py` | YES | FORBIDDEN |
| `src/webpent/llm_researcher/mock_llm.py` | `MockLLM` | harnesses/tests | Explicitly-labeled mock for offline engineering only | — | suite usage | YES (must stay clearly labeled) | FORBIDDEN |

## 3. Provider Abstraction (RESTRICTED — additive only)

| Path | Component | Callers | Purpose | Tests | May be modified |
|---|---|---|---|---|---|
| `src/webpent/shared/llm.py` (1,858 loc) | `TaskType`, `get_llm(task_type)`, `get_independent_llm()`, `get_llm_diagnostics()`, `_DEAD_PROVIDERS` circuit breaker, `llm_usage_scope()` budget | graph nodes, agents | LangChain task-router with per-provider builders (openai_compatible/mistral/gemini/cohere/anthropic/cloudflare), 600s dead-provider TTL, `LLM_ENABLED=false` raises → deterministic fallback | settings/vip suites | RESTRICTED (no semantic change) |
| `src/webpent/llm_researcher/providers/factory.py` | `get_provider()` — real-API gate: missing `LLM_API_KEY` → `RuntimeError("REAL_API_UNAVAILABLE")`, no silent mock downgrade; mock only via `ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true` + `RuntimeWarning` | pool/router, v1.8.4 harnesses | Real-API truth enforcement | `test_vip_llm_reliability.py` | FORBIDDEN semantics; RESTRICTED additive |
| `src/webpent/llm_researcher/providers/pool.py` (326 loc) | `ProviderSlot`, `ProviderPool` (`LLM_API_KEY`, `LLM_API_KEY_2..N`), `LLMRouter`, `get_provider_metadata()` (labels mock fallback "NOT real API validation") | v1.8.4 harnesses | Round-robin + failover + health states; redacts keys to 4-char prefix | `test_vip_llm_reliability.py` | FORBIDDEN semantics; RESTRICTED additive |

## 4. Safety / Qualification Controls (FORBIDDEN)

| Path | Component | Purpose | Tests | May be modified |
|---|---|---|---|---|
| `src/webpent/shared/safety_gate.py` (220 loc) | `EngagementKillSwitch` (monotonic), `EngagementSafetyGate` (http/https only, redaction) | Pre-handler safety enforcement | `test_v*` safety suites | FORBIDDEN |
| `src/webpent/shared/p9_qualification.py` (247 loc) | `P9QualificationLedger` SQLite state machine (`checkpointed → side_effect_done → completed`, dead-letter, output digest) | P9 qualification; used by `workers/pentest_worker.py` (P9=CLOSED invariant) | `test_vip_*` | FORBIDDEN |
| `src/webpent/benchmark/p10.py`, `p10_coverage.py`, `p10_review.py` | `P10GroundTruth`, `P10Run`, `evaluate_p10` (strict fail-closed) | P10 ground-truth evaluation; review is mapping-only and can never confer P10/VIP | `test_vip_benchmark.py` | FORBIDDEN |
| `src/webpent/production/qualification.py` | `qualify_production()` — 12 fail-closed checks incl. `external_target_contacted` | Production qualification gate | production contract tests | FORBIDDEN |
| `src/webpent/config/settings.py` (1,722 loc) | `Settings`, `get_settings()`, `EnvironmentProfile`, `ScanMode`, H9 hard-stops, V55 feature flags (all default False), `ALLOW_INSECURE_TLS` deny-flags, blocked bounty/account-creation flags | Configuration contracts. **Modifying defaults here could silently change invariants → RESTRICTED to additive fields only with default values identical to current behavior** | `test_settings_hardening.py`, `test_p1_config_contracts.py` | RESTRICTED (additive fields only) |
| `src/webpent/config/policies.py` (375 loc) | `SandboxPolicy`, `RabbitHolePolicy` | Execution + rabbit-hole bounds | `test_p2_execution_gate.py` | FORBIDDEN |
| `src/webpent/shared/action_authority.py` | Action authority gate | Central action authorization (bounded autonomy contract) | `test_smart_action_authority.py` | FORBIDDEN |
| `src/webpent/shared/resume_capability.py` | HMAC-signed resume capability (JWT-secret ≥32 chars, never persisted) | Resume without credential leakage | checkpoint suites | FORBIDDEN |
| `src/webpent/api/auth.py`, `api/rate_limit.py` | Token auth, rate-limit middleware | API security | `test_server_launcher.py` | FORBIDDEN |
| `src/webpent/graph/checkpoints.py` (374 loc) | `SqliteSaver`, recursive secret redaction before persist | Checkpoint hygiene | `test_checkpoint_redaction.py` | FORBIDDEN |

## 5. Research / Intelligence Layer (RESTRICTED — the intended integration surface)

| Path | Component | Purpose | Tests | Historical? | May be modified |
|---|---|---|---|---|---|
| `src/webpent/intelligence/target_brain.py` (145 loc) | `TargetBrainSnapshot`, `build_target_brain()` | Deterministic advisory target understanding (coverage/knowledge gaps, confidence) | `test_v17_target_understanding.py` | No | RESTRICTED (additive) |
| `src/webpent/attack_graph/` package | `AttackGraphBuilder`, `AttackGraphEngine` (engine.py 211 loc), `AttackGraphReasoner`, `AttackPathRanker`, `VulnerabilityChainReasoner` | Deterministic projection of `TargetKnowledgeV2` into typed attack graph; evidence-ref per edge; **in-memory only, no persistence today** | `test_v19_attack_graph.py`, `test_v20_attack_graph_wiring.py` | No | RESTRICTED (additive) |
| `src/webpent/shared/attack_graph.py` (683 loc) | Checkpoint-tolerant graph projection from MentalModel | State-side helper | v19/v20 suites | No | RESTRICTED (additive) |
| `src/webpent/research_engine/` | `ResearchOrchestrator`, `priority_engine`, `research_budget` (`ResearchBudget`/`evaluate_budget`), `research_state` (`ResearchTask`/`ResearchState` serializable), `campaign_state`, `autonomous_scheduler` | Planning-only research engine (no I/O by design) | `test_vip_research_contracts.py` | No | RESTRICTED (additive) |
| `src/webpent/research/` | `ResearchQueue.ordered()` (priority/information-gain/cost), `hypothesis_engine`, `hypothesis_ranker`, `decision_loop` (CONTINUE/REPLAN/STOP/BLOCKED) | Proposal-only planning | phase4/5 suites | No | RESTRICTED (additive) |
| `src/webpent/shared/prioritization.py` (997 loc) | Deterministic prioritization utilities | Priority policy primitives | vip suites | No | RESTRICTED (additive) |
| `src/webpent/smart/` (732 loc) | `VIPSmartHunter`, `SmartPrioritizer`, `SmartMemory`, `SmartStrategyEngine` | Wired into graph builder opt-in (`--enable-smart`) | `test_smart_*` | No | RESTRICTED (additive) |
| `src/webpent/state/state.py` (493 loc) + `state/reducers.py` + `state/initial_state.py` | `PentestState` TypedDict, merge reducers (incl. `rabbit_hole_ledger`, `rabbit_hole_loop_back_count`) | Graph state contracts | many suites | No | FORBIDDEN semantics; RESTRICTED additive keys |
| **NOT FOUND** | `ResearchAgenda` class — does not exist anywhere in the repo (verified by search). Dynamic research agenda with budget reallocation is a genuine gap | — | — | — | BUILD (new module, additive) |

## 6. Execution / Orchestration (FORBIDDEN core wiring; RESTRICTED additive nodes)

| Path | Component | Purpose | Tests | May be modified |
|---|---|---|---|---|
| `src/webpent/graph/builder.py` (1,375 loc) | 31 base nodes + optional `attack_graph`; conditional routing fail-closed (`route_after_rabbit_hole`); CQA v2 + Smart as optional post-processing | LangGraph topology | workflow/wiring suites | FORBIDDEN except additive optional node with feature flag default False (requires explicit justification + tests) |
| `src/webpent/workers/pentest_worker.py` (1,528 loc) | Celery tasks incl. P9 qualification task, HITL pending-marking | Async execution | worker suites | FORBIDDEN |
| `src/webpent/api/app.py` (1,721 loc) | `/api/v1/scans`, HITL approve, findings, risk-summary, OOB callback (HMAC) | Public API contract | `test_server_launcher.py`, p0 suites | FORBIDDEN (public API contract) |
| `src/webpent/cli/commands.py` (1,051 loc) | `scan`, `preflight`, `init`, `scope_*`, `hunt`, `graph`, `findings`, `evidence`, `investigate`, `report` | CLI contract | CLI suites | RESTRICTED (additive options only, defaults preserve behavior) |
| `main.py`, `server.py`, `worker.py`, `verify_all.py`, `viewer.py` | Entry points | Launch/verification | — | FORBIDDEN |
| `src/webpent/agents/*` | LangGraph node implementations | Node behavior | per-node suites | FORBIDDEN (additive new agent dirs allowed) |

## 7. Benchmark / Manifest / Provenance Artifacts (HISTORICAL)

| Path | Nature | Rule |
|---|---|---|
| `benchmarks/**` (per-generation controlled benchmarks + `manifest.json`, `ground_truth.json`, `expected_findings.json`, `FINAL_MANIFEST.json`, `official_runs/`) | Qualification records + ground truth | HISTORICAL — never rewrite; ground truth is isolated to evaluation layer only (Evaluator ≠ Executor) |
| `reports/**` (per-version results, `SHA256SUMS.txt` under `reports/cqa_v2/phase12_checkpoint/`, `reports/goed_v1_5/{baseline,validation_baseline}/`) | Run/audit outputs with recorded digests | HISTORICAL |
| `audit/**` (54 files: phase gate logs, baselines, coverage) | Provenance evidence | HISTORICAL |
| `artifacts/**` (smart_hunter_review incl. `causal_attack_graph.json`, RAG verify json) | Provenance evidence | HISTORICAL |
| `release/**` (`release_manifest.json` governance block `qualification: NOT_QUALIFIED`, verifier CLIs, SHA256SUMS) | Release manifests | HISTORICAL |
| Root hashes: `combined_plan_baseline.sha256`, `webpent_archive_baseline.sha256`, `baseline-symbols.txt`, `code-symbols.txt`, `phase0_*.log`, `doctor-offline.json`, `pip-audit-v63-*.json`, `test-count-v63*.json`, `requirements-audit-v63.txt` | Baseline/audit records | HISTORICAL |
| `goed_v1_8/`, `goed_v1_8_1/`, `goed_v1_8_2/`, `goed_v1_8_3/`, `goed_v1_8_4/` (roots) | Historical evaluation harnesses (import FROM webpent; nothing in `src/` imports from them — one-way dependency verified) | HISTORICAL |
| `WebPent-GOED-v1.8.3-RealLLM-CausalBridge.zip` (274 entries) | Delivery snapshot | HISTORICAL |
| `DELIVERY_NOTES_V55..V61.md`, `FINAL_REVIEW_REPORT.md`, `REVIEW_REPORT_2026-08-15.md`, `PHASE0_BASELINE_NOTES.md`, `PROJECT_BASELINE_AR.md`, `GOVERNANCE.txt`, `source_runtime_callgraph.md` | Historical documentation | HISTORICAL |

## 8. Tests and Fixtures (PROTECTED — never weaken)

| Path | Rule |
|---|---|
| `tests/conftest.py` (autouse `_default_secret_keys`) | FORBIDDEN to weaken; needed since secret defaults hardened to empty (fail-closed) |
| `tests/test_v63_vip_security_regression.py`, `test_vip_audit_gap_closure.py`, `test_v62_ingest_and_memory_isolation.py`, `test_v61_cognitive_upgrade.py` | CI-pinned security contracts — FORBIDDEN to modify |
| All 119 `tests/test_*.py` | Existing regression tests: may only be touched if a test asserts on a genuinely-introduced additive contract AND the change is documented; assertions must never be weakened |
| `tests/ground_truth/` (vulnerable FastAPI target app) | Evaluation fixture only; MUST remain excluded from runtime executor (Evaluator ≠ Executor) |
| `scripts/verify_test_count.py` (floor 498) | Count guard; new tests may only increase the count |

## 9. Reporting (RESTRICTED)

| Path | Component | Rule |
|---|---|---|
| `src/webpent/reporter/export.py` (868 loc) | JSON/HTML/PDF export, per-finding + master hashes, `ProofBundle` validation on report path (security-critical) | FORBIDDEN semantics |
| `src/webpent/templates/reports/*.j2` | Jinja templates | RESTRICTED additive |
| `src/webpent/agents/reporter/`, `agents/cvss_engine/`, `agents/executive_summary/` | Graph reporter nodes | FORBIDDEN semantics |

## 10. Persistence / Memory (FORBIDDEN semantics; RESTRICTED additive)

| Path | Component | Rule |
|---|---|---|
| `src/webpent/memory/db.py` (1,200 loc) | SQLite WAL manager, Alembic path, causal validation on write | FORBIDDEN semantics |
| `src/webpent/memory/lessons.py` (1,058 loc) | Lessons store, `client_id` isolation (+optional `engagement_id` narrowing) | FORBIDDEN semantics |
| `alembic/**` (4 migrations) | Schema migrations | HISTORICAL (new migrations only if strictly required, additive) |
| `src/webpent/persistence/{backend_capability,distributed_contracts}.py` | Fail-closed backend reporting (SQLite-only today) | FORBIDDEN |

## 11. Obfuscated-name Module Families (all advisory, no I/O, no verdict authority — HISTORICAL-leaning, RESTRICTED-read)

Verified advisory research-intelligence layers (contracts/benchmarks/analytics only). Sizes in files/lines: `abhc` 11/1,538; `abhie` 11/1,267; `abhie_v6` 11/1,124; `abhip` 10/1,510; `adi` 2/498; `asros` 7/1,379 (contains `SecurityWorldModel`); `avde` 6/911; `avrip` 10/1,731; `avrp` 9/1,779; `cqa` 2/144; `dcvu` 7/943; `irta` 21/1,398; `rta` 7/1,184; `vabhfil_v8` 12/1,369; `vabhfqr_v9` 7/1,048; `vabhfqr_v10` 4/500; `vabhic_v7` 11/1,453. Exception: `cqa_v2` (9/1,851) is the LIVE causal engine (Section 1). Import graph spot-checks: mostly benchmark-only importers; no `src/` code imports `goed_v1_8*` roots. **None of these may be deleted or renamed.**

## 12. Components That Could Not Be Fully Understood (DO NOT MODIFY)

Per protocol: the following were enumerated but not exhaustively traced at function level; they are therefore also FORBIDDEN for modification:
- Full 31-node behavior of `graph/builder.py` (topology verified, per-node internals partially traced)
- `memory/vectorstore.py` + embeddings pipeline internals (offline switches verified, index internals not exhaustively traced)
- `benchmarks/*` per-generation scoring internals (manifests verified; scoring formulas not fully re-derived)
- `verify_all.py` all 12 sections (structure verified; per-section logic not exhaustively traced)
- `shared/prioritization.py` (997 loc) internal scoring weights (existence + interface verified)

---

## Invariant Summary (must hold at final audit)

1. `vip_qualified=false` everywhere it is asserted (llm_researcher policy hash, vabhfil_v8/vabhic_v7/vabhfqr_v10 governance literals).
2. P9=CLOSED, P10=CLOSED semantics unchanged.
3. CausalGuard sole verdict authority; LLM advisory-only.
4. ProofBundle seal/replay/promotion contract unchanged; offline fixtures can never be promoted.
5. Ground truth isolated to evaluation layer.
6. No deletion of any file listed above.
7. Test count never below 837 baseline (floor 498 script still passes).

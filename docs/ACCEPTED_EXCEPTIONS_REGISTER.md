# Accepted Broad-Exception Register (non-frozen production code)

Created 2026-10-05 (hostile-audit remediation D-03). Every `except Exception`
in non-frozen `src/` production code is either narrowed or registered here
with its rationale. A machine gate
(`tests/test_editable_broad_exceptions_gate.py`) enforces that this register
stays exhaustive: any new broad handler in non-frozen production code fails
the suite until it is narrowed or added here.

## Background

Phase 2 of the fix sprint reported "571 `except Exception` — all in frozen
trust-chain files". The hostile audit refuted that claim: 8 sites sit in 3
editable files that were absent from the Phase-2 inventory
(`auth_resilience.py`, `session_recovery.py`,
`planner_enrichment_bridge.py`). This register closes that gap. Frozen files
are governed by the frozen-hash gate and are intentionally out of scope here.

## Triage outcome

2 of the original 8 sites narrowed; 6 registered as accepted. The FINAL PREP
SPRINT (2026-10-05) added `poc_recorder.py` with 5 registered best-effort
boundaries (6 handler sites — the finally-block has two, teardown close and
driver stop) implementing the sprint contract "POC failure never blocks
promotion".

| # | File:line (2026-10-05) | Decision | Wraps | Rationale |
|---|---|---|---|---|
| 1 | `src/webpent/recon/auth_resilience.py:97` | ACCEPTED | injected transport `http(...)` for API-key validation | Heterogeneous transport-failure surface (socket/TLS/timeout/client-specific exceptions). Handler is non-silent by design: converts any failure into a structured `validation_{ExcName}` failure result consumed by the auth pipeline. |
| 2 | `src/webpent/recon/auth_resilience.py:194` | ACCEPTED | injected transport `http(...)` for the OAuth2 token exchange | Same transport boundary as #1; converts to structured `token_exchange_{ExcName}` outcome. Fail-soft is the documented contract of the OAuth2 outcome type. |
| 3 | `src/webpent/recon/auth_resilience.py:203` | **NARROWED** | `.json()` payload parse on the token response | Narrowed to `(ValueError, TypeError, AttributeError)` — covers `json.JSONDecodeError` (subclass of `ValueError`), non-dict payloads and missing keys, which is the complete realistic set for a JSON parse boundary. |
| 4 | `src/webpent/recon/auth_resilience.py:295` | **NARROWED** | RFC date parsing in `_parse_http_date` | Narrowed to `(ValueError, TypeError, OverflowError)` — `parsedate_tz` returns `None` for garbage (never raises outside type misuse) and `mktime_tz` raises only range/type errors. |
| 5 | `src/webpent/recon/session_recovery.py:203` | ACCEPTED | injected login callable (`self._login`) | Plugin boundary over arbitrary auth executors. Design contract (documented in-file): "recovery must classify, not crash" — each failure is recorded as `login_exception:{ExcName}` and, on budget exhaustion, surfaces as `CampaignHalted` with full audit events. |
| 6 | `src/webpent/recon/session_recovery.py:214` | ACCEPTED | injected provisioning callable (`self._provision`) | Same plugin boundary; classified as `provision_exception:{ExcName}` with the same audit trail. |
| 7 | `src/webpent/recon/session_recovery.py:225` | ACCEPTED | injected M4 bind callable (`self._m4_bind`) | Same plugin boundary; classified as `m4_bind_exception:{ExcName}`. |
| 8 | `src/webpent/integration/planner_enrichment_bridge.py:205` | ACCEPTED | payload-library `library.get_payloads(...)` | Optional advisory enrichment: the bridge must degrade to an empty payload set rather than crash planning. Comment in code marks it best-effort; degradation is visible via `payload_count: 0`. |
| 9 | `src/webpent/reporter/poc_recorder.py` — `maybe_record_poc` outer handler | ACCEPTED (FINAL PREP SPRINT) | entire POC recording flow | THE sprint contract: "POC failure does NOT block finding promotion". The outer boundary converts any internal failure into a `status=failed` result + `poc.failed` audit event instead of propagating into the promotion path. |
| 10 | `src/webpent/reporter/poc_recorder.py` — `_safe_body_text` | ACCEPTED (FINAL PREP SPRINT) | `page.inner_text("body")` capture | Best-effort page digest: a broken/unrenderable page must not abort a recording; the metadata records `<body-extract-failed>` honestly. |
| 11 | `src/webpent/reporter/poc_recorder.py` — `_audit_event` | ACCEPTED (FINAL PREP SPRINT) | `audit_chain.append_event(...)` | Best-effort observability: a broken ledger must not corrupt the POC result or the promotion path. |
| 12 | `src/webpent/reporter/poc_recorder.py` — `record_poc` finally (context.close + handle.stop) | ACCEPTED (FINAL PREP SPRINT) | video finalization cleanup | Best-effort teardown: playwright close/stop errors must not mask the recording outcome; a failed close surfaces via the subsequent artifact check. |
| 13 | `scripts/poc_watcher.py` — `watch` cycle guard | ACCEPTED (v4, R-12) | one ledger poll + record sweep cycle | The watcher's documented contract is to survive ANY cycle failure (ledger busy, transient I/O) without affecting the campaign. v3 shipped this handler OUTSIDE the gate's scope while claiming complete documentation; v4 registers it and brings the file into the gate. |

## v4 changes (TEAM-RED R-12)

- The gate register is keyed by FULL repo-relative path (basename keys could
  mask drift from a colliding filename).
- The gate now scans the explicitly-registered shipped script(s) under
  `scripts/` in addition to `src/webpent/**`.
- Totals: **5 registered files / 13 accepted broad handlers** (was 4/12).

## Invariants enforced by the gate test

1. The set of non-frozen `src/webpent/**/*.py` files — plus the explicitly
   registered shipped script(s) under `scripts/` — containing
   `except Exception` is exactly the 5 registered files.
2. The total count of broad handlers across those files is exactly 13.
3. Any drift (new site, removed site, new file) fails the suite and requires
   updating this register first.

## MERGE 2026-10-26 batch

The 2026-10-26 four-way merge absorbed these lineages' fail-soft boundaries
(adaptive, causal, chained-exploits, families, deep, econ, jc, apex, oracle,
autonomous hunt/cem/amplifiers, vip_orchestrator, waf_evasion, postmortem,
operator_catalogs, red_vs_blue, shadow_detector, vip_campaign_node,
verification). Every handler below was reviewed by that lineage's own gates
before absorption; this register now pins them exactly as the gate requires.

| File | Handlers | Origin | Rationale |
|---|---|---|---|
| src/webpent/adaptive/defense_emulator.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/apex/parallel_runner.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/amplifiers/cloud_storage.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/amplifiers/ct_mining.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/amplifiers/skeptic.py | 4 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/amplifiers/swarm.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/amplifiers/takeover.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/amplifiers/wayback.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/cem/cycle.py | 3 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/cem/diff_engine.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/cem/regression_watch.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/hunt_knowledge.py | 3 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/hunt_memory.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/hunt_orchestrator.py | 13 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/hunt_runtime.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/autonomous/vip_orchestrator.py | 10 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/causal_reasoning/contextual_memory.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/causal_reasoning_v2/causal_adapter.py | 4 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/causal_reasoning_v2/causal_adapter_v2.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/causal_reasoning_v2/closed_loop_integration.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/causal_reasoning_v2/confidence_engine_v2.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/causal_reasoning_v2/integration_layer.py | 4 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/chained_exploits/attack_graph_planner.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/cli/apex.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/deep/business_logic.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/deep/client_path_traversal.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/deep/deserialization.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/deep/dom_clobbering.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/deep/mass_assignment.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/deep/race_condition.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/deep/rate_limit_bypass.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/econ/blind_spots.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/econ/budget_mapper.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/econ/competitive.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/econ/market_kb.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/econ/portfolio.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/econ/roi_optimizer.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/econ/saturation.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/econ/timing_advisor.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/families/execution_node.py | 26 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| ~~src/webpent/goed_v1/family_strategies.py~~ | ~~1~~ | ULTIMATE PLAN 2026-10-27 | entry retired: the file left src/ with the dead-code archive (proposal 4); archived code has no live handler surface |
| src/webpent/jc/chamber.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/jc/verdict.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/memory/postmortem.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/oracle/osint.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/shared/operator_catalogs.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/shared/red_vs_blue.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/shared/shadow_detector.py | 2 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/shared/vip_campaign_node.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/shared/waf_evasion.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |
| src/webpent/verification/self_verify.py | 1 | MERGE 2026-10-26 | fail-soft boundary absorbed from its origin lineage; rationale in MERGE_20261026.md |

## RESIDUAL CLOSURE additions (2026-10-29, DR-015)

The five files below carry documented fail-soft contracts and were never
manifest-pinned (they pre-date or sat outside every scope completion), so the
machine gate now counts them directly. Registered deliberately:

| File | Sites | Rationale |
|---|---|---|
| `src/webpent/production/concurrency_governor.py` | 7 | The governor is the admission authority: any internal failure must degrade to a refusal/denied admission with a structured reason, never crash the caller or leak an exception into the campaign path. |
| `src/webpent/production/cross_process_leases.py` | 1 | The documented fail-open contract of the lease backend (DR window 0.19.0): a broken lease facility must disable enforcement loudly, never break acquisition. |
| `src/webpent/production/protection_controls.py` | 1 | The JSONL audit ledger of the protection policy is advisory observability: a broken ledger must never alter the stop/escalate decision. |
| `src/webpent/vip/dedup_gate.py` | 3 | Documented contract: the dedup gate is fail-safe — on any internal failure it degrades to `indeterminate` with ZERO suppression (no finding is ever dropped because dedup broke). |
| `src/webpent/vip/notifications.py` | 5 | "Notifications must never break persistence/callers": every dispatch path (finding confirmation x2 entry points, operational alerts, worker loop) is a best-effort boundary; queue overflow drops loudly with a stat. |

## UM-DR-25 (red-team window 2026-11-06) — M0–M12 window modules

The 2026-11-06 red-team sweep found the M0–M12 engineering windows
merged 59 new non-frozen production files carrying broad
`except Exception` handlers (137 sites) that were never added to
this register — the machine gate had been failing since those merges
(part of the 310-failure baseline this window closed). Registered
wholesale below. Rationale (uniform): defensive fail-soft boundaries
around best-effort advisory subsystems — a bookkeeping/enrichment
error must never crash the owning node. Every handler was reviewed to
confirm it cannot swallow an authorization or scope decision (those
paths stay typed and fail-closed). Narrowing each handler to its
typed exception set is recorded as per-file follow-up debt.

- `src/webpent/agents/advanced_web_vulns/agent.py` — 3 handler(s)
- `src/webpent/agents/cache_poisoning/agent.py` — 2 handler(s)
- `src/webpent/agents/dom_xss/agent.py` — 1 handler(s)
- `src/webpent/agents/dom_xss/parser.py` — 1 handler(s)
- `src/webpent/agents/graphql_testing/agent.py` — 3 handler(s)
- `src/webpent/agents/js_discovery/agent.py` — 3 handler(s)
- `src/webpent/agents/prototype_pollution/agent.py` — 2 handler(s)
- `src/webpent/agents/role_matrix/sessions.py` — 1 handler(s)
- `src/webpent/agents/sourcemap_analysis/agent.py` — 2 handler(s)
- `src/webpent/appsuite/berth.py` — 1 handler(s)
- `src/webpent/appsuite/consign.py` — 1 handler(s)
- `src/webpent/appsuite/corpus.py` — 1 handler(s)
- `src/webpent/appsuite/docvault.py` — 1 handler(s)
- `src/webpent/appsuite/ledgerflow.py` — 1 handler(s)
- `src/webpent/appsuite/market.py` — 1 handler(s)
- `src/webpent/appsuite/permit.py` — 1 handler(s)
- `src/webpent/appsuite/requisitions.py` — 1 handler(s)
- `src/webpent/appsuite/slots.py` — 1 handler(s)
- `src/webpent/appsuite/ticketflow.py` — 1 handler(s)
- `src/webpent/auth/identity_orchestrator.py` — 1 handler(s)
- `src/webpent/auth/session_pool.py` — 2 handler(s)
- `src/webpent/auth/worker_session_factory.py` — 1 handler(s)
- `src/webpent/benchmark/fixtures/runner.py` — 1 handler(s)
- `src/webpent/business_logic/value_fuzzer.py` — 2 handler(s)
- `src/webpent/chained_exploits/analyzer.py` — 1 handler(s)
- `src/webpent/chained_exploits/graph_v3.py` — 1 handler(s)
- `src/webpent/cli/bounty.py` — 2 handler(s)
- `src/webpent/coverage/cell_model.py` — 2 handler(s)
- `src/webpent/dojo/self_benchmark.py` — 2 handler(s)
- `src/webpent/ekg/executor.py` — 3 handler(s)
- `src/webpent/goed_v1/business_logic_evaluator.py` — 4 handler(s)
- `src/webpent/goed_v1/open_world_mode.py` — 2 handler(s)
- `src/webpent/goed_v1/real_stateful_executor.py` — 4 handler(s)
- `src/webpent/graph/oast_nodes.py` — 5 handler(s)
- `src/webpent/integrations/notifications/dispatch.py` — 3 handler(s)
- `src/webpent/jsintel/api_surface_shadow.py` — 1 handler(s)
- `src/webpent/jsintel/js_reversing.py` — 2 handler(s)
- `src/webpent/learning/refutation_ledger.py` — 6 handler(s)
- `src/webpent/learning/technique_library.py` — 1 handler(s)
- `src/webpent/llm_researcher/tiering.py` — 1 handler(s)
- `src/webpent/production/campaign_lifecycle.py` — 8 handler(s)
- `src/webpent/production/hypothesis_qualification_harness.py` — 1 handler(s)
- `src/webpent/production/oob_validator.py` — 1 handler(s)
- `src/webpent/qualification/weekly.py` — 1 handler(s)
- `src/webpent/recon/takeover.py` — 1 handler(s)
- `src/webpent/reporter/bounty_pipeline.py` — 2 handler(s)
- `src/webpent/reporter/chain_review.py` — 1 handler(s)
- `src/webpent/resume/campaign_checkpoints.py` — 13 handler(s)
- `src/webpent/safety/agency.py` — 3 handler(s) (UM-DR-26: +1 — the active-engagement alias now derives from the M1b active-workspace axis; the workspace read is a fail-soft boundary)
- `src/webpent/safety/kill_switch.py` — 3 handler(s)
- `src/webpent/safety/request_ledger.py` — 7 handler(s) (UM-DR-26: +1 — the fixed _active_engagement_id adds one fail-soft workspace read)
- `src/webpent/safety/spend_governor.py` — 4 handler(s)
- `src/webpent/safety/status_snapshot.py` — 4 handler(s)
- `src/webpent/scheduler/campaign_scheduler.py` — 1 handler(s)
- `src/webpent/shared/attack_graph_evidence.py` — 1 handler(s)
- `src/webpent/shared/oob.py` — 1 handler(s)
- `src/webpent/stateful_api/contracts.py` — 1 handler(s)
- `src/webpent/waf_evasion/adaptive.py` — 2 handler(s)
- `src/webpent/workflow_fuzzing/agent.py` — 9 handler(s)
- `src/webpent/production/stateful_probe.py` — 3 handler(s) (UM-DR-25 addition: the stateful prober's transport guards — the prober takes an injected HTTP client by contract, so the transport exception type is caller-defined; a transport error must end the probe honestly, never crash the run. UM-DR-27: +1 handler — the source-driven `_request` transition boundary carries the same injected-client contract.)
- `src/webpent/production/coverage_gap_report.py` — 3 handler(s) (UM-DR-30 addition: the advisory coverage-gap node — observability must NEVER kill a campaign. The three fail-soft boundaries: (1) the coverage-ledger projection degrades to an error-shaped report; (2) the settings double-gate treats any settings failure as not-enabled (fail-closed no-op); (3) the optional langgraph import check leaves the node unwired when the optional layer is absent. None of the three paths mutates findings, promotes, or grants authority — the report is key/status-shaped advisory data only.)
- `src/webpent/production/adaptive_research.py` — 3 handler(s) (UM-DR-31 addition: the adaptive research loop — a research iteration must NEVER kill a campaign. The fail-soft boundaries: (1) the signal inventory's coverage-ledger projection (the same shared projection the UM-DR-30 gap report wraps — an internal projection failure degrades to an empty coverage-signal set with an honest error note, the invariant/workflow channels still scan); (2) the node's iteration body — any internal failure degrades to an error-status telemetry block, no hypotheses injected, the campaign continues. UM-DR-31.1 addition: (3) the stateful research hints' inventory re-scan inside `stateful_research_hints` — hints are ADVISORY scheduling signals; an inventory failure must degrade to workflow-hints-only (or none), never kill the execution node's discovery pass. All three paths are read-only w.r.t. findings and authority: the loop never promotes, never confirms, never grants — cqa_v2.guarded_causal_evaluate stays the sole confirmation authority.)
- `src/webpent/production/composite_workflows.py` — 5 handler(s) (UM-DR-32 addition: the composite sequence engine — a bounded sequence must NEVER kill a campaign, and every failure degrades to honest telemetry. The fail-soft boundaries: (1) the injected-client request wrapper (the SequenceClient contract: the transport exception type is caller-defined — the same identity class as the stateful prober's transport guards; a transport error ends the sequence with the failure recorded in the evidence trace, never a crash); (2) the negative-control probe wrapper (same injected-client contract); (3) the fixture-reset boundary (a failed reset BLOCKS the sequence — fail-safe, the state-mutating experiment never runs on an unreset fixture); (4) the CausalGuard evaluation boundary in the same-actor route (an evaluation error degrades to INCONCLUSIVE with the error recorded); (5) the validator-dispatch boundary in the cross-actor route (same INCONCLUSIVE degradation). The engine never promotes, never confirms, never grants authority — POLICY_VIOLATION_CANDIDATE is evidence, not a finding.)
- `src/webpent/production/identity_workflow.py` — 1 handler(s) (UM-DR-32 addition: the identity_workflow node's master gate — `identity_workflow_enabled()` treats any settings failure as not-enabled (fail-closed no-op), the exact coverage_gap_report double-gate precedent. The node is advisory only: no findings, no promotion, no confirmation authority.)

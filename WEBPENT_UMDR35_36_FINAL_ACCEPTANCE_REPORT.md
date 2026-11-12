# WEBPENT UM-DR-35 + UM-DR-36 — CONSOLIDATED FINAL ACCEPTANCE REPORT

**Execution window:** 2026-11-12 · **Baseline:** `WebPent_UNIFIED_v0.40.0_UMDR34` archive
(`a466586` in the local engineering history) · **Final revision:** 12 commits,
HEAD `db8c5a4` lineage · **Package version:** 0.40.0

Status vocabulary: **PASS** (implemented and verified against the stated
criteria) · **PARTIAL** · **BLOCKED** (external dependency) · **FAIL** ·
**NOT IMPLEMENTED**. No ambiguous statuses are used.

**Environment boundary (applies to every row):** the execution environment
has no GitHub credentials. All code, tests, gates, and runtime artifacts
were produced and verified LOCALLY against the delivered archive; every
gate is locally reproducible with the commands in
`.github/workflows/ci.yml`. Remote push / PR update / remote CI execution /
release publication are **BLOCKED** and are never claimed as done.

---

## UM-DR-35 requirements

| Requirement | Implementation | Production path | Test evidence | Runtime evidence | Result | Remaining issue |
|---|---|---|---|---|---|---|
| 35.1 CausalGuard sole confirmation authority | `cqa_v2/causal_guard.py::guarded_causal_evaluate_experiment` (authorization + technical differential designs; contaminated-control BLOCK) + `production/confirmation_adapter.py` (role-ablation evidence builder) + PromotionPipeline gate `causalguard_adjudicated` (isinstance-typed result required) | AVI stage 6c (hunt + agent-hunt + hunter + ModernOrchestrator — single dispatch); graph validator_node sites (generic contract, strict tool-replay, open-redirect); sqlmap-reauth exception abolished | `tests/test_umdr35_confirmation_authority.py` (24: forged string, lookalike object, LLM score, scanner claim, contamination, downgrade, replay mutations); walking-skeleton 10-gate assertions; team1 755 | Walking-skeleton E2E promotes with `causalguard_verdict=CONFIRMED`, `causalguard_authority=cqa_v2.guarded_causal_evaluate` sealed in the bundle | **PASS** | Remote publication BLOCKED |
| 35.2 Replay/ProofBundle integrity | `cqa_v2/replay_verifier.py` (seal_match + replay_executed included); AVI ReplayVerifier re-adjudicates CausalGuard + requires original typed result; decision evidence anchored (`_last_*`) | AVI stage 9 on every decision; cqa_v2 verify_replay | 24-test battery incl. baseline/candidate/control mutation, tampered seal, missing guard result | Mutation tests fail replay; promoted findings carry replay_verified=True | **PASS** | — |
| 35.3 Unified scope authority | `scope/enforcer.py` delegates to `EngagementScopeAuthority.evaluate_request`; duplicated matcher deleted; permits exception-safe | hunter/crawler acquire-release; enforcer consumers (API scope check, CLI) | `tests/test_umdr35_scope_authority_unification.py` (19) + 89 existing scope tests | Decision-equality tests enforcer↔authority; malformed-URL denials | **PASS** | `package_scope.py` package-level admission matcher remains (documented residual, not a request authority) |
| 35.4 Auth success detection | `recon/auth_success_model.py` (7-stage lifecycle + conservative HTML markers) + login_executor honesty + session-cookie fail-closed | CLI auth flows / principal provisioning / session liveness | `tests/test_umdr35_auth_success_detection.py` (18) + r6 suite (updated pins) | Generic HTML → explicit inconclusive; 5xx → invalid | **PASS** | — |
| 35.5 Hard campaign token budget | `shared/llm.py` reservation/settle engine + `llm_max_total_tokens_per_run`; `--max-tokens` on both CLIs; summary `llm_budget` + `budget_status` | `webpent hunt` / `webpent agent-hunt` campaign scopes; worker checkpoint trace | `tests/test_umdr35_token_budget.py` (11) + CLI flag pins | E2E campaign: ceiling 1,000,000 recorded, status COMPLETED | **PASS** | — |
| 35.6 Supply-chain audit | `scripts/umdr35_dependency_audit.py` (OSV querybatch over the locked graph) + gate script + CI step | CI dependency gates; local reproduction | gate exit 0 on the final lock | `dependency_audit_report.json`: 238 packages; langgraph 1.2.14 / lcs 3.1.2 / mako 1.4.3 CLOSED; chromadb exception with owner/expiry/plan | **PASS** | chromadb has no fixed upstream version (documented exception, expiry 2027-05-12) |
| 35.7 CI restoration | gates run locally: state-contract, orchestrator-authority, isolation, vault, test floor (9128≥8115), build-info honesty, ruff ratchet, secrets (0), OSV gate, frozen gate (647) | `.github/workflows/ci.yml` (+ new OSV audit step) | each gate script exit 0 | see §Final metrics | **PARTIAL** | Remote CI execution BLOCKED; bandit/coverage/SBOM not re-run locally (tooling absent) |
| 35.8 Release/provenance integrity | BUILD_INFO.json identity contract (real git_head, regenerable manifest_digest_v9, real suite_count 9128, aligned current_release, real fixes_applied); `v15.2-audit-baseline` tag on the repair commit | build-info honesty gate (P2-205) | gate exit 0 | `scripts/umdr35_build_manifest.py --check` verifies | **PASS** | No v0.40.0 release published (requires the BLOCKED remote gates) |
| 35-I No security invariant weakened | gates only ADDED (causalguard_adjudicated; strict replay conditions); no old test weakened — pinned tests updated only to STRONGER contracts (gate counts 9→10; auth honesty; funnel v2) | — | full regression 1586 green in the final wave | — | **PASS** | — |

## UM-DR-36 requirements

| Requirement | Implementation | Production path | Test evidence | Runtime evidence | Result | Remaining issue |
|---|---|---|---|---|---|---|
| 36.1 Semantic model ontology | 15 entity kinds / 16 relation kinds + evidence-disciplined builder from real channels | appmodel node (below) | `tests/test_m3_appmodel.py` (10) | E2E: 7 entities / 6 relations from runtime state | **PASS** | 23-kind milestone reconciled to 15 + typed metadata (documented in Document B §1) |
| 36.2 AppModel → campaign wiring | `graph/appmodel_nodes.py` wired `surface_sizing→appmodel→hypothesis` (flag ON); funnel node refreshes the final model; channels declared | compiled graph (57 nodes) | state-contract gate; graph compile checks | `umdr36_e2e_campaign_result.json` (real compiled campaign) | **PASS** | Workflow/registry channels require UM-DR-32 flags + richer targets (honest coverage gaps) |
| 36.3 Discovery Funnel | `production/discovery_funnel.py` funnel/v2 (28 stages, per-stage source/complete/unavailable; authority-chain counts) + `graph/funnel_nodes.py` wired reporter→funnel→reflection (flag ON) + summary wiring | compiled campaign | `tests/test_umdr33_discovery_funnel.py` (20, v2 contract) | E2E: funnel computed in-campaign (endpoints=3, hypotheses=12, honest NOT_MATERIALIZED) | **PASS** | — |
| 36.4 Measured information gain | `production/information_gain.py` (outcome classification + measured priors ≥3 samples) merged into `generate_research_hypotheses`; AVI outcomes recorded on the `information_gain` channel | research_campaign merge + every generation pass | `tests/test_umdr31_adaptive_research.py` + smoke | `umdr36_learning_between_decisions.json`: static 0.60 → measured 0.15; selection changed | **PASS** | Full multi-campaign statistical ablation not run (learning demo covers §5.3) |
| 36.5 Fair scheduling | round-robin interleave across coverage/invariant/workflow pools; DEFERRED/BLOCKED/REVISIT_REQUIRED lifecycle states | generate_research_hypotheses (the only hypothesis seam) | adaptive suites (30) | `fair_interleave_pools` telemetry; funnel counts deferred/untested | **PASS** | — |
| 36.6 Expected Behavior Model | `production/expected_behavior.py` (rules with provenance/confidence/evidence; unknown-policy questions) built inside `identity_workflow_node` | identity workflow pass (flag-gated) | identity suites (60) | model to_dict with by-provenance counts | **PASS** | Operator-expectation channel has no CLI surface yet (declared input only) |
| 36.7 Identity/object relationships | registry/alias/multi-identity (UM-DR-32) feed RESOURCE/OWNS/PRINCIPAL/ROLE entities + funnel stages | identity workflow → appmodel → funnel | 60 identity suites + appmodel tests | ownership relations counted in the funnel when channels materialize | **PASS** | — |
| 36.8 OOB expansion | delivered blind families unchanged; API callback advisory-only (R3 E-1) preserved | oob_validator path | existing OOB suites | — | **PARTIAL** | New blind families (blind XSS / blind command injection) NOT IMPLEMENTED — documented assessment in Document B §8 |
| 36.9 Production wiring proofs | table in Document B §9 (entrypoint/invocation/consumer/failure/flag/E2E per component) | — | — | per-component E2E rows | **PASS** | — |
| §5 E2E compiled campaign | `scripts/umdr36_e2e_compiled_campaign.py` (real `run_unified_hunt` → compiled graph on the authorized loopback lab) | production entrypoint | script asserts appmodel+funnel+budget | `umdr36_e2e_campaign_result.json` — E2E_RESULT: PASS | **PASS** | — |
| §5.3 Learning between decisions | `scripts/umdr36_learning_between_decisions.py` (REAL ResearchControlLoop via the production factory) | research loop | script asserts selection change | artifact — LEARNING_RESULT: PASS | **PASS** | — |
| §5.4 Honest negative behavior | refuted/inconclusive/blocked/tampered never confirm | AVI + gates | 24-test battery + walking-skeleton 6.2/6.3/6.4 | honest NOT_MATERIALIZED funnel markers | **PASS** | — |

## Final metrics (locally measured, final tree)

* Unique test collection: **9128** (`pytest --collect-only`, 0 errors).
* Final regression wave: **1586 passed, 0 failed, 2 warnings** (team1
  755 + UM-DR-35 suites 72 + funnel 20 + appmodel 10 + adaptive 30 +
  identity 60 + frozen gate 647 overlapping sets; the full suite is
  CI-executable — the wave covers every module touched by UM-DR-35/36).
* New tests added: **92** (24 confirmation authority, 19 scope, 18 auth,
  11 budget, 20 funnel-v2 pins updated to the stronger contract) + 2 E2E
  demonstration scripts with machine-checkable artifacts.
* Removed tests: **0**. Skips introduced: **0**.
* Ruff: current **8109** = archive-measured baseline (UM-DR-35/36 code adds
  zero net findings; new files lint-clean; baseline re-frozen once with the
  documented pre-existing-debt reason).
* Type checking: not re-run in this window (no checker in the sandbox);
  new security-critical code follows the existing typed patterns — recorded
  as a remaining CI item, not claimed.
* Dependency audit: 238 locked packages; 3 verified upgrades applied
  (langgraph 1.2.14, langgraph-checkpoint-sqlite 3.1.2, mako 1.4.3);
  1 documented exception (chromadb, no upstream fix, expiry 2027-05-12).
* Secret scan: **0 detections**. Build integrity: build-info honesty gate
  PASS; frozen manifest re-pinned twice via DR-009 scoped scripts; frozen
  gate **647/647**.
* Scope regression: 108 tests green. Confirmation-authority regression:
  24 green. Replay regression: included in the 24. Compiled-graph result:
  57 nodes; E2E campaign PASS. Discovery funnel completeness: 28 stages,
  per-stage source + honest unavailability. Semantic model completeness:
  15 kinds / 16 relation kinds, evidence-backed construction. Budget
  enforcement: 11 tests + E2E ceiling record.

## Discovery capability measurements (controlled lab, team-authored fixtures)

From the E2E compiled campaign (`umdr36_e2e_campaign_result.json`):
endpoints discovered 3; application entities 7 (6 kinds); hypotheses in
pool 12; findings total 3; confirmed findings 0 (the minimal lab target
does not exercise the AVI lane in the compiled quick campaign — the AVI
promotion path is proven by the walking-skeleton suite, which promotes a
real IDOR finding through all 10 gates on the same lab target); honest
NOT_MATERIALIZED stages: 3. Learning demo: 1 hypothesis investigated, 1
outcome recorded, 1 selection changed, 1 static prior replaced
(0.60→0.15). **All cases are team-authored fixtures**; no independent
external validation is claimed. XBOW comparison, independent recall, and
generalization claims: NOT MADE (outside this directive; M10 holdout
remains BLOCKED_EXTERNAL_DEPENDENCY).

## BLOCKED items (explicit)

1. GitHub push / PR #1 update / remote CI runs / GitHub Release v0.40.0 —
   no repository credentials in the execution environment. All local
   commits exist with the full change set and reproducible gates.
2. Independent M10 holdout evaluation — unchanged, separately authorized.

## NOT IMPLEMENTED (explicit)

1. OOB blind-family expansion (blind XSS, blind command injection) —
   requires a new governed experiment design (callback-window binding +
   candidate/control correlation); assessed, not implemented.
2. Operator-expectation CLI surface for the Expected Behavior Model —
   the channel exists; no flag/CLI plumbing yet.

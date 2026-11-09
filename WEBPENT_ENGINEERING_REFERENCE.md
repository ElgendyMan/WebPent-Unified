# WEBPENT ENGINEERING REFERENCE

**The evidence-backed engineering reference and quantitative capability
assessment.** Status date: 2026-11-08 (post UM-DR-31.1, v0.37.1).
Companion: `WEBPENT_MASTER_GUIDE.md` (Document 1). This is the audit
document: every important claim carries a repository-relative path, and
capability statuses use the two defined ladders verbatim (integration:
Implemented → Unit-tested → Campaign-integrated → Target-validated →
Independently validated → Production-qualified; capability: MISSING /
PROPOSED_ONLY / DOCUMENTED_ONLY / STUB_OR_PLACEHOLDER / PARTIAL /
IMPLEMENTED_NOT_WIRED / IMPLEMENTED_AND_WIRED / EXPERIMENTAL / TESTED /
BENCHMARKED / DEMONSTRATED / LEGACY_OR_DEPRECATED / BROKEN / UNSAFE /
NOT_VERIFIED / NOT_APPLICABLE — these are NOT interchangeable; e.g. a
component can be TESTED through unit tests but NOT_BENCHMARKED, or
BENCHMARKED on authored corpora yet not INDEPENDENTLY VALIDATED).

---

## 1. Repository and Module Directory (execution paths first)

Root: `WebPent_UNIFIED/`. Package `src/webpent/` (~89 subpackages after
the UM-DR-29 dead-code disposition). Tests `tests/` (672 files, 8,711
collected; 8,702 passed / 7 skipped / 3 xfailed in the UM-DR-31 chunked
run over ALL test files — 50 new tests this window). Gates:
`frozen_modules.sha256` (639 pinned paths; DR-009 declared-refreeze
protocol, 6-path UM-DR-31 refreeze),
`docs/ACCEPTED_EXCEPTIONS_REGISTER.md` (+2 documented UM-DR-31
handlers), `docs/direct_io_inventory.json` (1,155 records).

| Module | Purpose | Key symbols | Callers → callees | Tests | Status |
|---|---|---|---|---|---|
| `graph/builder.py` | The production graph composer (45 real nodes + research_loop flag-gated) | `build_graph()`, flag-gated wires, `_umdr31_routes()` | CLI/workers → all nodes | test_vip_graph_wiring, seam suites, test_umdr31_research_loop_integration | IMPLEMENTED_AND_WIRED, TESTED |
| `state/state.py` | PentestState (288 channels: 147 merged / 141 last-write) | `PentestState`, `stateful_discovery` channel (UM-DR-28), the 20-key family spine contract + `coverage_gap_report` + `invariant_review` (UM-DR-30), `research_loop` (UM-DR-31, merge_dicts — the loop node is the sole writer) | builder, checkpoints | test_m1b_checkpoint_channel_matrix (6), test_umdr30_family_channel_contract (28), test_umdr31_research_loop_integration | IMPLEMENTED_AND_WIRED, TESTED; the silent-drop class closed family-wide (UM-DR-30) |
| `families/execution_node.py` | The wired causal family spine | `family_execution_node`, `wire_family_execution` | builder (behind `enable_family_execution_spine`) → validators, promotion | test_m3_family_qualification_seam, test_umdr28_campaign_stateful_e2e, test_umdr30_family_channel_contract | IMPLEMENTED_AND_WIRED, TESTED; full 20-key output contract declared and surviving (UM-DR-30) |
| `production/coverage_gap_report.py` | **UM-DR-30 runtime coverage gap map** | `build_coverage_gap_report`, `coverage_gap_report_node`, `wire_coverage_gap_report` | builder (behind `enable_coverage_gap_report`) → coverage_map, gap_detector, coverage_ledger | test_umdr30_coverage_gap_report (15) | IMPLEMENTED_AND_WIRED, CAMPAIGN_INTEGRATED (advisory, flag-gated fail-closed) |
| `business_logic/invariant_checker.py` + the fuzzer wiring | **UM-DR-30 advisory invariant review** | `InvariantChecker.check`, `_workflow_enrichment` wiring point | business_logic_fuzzer node → `invariant_review` channel (merge_lists) | test_umdr30_invariant_review_wiring (15) | IMPLEMENTED_AND_WIRED, CAMPAIGN_INTEGRATED (advisory, non-promoting; formerly a zero-importer orphan) |
| `production/adaptive_research.py` | **UM-DR-31 evidence-driven adaptive research loop** | `classify_coverage_status` (the R6 classification contract: 7 canonical classes + fail-closed `unknown_status`), `hypothesis_fingerprint` (R4: host-case-normalized, query-identity-preserving), `generate_research_hypotheses`, `research_loop_node`, `stateful_research_hints` (R3 scope filter + §6.1 coverage-surface hints) | builder (behind `enable_adaptive_research_loop`, fail-closed default False) → the coverage ledger projection, `invariant_review`, `workflow_observations` → the real hypothesis pool → the strategist; hints → execution_node → run_stateful_discovery (ordering only, same budget/scope) | test_umdr31_adaptive_research (60), test_umdr31_research_loop_integration (16), test_umdr31_campaign_e2e_ablation (8) | IMPLEMENTED_AND_WIRED, **CAMPAIGN_DEMONSTRATED** (four-arm ablation on a controlled live target; bounded 3×12; non-promoting by construction — the causal guard stays the sole confirmation authority) |
| `production/stateful_discovery.py` | **UM-DR-28 campaign integration** (UM-DR-31: optional `research_hints` — deterministic priority reordering within the same budget; operator-configurable `stateful_discovery_max_requests`, default 360) | `mine_probe_cases`, `CampaignProberClient`, `run_stateful_discovery` | execution_node → stateful_probe, transition_sources, findings | test_umdr28_stateful_discovery (15), E2E (10), test_umdr31_campaign_e2e_ablation | IMPLEMENTED_AND_WIRED, CAMPAIGN-INTEGRATED, Target-validated (authored targets) |
| `production/stateful_probe.py` | The bounded two-phase stateful prober | `StatefulCaseProber`, `make_observation(enrich=)`, `ProbeOutcome.evidence_trace` | stateful_discovery, benchmark runners → cqa_v2 guard | test_blind_v3_replica (20), test_transition_sources (27), umdr28 suites | IMPLEMENTED_AND_WIRED, TESTED, BENCHMARKED (fixtures) |
| `production/transition_sources.py` | Grammar-free transition discovery | `ObservedSurfaceSource`, `NameGrammarSource`, `observed_source_from_campaign_state` | stateful_discovery, probers → family_feeds | test_transition_sources (27) | IMPLEMENTED_AND_WIRED, TESTED, BENCHMARKED |
| `cqa_v2/causal_guard.py` | THE confirmation authority (frozen) | `guarded_causal_evaluate`, `_extract_context` (UM-DR-28 channel fallback) | all deterministic paths | guard suites + 47 byte-compat regressions | IMPLEMENTED_AND_WIRED, TESTED, adversarially pinned |
| `cqa_v2/representation_oracle.py` | **UM-DR-28 representation equivalence** | `canonical_representation`, `authorization_semantics`, `enrich_observation` | stateful_probe.make_observation → guard channels | test_umdr28_representation_oracle (23) | IMPLEMENTED_AND_WIRED, Target-validated (equivalence fixture) |
| `shared/family_feeds.py` | Observed-surface consolidation | `endpoint_inventory_from_state`, `multi_tenant_from_state`, `auth_flows_from_state` | execution_node, stateful_discovery, stateful_api | test_m3_family_qualification_seam | IMPLEMENTED_AND_WIRED, TESTED |
| `stateful_api/` | M5 planning engine | `operations_from_state`, `infer_dependencies`, `build_bola_plans`, `generate_sequences` | planners (advisory) | stateful_api suites (16+) | IMPLEMENTED_AND_WIRED (planning); live sequence execution deferred |
| `production/validators.py` | Canonical dispatch, 29 families | `run_validator`, `maybe_record_validator_outcome` | execution paths | validator suites, confusion matrix | IMPLEMENTED_AND_WIRED, TESTED, BENCHMARKED (lab) |
| `deception/` | Deception-resistant verifier | causal verifier, structural signatures | confirmation chain | 16 tests + benchmark | **Production-qualified** (24/24, blind 8/8) |
| `recon/identity_discovery.py` + `principal_provisioning.py` + `login_executor.py` | The r6c/r9 identity ladder | two-branch S1, rollup, validation ladder | graph, workers | r6/r9 suites | IMPLEMENTED_AND_WIRED, TESTED |
| `recon/autonomous_crawler.py`, `browser_crawler.py`, `browser_farm.py` | Crawling (robots double-gate; Playwright) | SSRF-guarded farms | graph recon | crawler + SSRF suites | IMPLEMENTED_AND_WIRED, TESTED |
| `jsintel/js_reversing.py` | esprima AST JS reversing | constant propagation, verified sinks | recon (flag ف3.2) | test_v25_javascript_intelligence | IMPLEMENTED_AND_WIRED, TESTED |
| `safety/agency.py`, `shared/rate_governor.py`, `approvals/` | Safety governors | ActionAuthority, kill-switch, tier 0–3 | every execution boundary | M2/M9 adversarial suites | IMPLEMENTED_AND_WIRED, TESTED |
| `memory/ab_lab.py` | The lesson A/B lab (atomic claims) | `tick()`, P1-02 claim, P1-08 reclaim | weekly canary | test_hardening_0330_b3 (P101–P108) | IMPLEMENTED_AND_WIRED, TESTED (P102 race documented UM-DR-28) |
| `appmodel/` | Organization→…→Observation target model | discovery confidence, attack-graph projection | planners | appmodel suites | IMPLEMENTED_AND_WIRED (planning inputs) |
| `reporter/` + `reporting/` | Findings → reports | POC recorder (`safe_artifact_stem`) | graph reporter | reporter suites | IMPLEMENTED_AND_WIRED, TESTED |
| `campaign/` (executor, worker, claims, leases) | Campaign runtime | workers, cross-process leases | operators | campaign suites | IMPLEMENTED_AND_WIRED, TESTED |

Deliberate non-entries (honesty): the archived prototypes
(`archive/pre_v10_prototypes/goed_v1`) are LEGACY_OR_DEPRECATED; the
lessons-v4 subsystem was deleted in the 0.29.0 G-1 window (skip-marked
tests document it).

## 2. Architecture and Engineering Assessment

- **Layer separation** — clean at the boundaries that matter:
  execution (executors) / confirmation (guard) / policy (safety) /
  persistence (stores). The confirmation layer has exactly ONE
  authority — the strongest possible cohesion for trust.
- **Modularity/coupling** — the family spine consumes feeds through
  `family_feeds` (no direct crawler coupling); the stateful stack is
  three composable modules (sources → probe → campaign integration).
  Known coupling debt: `execution_node.py` is large (676 lines) but
  additive-only by contract.
- **State architecture** — PentestState TypedDict with explicit
  channels; append-only via reducers where history matters
  (`findings`, traces); the R2-graph-03 class (undeclared keys
  silently dropped) is actively managed — UM-DR-28 declared its new
  channel and documented the family_* residual.
- **Error handling** — fail-closed defaults everywhere; the prober's
  transport errors end honestly (INCONCLUSIVE with block reasons);
  broad exceptions are registered and gated (P-1 hygiene).
- **Concurrency** — RLock + conditional-UPDATE claims in the A/B lab
  (P102 analysis UM-DR-28: the double-execution invariant is
  structurally sound; the concurrent loser's designed no-op is now
  documented); cross-process leases for campaigns.
- **Persistence** — per-workspace sqlite; redacting checkpoints
  (secret channels persisted empty — matrix-tested).
- **Observability** — node step traces, evidence traces (UM-DR-28),
  campaign summaries on declared channels, engagement audit chains.
- **Testability** — 8,661 tests; machine gates for drift classes
  (frozen bytes, exceptions, direct I/O); the freeze discipline makes
  regressions structurally loud.
- **Bottlenecks / failure points (engineering opinions, labeled as
  such)** — `execution_node.py`'s breadth; the family_* channel gap
  (CLOSED by UM-DR-30 — declared and surviving; the remaining gap is
  downstream consumption by replanning); benchmark author-bias (no
  in-repo cure — operator corpora).

## 3. AI Agent Architecture Assessment

- **Orchestrator** — LangGraph `build_graph()`; conditional routing
  after hypothesis/attack-graph nodes; super-step semantics used for
  additive wiring (the family node waits-then-feeds validator).
- **Nodes/edges** — 45 real nodes (builder-referenced) + the
  flag-gated `research_loop` node. Measured on the compiled graph
  (UM-DR-31.1 R10, the F13 counting convention made explicit):
  **54 registered nodes flag-off / 55 flag-on**, counting unique node
  names in `build_graph()` and EXCLUDING LangGraph's `__start__` /
  `__end__` bookkeeping nodes (56/57 if those are counted — the
  convention the UM-DR-31 audit used). Conditional-mapping overrides
  route six strategist entry
  points through the research loop when `enable_adaptive_research_loop`
  is on
  (validator — the post-execution feedback seam; causal_research;
  disclosed_report_intel ×2; attack_graph; vip_orchestrator;
  smart_campaigns_execution); flag-gated additions wire additively
  (no edge removals — zero-risk insertion pattern, tested per flag;
  the rabbit_hole loop-back is deliberately not redirected — that
  pass filters to RABBIT_HOLE-origin hypotheses only).
- **State schemas** — PentestState/UnifiedState; `stateful_discovery`
  declared UM-DR-28; `research_loop` declared UM-DR-31 (merge_dicts,
  sole writer).
- **Planner** — deterministic weighted ranking + coverage advisory
  (flag-gated); replan contract (REFUTED → replan-once, no
  re-exploitation) — TESTED; **UM-DR-31: the adaptive research loop
  feeds the planner** — signal inventory (the R6 classification
  contract: 7 canonical classes + fail-closed `unknown_status`) →
  deduplicated evidence-backed hypotheses (deterministic uuid5 ids +
  stable fingerprints; conclusively-rejected never repeated) in the
  real pool, ranked by the UNCHANGED strategist formula; the loop is
  bounded (3 iterations × 12 hypotheses, configurable, fail-closed on
  missing mandatory limits) and non-promoting by construction.
- **Validator agent** — deterministic dispatch (29 families) +
  post-P0 checks; the adversarial reviewer + self-verify wrap every
  promotion (only-downgrade / fail-closed).
- **LLM integrations** — multi-provider behind the ToolBoundary;
  structured outputs (pydantic); retries/recovery at the provider
  seam; spend caps; prompt-injection boundary documented
  (`docs/LLM_SECURITY_BOUNDARY.md`). The Charter §4.1 gate REFUSES
  the LLM hypothesis budget (recorded measurement below thresholds) —
  the refusal itself is the tested behavior.
- **Agent count discipline** — no speculative agents; UM-DR-27/28
  extended existing components (directive §8.1 consolidation rule).

## 4. AI Intelligence and Autonomy Evaluation Matrix

Legend: status uses the capability ladder; "Runtime call chain" cites
the production path (not the unit-test path).

| ID | Capability | Existence | Location / chain | Status | Evidence | What's still needed |
|---|---|---|---|---|---|---|
| AI-01 | Target understanding | Yes | recon→family_feeds→appmodel | IMPLEMENTED_AND_WIRED, TESTED | crawl suites, appmodel suites | richer non-HTTP surface types |
| AI-02 | Application modeling | Yes | `appmodel/` | IMPLEMENTED_AND_WIRED (planning) | appmodel suites | live-model refresh cadence |
| AI-03 | Context-aware reasoning | Yes | hypothesis contracts (preconditions/alternatives) | TESTED | M3 hypothesis suites | — |
| AI-04 | Hypothesis generation | Yes | `recon/hypothesis_generator.py` | IMPLEMENTED_AND_WIRED, TESTED | hypothesis suites | LLM-side currently gate-refused |
| AI-05 | Multi-step planning | Yes | planner + stateful probe (two-phase) | TESTED, BENCHMARKED (fixtures) | transition_sources suites | independent holdout |
| AI-06 | Dependency-aware planning | Yes | `stateful_api.infer_dependencies` (edges labeled `inferred`) | TESTED | stateful_api suites | live sequence execution (deferred owner) |
| AI-07 | Info-gain prioritization | Yes | planner factors | TESTED | planner suites | measured prioritization ablation |
| AI-08 | Attack-graph exploration | Yes | `attack_graph/` + chained_exploits | TESTED | attack-graph suites | deeper composition benchmarks |
| AI-09 | Tool selection | Yes | validator dispatch by vuln_class | TESTED | dispatch suites | — |
| AI-10 | Context/memory management | Yes | attack memory, decision log, embeddings (redacted) | TESTED | memory suites | — |
| AI-11 | Feedback-driven adaptation | Yes | refutation learning; control rotation (UM-DR-28) | TESTED | refutation suites; umdr28 | measured cross-target learning |
| AI-12 | Backtracking/alternative paths | Yes | replan-once contract; control rotation | TESTED | hunter_graph suites | — |
| AI-13 | Failure recovery | Yes | fail-soft discovery; transport-error honesty; P1-08 reclaim | TESTED | umdr28 suites; ab_lab | — |
| AI-14 | Autonomous replanning | Yes (bounded) | hunter loop | TESTED | replan suites | — |
| AI-15 | Evidence-based decisions | Yes | the causal guard (only authority) | TESTED, adversarially pinned | guard + deception suites | — |
| AI-16 | Rational stopping | Yes | budgets (per-case, whole-run), smart-stop loops | TESTED | budget suites | — |
| AI-17 | Multi-agent collaboration | Partial (by design) | planner/hunter/validator roles | TESTED | graph suites | deliberate: no agent sprawl |
| AI-18 | Autonomous execution within authorization | Yes | scope law + ActionAuthority + governors | TESTED (adversarial) | M2/M9 suites | — |
| AI-19 | Execution reproducibility | Yes | deterministic probes; evidence traces; ProofBundle replay | TESTED | replay suites | — |
| AI-20 | Human intervention management | Yes | HITL interrupts; approvals tiers | TESTED | M9 suites | — |

Not claimed: learning that generalizes from history alone (attack
memory informs advisories; no cross-target autonomous policy change is
claimed or wired — NOT VERIFIED beyond the advisory seam).

## 5. Complete Bug Hunting Capability Inventory

Legend per family: detector path · validation mechanism · status.
"Benchmarked (lab)" = authored corpora; **no family is INDEPENDENTLY
VALIDATED** (holdout NOT AVAILABLE — the global honesty boundary).

### A. Injection
SQLI / BLIND_SQLI (`production/validators.py` + payload engine;
response-differential + time-based causal with negative controls) —
Proven (lab). COMMAND_INJECTION (output-marker causal) — Proven (lab);
non-echo variants OOB-dependent. SSTI, XXE/XXE_OOB (expression/entity
causal) — Proven (lab); XXE_OOB needs OAST reachability. NOSQL_INJECTION,
HEADER injection — registered validators, Partial (corpus depth).
LDAP/XPath/HTTP-request-smuggling: REQUEST_SMUGGLING enum + validator
exists (V10 P0-1) — Partial; LDAP/XPath — NOT claimed beyond generic
payload paths (recorded Absent-by-depth).

### B. XSS
Reflected/stored via reflection differential with context checks —
Proven (lab). DOM-XSS via the browser farm — Partial (browser-dependent).

### C. Authentication & sessions
AUTH_BYPASS / JWT_MANIPULATION / JWT_WEAKNESS / JWT_KEY_CONFUSION
(token-tamper differentials; weak-secret candidates redacted at
checkpoints) — Proven (lab). WEAK_SESSION, BRUTE_FORCE, CAPTCHA
detectors (V10 P1 set) — registered, Partial. Password-reset /
account-recovery / MFA-specific flows — NOT_APPLICABLE to current
corpora (recorded Absent-by-depth; identity ladder is the path in).

### D. Authorization & access control
**The flagship class.** IDOR/BOLA: (1) M5 two-identity differential
plans (randomized-id negative controls) — planning Proven, live
execution deferred; (2) **the campaign-integrated stateful discovery
(UM-DR-28): structural read-triples + observed transitions + causal
guard + representation oracle — Target-validated on authored targets
(3/3 E2E; 73/73 fixtures at 0 FP)**. PRIVILEGE_DIFFERENTIAL,
MASS_ASSIGNMENT — registered validators, Partial. Tenant isolation —
TenantBoundaryDetector on family feeds (explicit-only multi-tenancy),
Partial. Horizontal/vertical escalation — via the alias/effective_as
semantics (UM-DR-28, AUTH_BYPASS), Proven (lab).

### E. Server-side
SSRF/BLIND_SSRF (callback + response causal; egress policy) — Proven
(lab). LFI/RFI/PATH_TRAVERSAL/FILE_UPLOAD (content signatures +
controls) — Proven (lab). DESERIALIZATION — registered, Partial.
RCE — via command-injection class (Proven, lab).

### F. API security
REST: the full stateful stack (contracts ingestion → dependency model
→ bounded sequences → differentials). GRAPHQL_* (introspection/depth/
field-suggestion/batching) — registered UM-DR-26, Partial. BOLA/BFLA:
BOLA via the stateful path (see D); BFLA — Partial (role-differential
plans). Excessive data exposure / rate-limit enforcement —
INFO_DISCLOSURE + rate-limit validators, Partial.

### G. Business logic
BUSINESS_LOGIC / RACE_CONDITION (invariant differentials; burst
detection with committed side-effect counts) — Partial→Strong on
authored workflows; the source-driven mechanism is the generalization
path (Document B §7). Workflow bypass / state-transition abuse —
**the blind_v3 mechanism classes: 1.0/1.0 on three fixture populations
(replica, generalization, equivalence)** — Proven (lab).
Price/quantity manipulation — scenario-bounded, Partial.

### H. Client-side & browser
CORS, CSP, clickjacking, open redirect (M2 adversarial corpus) —
Open redirect Proven (corpus-tested); CSP/CORS validators — Partial.
DOM-clobbering — registered (deep/), Partial.

### I. Configuration & exposure
Security headers, debug-endpoint exposure, sensitive-info patterns
(INFO_DISCLOSURE) — Partial (bounded pattern sets). TLS-level checks —
Absent by scope (network layer).

### J. Recon & attack-surface discovery
Endpoint discovery (crawl + OpenAPI + forms), JS shadow endpoints
(ق8), parameter discovery — IMPLEMENTED_AND_WIRED, TESTED. Domain/
subdomain/asset/port discovery — external-tool adapters exist;
NOT_VERIFIED in-repo without those tools. Technology fingerprinting —
Partial. Continuous monitoring — NOT claimed.

### K. Blind & out-of-band
BLIND_SQLI (time-based), BLIND_SSRF (callback), OAST correlation node
(per-hypothesis nonce-bound sessions; CANDIDATE-only findings) — Proven
(lab) with OAST reachability caveat. Blind XSS — browser-farm
dependent, Partial.

### L. Additional implemented classes
Deception resistance (cross-cutting verification hardening) —
**production_qualified**. CACHE_POISONING / PROTOTYPE_POLLUTION
(UM-DR-26 registration fix) — Partial. Representation-equivalence /
body-represented authorization semantics (UM-DR-28) — Proven (lab:
0.0→1.0, 0 FP). CVE/N-day matching — advisory-only (ق6), NOT a
detection claim.

## 6. Quantitative capability summary (the honest numbers)

| Population | Mode | TP/FP/FN/TN | Recall | Precision | Evidence |
|---|---|---|---|---|---|
| Original blind_v3 (recorded; target ABSENT) | 3-GET, LLM off | 10/5/63/42 | 0.1370 | 0.6667 | `reports/goed_v1_8_4/differential_v184.json` |
| Same, LLM on | causal-feedback loop | — | 0.3425 | 0.5556 | same file |
| Replica (authored) | stateful prober | 73/0/0/47 | 1.0 | 1.0 | `reports/qualification/blind_v3_replica_*.json` |
| Generalization fixture (authored; unknown grammar) | observed-source | 73/0/0/47 | 1.0 | 1.0 | `.../blind_v3_generalization_*.json` |
| — control: legacy grammar | name-guessing | — | +0.0000 | — | same |
| Equivalence fixture (authored; body semantics) | legacy obs + source | 0/0/73/47 | 0.0 | — | `.../umdr28_equivalence_measurement.json` |
| — oracle obs + source | full stack | 73/0/0/47 | 1.0 | 1.0 | same |
| Campaign E2E (authored live target) | campaign-integrated | 3/0/0/4 (+2 scope-refused) | 1.0 | 1.0 | `.../umdr28_campaign_e2e.json` |
| Deception corpus | verifier | 24/0/—/— | — | 1.0 (rejection) | `reports/deception/benchmark_v1.json` |

Populations are NEVER merged (the genealogy rule,
`docs/engineering/M10_RECALL_RCA.md` §1). Request economics: 8.9
req/case (generalization), ≤30/case hard cap, ≤360/campaign-run cap —
all enforced and reported.

## 7. Engineering records and change discipline

- `DRIFT_REGISTER.md` — UM-DR-01…31 (UM-DR-31: the evidence-driven adaptive research loop — the advisory signals now CONSUMED by the real planner, six strategist entry routes redirected through the bounded research_loop node, priority hints ordering the stateful budget, four-arm ablation pinned, 6-path DR-009 refreeze, 50 new tests; M10 stays closed — holdout BLOCKED_EXTERNAL_DEPENDENCY; UM-DR-29: the dead-code disposition
  — the Ultimate-Plan-proposal-4 archive physically completed, 7
  frozen-but-dead packages archived, the false goed_v1 core-engine
  docstrings and the nonexistent BUILD_INFO.git_head corrected, the
  direct-I/O pin finally realized; UM-DR-30: the capability-integration
  window — the family spine's 20-key channel contract declared (the
  silent-drop class closed family-wide), the coverage gap map and the
  invariant review campaign-wired (both advisory, both
  precision-preserving by construction), run_campaign.sh rebuilt on the
  real CLI contract, the langgraph CVE backlog closed as
  resolved-by-pinning with dnspython 2.8.0→2.9.2 remediated; M10 stays
  closed — holdout and competitor access BLOCKED_EXTERNAL_DEPENDENCY).
- `BUILD_INFO.json` — suite counts with evidence statements (the
  strengthened window-name/ledger-existence invariant,
  `tests/test_umdr24_release_gate_compliance.py`).
- Machine gates: frozen-module (639), broad-exception, direct-I/O
  (1,149 records), coverage ratchet, SBOM/CVE gate, release packaging
  (14-gate chain, `docs/engineering/RELEASE_PROCESS.md`).
- `docs/engineering/UMDR30_FEATURE_QUALIFICATION_MATRIX.json` — the
  per-capability evidence matrix (status vocabulary enforced; no
  integration claim without runtime evidence; supersedes the UMDR29
  matrix — coverage_intelligence and business_invariant reasoning
  promoted to CAMPAIGN_INTEGRATED with this window's wiring evidence).
- `docs/engineering/UMDR30_RELEASE_READINESS_MATRIX.json` — the §19
  release-acceptance record (per-criterion PASS/WITH-NOTES verdicts,
  counts, external-dependency register).

— End of WEBPENT_ENGINEERING_REFERENCE (Document 2) —

## 8. UM-DR-31 addendum — the research-loop engineering contract

**Feature flags (defaults are fail-closed):**

| Flag | Default | Effect when ON | Effect when OFF |
|---|---|---|---|
| `enable_adaptive_research_loop` | `False` | the `research_loop` node exists and six strategist-bound conditional routes are redirected through it (`research_loop → strategist`); the node re-checks the flag at runtime (double-gate) | neither the node nor the edge exists; every conditional mapping keeps its original strategist target — the graph shape is byte-comparable |
| `max_research_iterations` | `3` (clamp 1..16) | hard cap on working iterations; beyond it, honest `capped` pass-throughs | n/a — mandatory: an invalid/missing value fails the node closed to a no-op |
| `max_research_hypotheses_per_iteration` | `12` (clamp 1..64) | hard per-iteration cap on new hypotheses (info-gain priority order; `capped` reported in telemetry) | n/a — mandatory, same fail-closed rule |
| `stateful_discovery_max_requests` | `360` (1..3600) | the whole-discovery request budget the family execution node passes to `run_stateful_discovery` | n/a — default keeps the UM-DR-28 behavior exactly |

**Research-loop lifecycle (one bounded iteration):**
signal inventory (read-only; coverage ledger projection classified per the R6 contract — 7 canonical classes + fail-closed unknown_status — + invariant candidates + allowed-scope, admission-filtered workflow boundaries) → hypothesis generation (deterministic templates; `HypothesisOrigin.COVERAGE_GAP` / `.INVARIANT`; full research-contract fields; deterministic `uuid5` ids from stable fingerprints) → pool-aware dedup (open ⇒ suppressed_open; closed ⇒ suppressed_closed — conclusively-rejected and promoted hypotheses are NEVER regenerated; an actionable invariant candidate covers its source observation) → pool injection (`merge_hypotheses` upsert) → the strategist's UNCHANGED ranking/promotion gates → the standard authorized execution path, plus priority hints for the stateful discovery (ordering only, within the same budget/scope/authority) → causal verification (`cqa_v2.guarded_causal_evaluate`, unchanged, sole authority) → ProofBundle + ledger updates → the next iteration consumes the updated state.

**Evidence lineage:** `origin_detail` carries `umdr31_research_loop fp=<fingerprint> signal=<signal_id>`; `evidence_refs` carry ledger keys / observation fingerprints; the telemetry channel records per-iteration detail, cumulative counters, generated hypothesis ids, stateful priority directories and the named confirmation authority.

**Test commands:**

```
python3 -m pytest tests/test_umdr31_adaptive_research.py -q            # 27 unit
python3 -m pytest tests/test_umdr31_research_loop_integration.py -q    # 15 integration
python3 -m pytest tests/test_umdr31_campaign_e2e_ablation.py -q        # 8 e2e + ablation
python3 -m pytest tests/test_frozen_module_gate.py -q                  # 643 (6 documented re-pins)
```

**Ablation artifact:** `reports/qualification/umdr31_ablation.json` (four arms, identical conditions, honest population labeling). **Qualification:** `docs/engineering/UMDR31_FEATURE_QUALIFICATION_MATRIX.json`; **readiness:** `docs/engineering/UMDR31_RELEASE_READINESS_MATRIX.json`; **execution report:** `docs/engineering/UMDR31_EXECUTION_REPORT.md`.

# M3_PHASE_REPORT.md — M3 (Research Brain & Attack Surface Model)

**Phase:** M3 of the CANONICAL_PHASE_REGISTRY (Part 4 §5 — P1).
**Date closed:** 2026-11-06 (UTC).
**Windows:** DRIFT_REGISTER UM-DR-16 (window 1, research wiring — closed 2026-11-05) + UM-DR-17 (window 2, the remaining scope — closed 2026-11-06).
**Baseline entering window 2:** post-UM-DR-16 tree; frozen authority manifest (13 files) untouched; frozen-module gate 661 green.
**Refreezes (window 2, in order, each tests-before-refreeze with post-write self-check):**
`scripts/refreeze_manifest_m3_js_ast_reversing.py` (2 declared), `scripts/refreeze_manifest_m3_family_seam.py` (3 declared), `scripts/refreeze_manifest_m3_identity_runner.py` (2 declared), `scripts/refreeze_manifest_m3_oast_resume.py` (2 declared), `scripts/refreeze_manifest_m3_attack_graph_evidence.py` (1 declared). The frozen-gate test's baseline-drift expectation gained `M3_WINDOW2_20261106_THAW_PATHS` (exactly `src/webpent/agents/attack_graph/agent.py` — the only re-pinned path predating the pre-unfreeze baseline; all other re-pins were covered by UM-DR-16's set or postdate the baseline).

---

## 1. Window 1 recap (UM-DR-16, 2026-11-05)

ق6 cve_advisory→target_understanding + ق8 api_surface_shadow→hypotheses/planner wiring (flag-gated, fail-soft, provenance-preserved), the M3 hypothesis-record contract fields (preconditions/alternatives/expected_behavior/negative_control/info_gain/risk), and the Charter §4.1 LLM qualification gate (recall≥0.5 ∧ precision≥0.7 ∧ >deterministic-0.137-baseline ∧ ≥30 samples ∧ fresh — fail-closed budget refusal). Evidence: `tests/test_m3_research_wiring.py` (15). Full record: DRIFT_REGISTER UM-DR-16.

## 2. What window 2 (UM-DR-17) delivered

### 2.1 — Fix ف3.2: real JS reversing (the 2-regex analyzer replaced)

`jsintel/js_reversing.py` (NEW, outside the frozen gate) — the esprima AST reverser:

- **Structural recall the regex engine cannot reach:** multi-level constant propagation (`const base="/api/v2"; const users=base+"/users"; fetch(users)` → `GET /api/v2/users` — the legacy engine provably misses this, pinned in the tests), template literals with dynamic segments rendered as `{expr}` placeholders, axios/jQuery config-object call forms (`axios({url, method})`, `$.ajax({...})`), XHR `.open` with constant concentration.
- **Structural precision the regex engine cannot reach:** call-site/assignment-verified sinks — code inside comments produces NOTHING (the regex engine's documented false positive, eliminated), `String.prototype.replace` is not `location.replace` (receiver-verified), `el.innerHTML = x` is an assignment not a word in prose.
- **Graceful degradation:** esprima unavailable → regex fallback + `js_ast_unavailable_regex_fallback`; unparseable source (minified-odd/TS/JSX/corrupt) → regex fallback + `js_ast_parse_failed_regex_fallback`. The frozen regex engine stays the safety net, never the primary.
- **Same typed output and safety contract:** `JavaScriptIntelligence` only, in-scope-only, redacted URLs (sensitive query values `[REDACTED]`), hashed secret values, same caps.
- **Wiring:** `enable_js_ast_reversing` (fail-closed default False) + the frozen agent's per-asset `_analyze_asset` dispatcher — flag off is byte-identical to the legacy engine (test-pinned by full-model-dump equality).
- **Tests:** `tests/test_m3_js_ast_reversing.py` (22) — incl. the recall-proof (AST finds what regex cannot) and the precision-proof (regex's comment false-positive eliminated).

### 2.2 — The tenant_isolation qualification seam (M1b residual ②)

M0's CAPABILITY_WIRING_MAP rows closed: `wire_family_execution()` had NO caller from the builder, and the tenant_isolation/multi_step_auth analyzers waited for channels nobody populated (the ب6-pattern).

- `shared/family_feeds.py` (NEW): derives the family analyzers' vocabulary from REAL PentestState channels — `endpoint_inventory_from_state` (openapi_routes → surface_records → forms → ق8 shadow_endpoints → crawled URLs, deduped, bounded, provenance-per-entry), `multi_tenant_from_state` (EXPLICIT-only: declared on target/state/engagement — never inferred), `auth_flows_from_state` (only from profiles with real step lists; secrets never surface).
- Frozen `families/execution_node.py` (declared): the node consults the adapter when direct channels are absent — derivation observable via `family_feeds_derived`.
- Frozen `graph/builder.py` (declared): `_family_execution_enabled()` + flag-gated `wire_family_execution(graph)` — the causal spine (six passive analyzers incl. tenant_isolation, deterministic validators, ProofBundle sealing, promotion) gains its first production-builder caller, additively (sandbox→validator direct edge stays).
- Flag: `enable_family_execution_spine` (fail-closed default False).
- **Tests:** `tests/test_m3_family_qualification_seam.py` (11) — incl. the ب6-closure proof (real-state-only input now produces tenant_isolation candidates where it previously returned `no_input_surface`) and both builder-compile directions.

### 2.3 — ق7: identity_orchestrator runner injection

M0 FEATURE_DELTA ق7: «غير موصول — يحتاج حقن session_factory من runner».

- `auth/worker_session_factory.py` (NEW): `vault_session_factory` (reauth-vault-backed; STRICT role match on the sealed entry's own role field — the review caught and a test pins that a fallback scan over sealed profiles would hand one role another role's session: a cross-role leak, refused), `profiles_from_state` (handle-only conversion), `build_worker_identity_orchestrator` (the runner bundle: orchestrator + factory + report-safe provenance).
- Frozen `workers/pentest_worker.py` (declared): after the vault-sealing block, flag-gated construction + `ensure_sessions()` + `identity_session_provenance` attached to the task result. Worker default: cookie-restore only (`login_executor=None`); fail-soft.
- Flag: `enable_identity_orchestrator` (fail-closed default False).
- **Tests:** `tests/test_m3_identity_orchestrator_runner.py` (12) — incl. the flag-off structural-absence test through the real `run_pentest_task.run` entry and the flag-on integration with a stubbed graph.

### 2.4 — OAST + campaign-resume production wiring

M1a deferral: "OAST/`enable_campaign_resume` production-graph wiring → M3 — needs node patterns outside the frozen builder; flags now exist fail-closed". Both engines shipped implemented-and-tested with ZERO production consumers.

- `graph/oast_nodes.py` (NEW): `oast_correlation_node` — arms one OAST session per OPEN hypothesis (terminal-status hypotheses excluded), polls the CONFIGURED provider, emits **candidate findings only** (the bridge's CandidateOnlyRule is structural: no verdict field, `requires_validator=True` pinned). Local provider default ⇒ honest `provider_unavailable` (a graph node never silently spawns a network listener); no engine secret ⇒ `bridge_secret_unavailable` (unbound nonces would let forged callbacks correlate — refused). `wire_oast_correlation`: post_exploitation→oast_correlation→rabbit_hole additive-only, direct edge stays.
- `production/campaign_lifecycle.py` (NEW): the worker-level context — `mark_campaign_interrupted` (flag-gated marker + state fingerprint), `campaign_resume_decision` (the redelivery gate: fresh marker + retry budget), `record_probe_executed`/`probe_already_executed` (bounded ledger, engagement-scoped), `campaign_backoff_seconds`, `clear_campaign_interrupt`.
- Frozen `workers/pentest_worker.py` (declared): the soft-timeout handler marks `soft_time_limit` (resumable per the package's reason vocabulary), the recursion-limit handler marks `recursion_limit` (forensic-only — auto-resuming into the same loop would be a bug, and the vocabulary deliberately excludes it), the terminal exit clears the marker (a stale crash mark can never auto-resume a finished engagement).
- Frozen `graph/builder.py` (declared): `_oast_enabled()` + flag-gated `wire_oast_correlation(graph)`.
- Flags: `enable_oast`, `enable_campaign_resume` (both declared M1-C; both still fail-closed default False — no settings change this window).
- **Tests:** `tests/test_m3_oast_campaign_resume_wiring.py` (15) — incl. nonce-bound correlation vs forged foreign-host callbacks, the additive builder wiring both directions, the full lifecycle roundtrip (flag-inert default, marker+decision+budget, ledger dedup, bounded monotone backoff), and the worker source-level contract.

### 2.5 — Attack-graph evidence-edge enrichment

Registry acceptance: "every attack-graph edge evidence-backed".

- `shared/attack_graph_evidence.py` (NEW): the post-pass over `build_attack_graph`'s output — every edge gets `metadata.evidence_status` ∈ {backed, enriched, unbacked}; empty edges are backfilled ONLY from real evidence (finding pointer + sealed `evidence_hash`, hypothesis `evidence_refs`, endpoint nodes' observation refs with generic sentinels excluded); the unbacked count is accounted in `coverage_gaps` as `attack_graph_unbacked_edges:<N>` (drop-unbacked optional); an `evidence_edge_summary` block counts each class. Fail-soft (any error returns the input unchanged).
- Frozen `agents/attack_graph/agent.py` (declared): the node runs the pass after `build_attack_graph`.
- **Tests:** `tests/test_m3_attack_graph_evidence_edges.py` (8) — incl. the acceptance predicate on a fully-evidenced graph and the honest-unbacked accounting on an unevidenced one.

### 2.6 — The appmodel greenfield

Part 4 §5: "appmodel relations (Organization→…→Observation) with discovery confidence · attack-graph abstraction over relational truth (no Neo4j without measurement)".

- `appmodel/` (NEW package, outside the frozen gate): typed entities (Organization/Tenant/Application/Endpoint/Workflow/Identity/Observation), typed relations (contains/hosts/exposes/performs/authenticates_as/observed_on/reachable_from), `DiscoveryProvenance` (declared/observed/inferred) with deterministic per-provenance confidences, endpoint-checked relations (a relation to an unknown entity is refused), re-observation merging (stronger provenance wins, refs merge).
- `appmodel/builder.py`: derives the spine from REAL channels (engagement context → org/tenant declared; crawled_data → applications/endpoints observed; identity_profiles → identities; mental-model nodes → observations attached to matching endpoints) with honest coverage gaps when channels are absent.
- `to_attack_graph_projection()`: speaks the frozen AttackGraph vocabulary (kind-mapped nodes, evidence-carrying edges — an appmodel edge is evidence-backed by construction or it does not exist); `merge_appmodel_into_attack_graph` is additive (own id space, nothing replaced).
- **No graph database** — structural test pins no driver imports/URIs; persistence is a measured later decision.
- **Tests:** `tests/test_m3_appmodel.py` (10).

### 2.7 — The blind_v3 qualification harness (the corpus run)

UM-DR-16 built the Charter §4.1 gate with no runner; the registry named the gap: "the corpus harness run is the next step".

- `production/hypothesis_qualification_harness.py` (NEW): the blind_v3 manifest contract (`load_blind_v3_ground_truth` — shape-validated fail-closed), producer measurement (`measure_producer` — TP/FP/FN through the REAL gate; producer crashes counted honestly as not-flagged), a deterministic verdict store (`save_verdict`/`load_latest_verdict`) the freshness gate consumes, and `replay_deterministic_baseline` — re-reads the RECORDED blind_v3 mode_a metrics from `reports/goed_v1_8_4/differential_v184.json`, cross-checks them against the charter's pinned constants (drift = ValueError: the documented baseline and the live gate can never silently drift apart), and replays them through the gate.
- `scripts/run_hypothesis_qualification.py` (NEW CLI): `--manifest <path> --producer-module module:callable` measures any producer; `--replay-baseline` replays the recorded baseline. **The baseline replay was EXECUTED** (this closure): sample 120, tp=10 fp=5 fn=63, recall 0.1370, precision 0.6667 — verdict REFUSED (recall_below_threshold + precision_below_threshold + recall_not_above_deterministic_baseline), budget REFUSED. The deterministic engine is the baseline; the gate refuses it by construction, exactly as designed.
- **Tests:** `tests/test_m3_qualification_harness.py` (10) — incl. the end-to-end runner subprocess test and the drift-detection test.

## 3. Acceptance vs the registry

| Registry acceptance (Part 4 §5) | Status |
|---|---|
| appmodel relations (Organization→…→Observation) with discovery confidence | **delivered** (§2.6) |
| hypothesis records (preconditions, alternatives, expected behavior, negative control, info-gain/cost/risk) | **delivered** (UM-DR-16 window 1) |
| attack-graph abstraction over relational truth (no Neo4j without measurement) | **delivered** (§2.6 projection + structural no-DB test) |
| LLM structural hypothesis generation per Charter §4.1 (recall≥0.5/precision≥0.7 gate before budget expansion) | **gate delivered + harness run** (UM-DR-16 + §2.7); no LLM producer exists yet — the gate pins the contract BEFORE any such path is built (by design) |
| wiring of ق6 (cve_advisory→target_understanding) and ق8 (api_surface_shadow→planner hypotheses) | **delivered** (UM-DR-16 window 1) |
| real JS reversing replacing the 2-regex analyzer (Fix ف3.2) | **delivered** (§2.1) |
| multi-step lab scenarios discovered AND proven; recall/precision vs deterministic baseline 0.137 measured on TEAM1 fixtures | **measurement harness delivered and the recorded 0.137/0.6667 baseline replayed live through the gate** (§2.7); live lab-scenario discovery campaigns are M11's benchmark scope (the corpus is an operator-supplied external input — the harness is the wiring) |
| every attack-graph edge evidence-backed | **delivered** (§2.5 — per-edge evidence_status + honest unbacked accounting) |

Deferred with owners (nothing silently dropped):
- Live Juice-Shop/crAPI lab runs + per-family metrics + qualification labels → **M11** (Benchmarking & Research Qualification — the phase that owns corpora, blind holdouts and the weekly runs; the M3 harness is its measurement entry point).
- Blind-deception fixtures (generic 200s, decoys, WAF pages) → **M6** (Target-Deception Resistance).
- LLM structural hypothesis producer itself → gated behind the Charter §4.1 qualification (recall≥0.5 ∧ precision≥0.7 ∧ >baseline on ≥30 fresh samples); the deterministic engine remains the only producer until measured otherwise.

## 4. Gate evidence at closure

- **Frozen-module gate:** 661 passed (five refreezes, 10 declared frozen changes total in window 2, each with tests-before-refreeze and post-write self-check; the baseline-drift expectation registered `M3_WINDOW2_20261106_THAW_PATHS`).
- **Combined M3 suites + frozen gate:** 764 passed (test_m3_research_wiring 15 + js_ast 22 + family seam 11 + identity runner 12 + oast/resume 15 + attack-graph evidence 8 + appmodel 10 + qualification harness 10 + frozen gate 661 — collected as one run, 0 failures).
- **Test-count gate:** 8,420 ≥ floor 8,115 (`scripts/verify_test_count.py` — OK).
- **Coverage ratchet:** 4.27% ≥ 4.07% floor (`scripts/coverage_ratchet.py --scope ...` — OK, scoped per the M1-C configuration).
- **Authority manifest:** `docs/integration/WEBPENT_AUTHORITY_MANIFEST.json` untouched (13 files) — verified by the frozen gate's authority checks.

## 5. Security review notes (window 2)

- The ق7 review caught a cross-role session leak in the factory's first draft (fallback scan over sealed profiles): fixed to STRICT own-role matching, pinned by test.
- The OAST node refuses to correlate without an engine-held HMAC secret (unbound nonces = forgeable evidence) and never spawns a listener in the local default.
- The campaign-resume marker vocabulary deliberately excludes recursion_limit from auto-resumable reasons (auto-resuming into the same loop would be a bug); HITL pauses never write markers (the signed-capability path owns those).
- `multi_tenant_from_state` is explicit-only: a fabricated tenant boundary would fabricate candidates.
- The AST reverser inherits the frozen engine's redaction helpers (same-origin gate, `[REDACTED]` query values, hashed secrets) — the module never re-implements redaction.

— End of M3_PHASE_REPORT.md —

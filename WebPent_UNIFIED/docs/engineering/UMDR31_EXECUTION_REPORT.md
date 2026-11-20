# UM-DR-31 Execution Report — Evidence-Driven Adaptive Research Loop

**Window:** UM-DR-31 · **Version:** 0.37.0 · **Date:** 2026-11-07
**Baseline:** v0.36.0 / UM-DR-30 (HEAD `97c4931`, working tree clean, BUILD_INFO suite_count 8,661)
**Directive:** "Transform WebPent from a collection of partially connected discovery and analysis capabilities into a bounded, evidence-driven, adaptive vulnerability research system."

---

## 1. Baseline verification (directive §1)

Independently verified before any source change — the UM-DR-30 report was NOT trusted on faith:

| Check | Verified result |
| --- | --- |
| Git HEAD / branch | `97c4931` on `main`, clean working tree |
| Version SSOT | `pyproject.toml` = `src/webpent/__init__.py` = `Dockerfile` = 0.36.0 |
| BUILD_INFO | suite_count 8,661 = actual collection 8,661; git_head `5b73ee4` (the documentation-complete head; the code head `a2e05a3` recorded in the umdr30 record) |
| Frozen manifest | 639 entries; frozen gate 641/641 passed |
| UM-DR-30 gates | coverage_gap_report 15 + invariant_review 15 + family channel contract 20 + stateful 23 = 73 passed |
| Compliance gates | packaging + direct-I/O (1,149 records) + broad-exception + release compliance = 20 passed |
| Environment | Python 3.12.16, pydantic 2.12.5, langgraph installed, `import webpent` OK |

**Reconciliation:** none required — the reported UM-DR-30 state matched the repository exactly. The baseline is reproducible (documented commands re-run green before the first edit).

**Baseline preservation:** v0.36.0 / UM-DR-30 treated as immutable; the release archive `WebPent_UNIFIED_v0.36.0_UMDR30.zip` and its recorded hashes are untouched. All UM-DR-31 changes are additive and flag-gated (§3 below); flag-off keeps the graph shape byte-comparable and the stateful behavior byte-stable.

## 2. The gap this window closes (directive §2)

UM-DR-30 wired the coverage gap map and the invariant review as **advisory producers**: their output landed on declared channels, but **no consumer changed a research decision** — the honest qualification matrices recorded both as advisory/CAMPAIGN_INTEGRATED. That is exactly the "another node that produces a report nobody consumes" anti-pattern the directive names.

UM-DR-31 closes the loop as an **operational data flow inside the production campaign graph**:

```
recon/discovery observations (campaign state)
  → research signal inventory        (adaptive_research: six-way classification)
  → adaptive hypothesis generation   (deterministic templates + fingerprints + dedup)
  → the REAL hypothesis pool         (state["hypotheses"], merge_hypotheses upsert)
  → the REAL strategist planner      (ranking + promotion gates — UNCHANGED)
  → the REAL authorized execution    (payload_generator → execution_sandbox; family
                                      execution spine → stateful discovery with
                                      the planner's priority hints)
  → causal verification              (cqa_v2.guarded_causal_evaluate — UNCHANGED,
                                      sole confirmation authority)
  → ProofBundle + coverage ledger updates
  → the NEXT research_loop invocation consumes the UPDATED state
```

The output of each stage demonstrably influences the next: the signal inventory changes which hypotheses are generated (integration tests), the enriched pool is the strategist's ranking input (the planner's own pass reports it), the research hints change which stateful cases the budget reaches first (the ablation's measured delta), and execution outcomes change the next research decision (the feedback test).

## 3. Changes implemented

### 3.1 New module — `src/webpent/production/adaptive_research.py` (non-frozen)

The research loop core. Responsibilities, inputs/outputs, integration points:

- **`research_signal_inventory(state)`** — read-only signal classification: (a) the shared coverage-ledger projection (the SAME code path the UM-DR-30 gap report uses — consistency by construction) classified six ways: observed-not-tested / tested-inconclusive / blocked-operational (actionable) vs blocked-policy / non-actionable-validator / tested-rejected / confirmed (never actionable); (b) the invariant review channel (actionable: `authorization_context_must_be_present` → IDOR probe, `state_must_progress_or_reject_replay` → business-logic probe; `out_of_scope_transition_must_not_be_processed` → recorded as a scope violation, **never** a hypothesis); (c) workflow observations with cross-identity / role-scoped / object-scoped boundaries, allowed scope only. Unmapped ledger classes are recorded, never guessed. No target context ⇒ fail-closed to zero.
- **`hypothesis_fingerprint(...)`** — stable sha256 over canonical JSON of (normalized target, vuln class, objective key, sorted principals, sorted preconditions, sorted state keys). Security-relevant differences NEVER merge (unit-pinned); cosmetic differences DO.
- **`generate_research_hypotheses(state, max_new)`** — deterministic templates → ordinary `Hypothesis` citizens (new origins `coverage_gap` / `invariant`) with the full research contract (preconditions, expected_behavior, negative_control, alternatives, info_gain, risk, estimated_cost, evidence_refs, origin_detail carrying the fingerprint). Deterministic `uuid5` ids (the workflow-understanding convention) make pool upsert idempotent. Dedup: open pool entries are not duplicated; **conclusively-rejected (resolved_false / abandoned) and promoted entries are never repeated**. Semantic dedup: an actionable invariant candidate covers its source observation's boundary signal. Deterministic priority: info-gain prior desc, stable signal order; the per-iteration cap is reported, never silently exceeded.
- **`research_loop_node(state)`** — the LangGraph node. Double-gated fail-closed (builder wiring + runtime re-check of flag AND mandatory limits — invalid limits ⇒ no-op). Bounded by `max_research_iterations` (default 3) × `max_research_hypotheses_per_iteration` (default 12); beyond the cap an honest pass-through (`capped` telemetry). Fail-soft on internal errors (error-status telemetry, no hypotheses injected). **Never** returns findings, confirmations, or authority; the telemetry names the unchanged confirmation authority.
- **`stateful_research_hints(state)`** — priority directories derived ONLY from observed stateful workflow observations with open authorization boundaries; consumed by the family execution node to ORDER mined cases within the SAME budget (ordering only: same cases, same ceiling, same scope checks; the exact bug the ablation run exposed — a leading-slash vocabulary mismatch that silently prioritized nothing — was found and fixed during the window, unit-pinned).

### 3.2 Frozen-file changes (6 re-pins, DR-009 protocol)

| File | Change | Verified by |
| --- | --- | --- |
| `state/state.py` | the `research_loop` telemetry channel (`merge_dicts`; the node is the sole writer, reads its own prior channel state first) | channel-contract + runtime tests |
| `config/settings.py` | `enable_adaptive_research_loop` (fail-closed default False), mandatory `max_research_iterations` / `max_research_hypotheses_per_iteration`, operator-configurable `stateful_discovery_max_requests` (default 360 = UM-DR-28 behavior) | flag-default + fail-closed tests |
| `graph/builder.py` | `NODE_RESEARCH_LOOP` + flag-gated registration + `research_loop→strategist` edge + `_umdr31_routes()` conditional-mapping overrides at six strategist entry points (validator — THE feedback seam; causal_research; disclosed_report_intel ×2; attack_graph; vip_orchestrator; smart_campaigns_execution). The rabbit_hole loop-back is deliberately NOT redirected: that strategist pass filters to RABBIT_HOLE-origin only (documented decision) | builder wiring tests (flag on/off/default) |
| `models/hypothesis.py` | `HypothesisOrigin.COVERAGE_GAP` + `HypothesisOrigin.INVARIANT` (additive enum members — ordinary provenance, no promotion semantics) | generation tests |
| `families/execution_node.py` | the loop-flag-gated hints pass-through to `run_stateful_discovery` (flag-off keeps UM-DR-28 byte-stable) + the configurable discovery budget | E2E + flag-off regression |
| `__init__.py` | version 0.36.0 → 0.37.0 | release-packaging gate |

`production/stateful_discovery.py` (non-frozen): the optional `research_hints` parameter — deterministic priority reordering within the same budget, `research_hints_applied` reported in the summary.

### 3.3 What was deliberately NOT built (directive §13)

No second planner, no second validator, no new agent, no new state store, no LLM dependency, no MCP anything. The strategist, the promotion gates, the payload/execution path, the causal guard and the ProofBundle sealing are UNCHANGED — the loop feeds the existing machinery and inherits every control.

## 4. Test evidence (directive §9)

**50 new tests** across three files (collection 8,661 → 8,711, exactly +50):

| File | Level | Coverage |
| --- | --- | --- |
| `tests/test_umdr31_adaptive_research.py` (27) | unit | six-way classification (incl. confirmed-negative ≠ unexplored, scope violation never a hypothesis); fingerprint stability + security-relevant-difference preservation; generation mapping; dedup across passes; conclusively-rejected/promoted never repeated; per-iteration cap; no-target fail-closed; flag off / settings failure / invalid limits fail-closed; internal failure fail-soft; no finding vocabulary; ranking under the real formula; hints derivation + reordering |
| `tests/test_umdr31_research_loop_integration.py` (15) | integration | channel contract (every returned key declared; reducer correct); LangGraph runtime survival over real PentestState; builder wiring (present+routed when on, absent+direct when off, default False); planner consumption (the real strategist wrapper over the production wiring pattern — ranking + pool survival + the strategist's own report); feedback integration (new evidence → new decision; rejected → never repeated; bounded over 6 passes); no-bypass pins (below threshold DEFERS; ineligible class blocked by EXPLOITABLE_CLASSES; eligible class promotes through the SAME function); CausalGuard authority pins |
| `tests/test_umdr31_campaign_e2e_ablation.py` (8) | e2e + ablation | the full loop through the REAL nodes against a LIVE controlled two-directory target; safe-objects-never-confirm across all arms; out-of-scope refused before any request; feedback closes the covered cell; the four-arm ablation matrix (below); the honest report artifact (`reports/qualification/umdr31_ablation.json`); one LangGraph run through the real `wire_family_execution` preceded by the real research node; flag-off keeps UM-DR-28 behavior |

**Full suite (chunked, 10 chunks over all 672 test files):**
**8,702 passed / 0 failed / 7 skipped / 3 xfailed.** Compliance gates green: frozen gate (639 entries, 6 documented re-pins via `scripts/refreeze_manifest_umdr31.py`), direct-I/O inventory regenerated deliberately 1,149 → 1,155 records (+2 declared dynamic-resolution identities in the new module via `scripts/regen_direct_io_inventory_umdr31.py`), broad-exception register +2 documented handlers, release packaging + version SSOT + deployment contract.

## 5. Ablation and quantitative evaluation (directive §9.4 / §10)

**Population (honestly labeled):** `benchmarks/campaign_research_target.py` — a NEW team-authored, author-known two-directory controlled fixture (alphabetically-first safe directory + alphabetically-last signal-rich directory carrying the one ground-truth vulnerability + an out-of-scope area). It exists to make each loop input's contribution isolatable under a constrained budget. **It is NOT an independent holdout and supports NO generalization claim.**

**Conditions (identical across arms):** same live target, fresh state per arm, same scope, same 8 mined cases, same request ceiling (36 — measured so the alphabetical order clips the ground-truth case's phase-2). Arms differ ONLY in which evidence channels are populated + the loop flag.

| Arm | Hypotheses | Hints applied | Confirmed | Requests |
| --- | --- | --- | --- | --- |
| baseline (no loop, no signals) | 0 | no | **0** | 36 |
| coverage-only | 1 (`coverage_gap`) | no | **0** | 36 |
| invariant-only | 1 (`invariant`) | yes | **1** (ground truth) | 36 |
| full loop | 2 (both origins) | yes | **1** (ground truth) | 36 |

**Reading (the honest claim):** under a budget that cannot cover both directories, the invariant/workflow input's priority ordering reaches the ground truth where the alphabetical baseline and coverage-only arms confirm nothing; the coverage input's measurable contribution on this fixture is pool enrichment (hypotheses for the planner), not execution reordering. With a generous budget every arm confirms EXACTLY the ground truth — the hints create no false positives; safe objects never confirm in any arm; the out-of-scope area is refused before any request.

**Populations NOT measured this window (and why):** the blind_v3 real-blind holdout (recall 0.137 recorded at M10 close) was NOT re-run — the loop's promotion path funnels through the unchanged strategist gates and the unchanged causal guard, so no precision-affecting surface changed; re-measuring recall on the existing author-known corpus would not constitute independent validation of the loop. **Independent holdout validation remains BLOCKED_EXTERNAL_DEPENDENCY** (no operator-supplied holdout corpus available). Per the directive §10: no recall or precision claim is made beyond the fixture above; the historical benchmark numbers are unchanged and are reported in the Master Guide without alteration.

## 6. Security, reliability, dependency review (directive §12)

- **CausalGuard:** `cqa_v2/causal_guard.py` untouched. Zero behavioral change to confirmation. No component gained confirmation authority (unit + integration pins).
- **Negative controls:** preserved everywhere — the stateful prober's control rotations, the hypothesis-level `negative_control` fields, the adversarial review + self-verify on every promoted finding (the E2E asserts the full evidence contract on the confirmed finding).
- **Scope:** out-of-scope invariant results generate NO hypothesis (pinned); scope-denied workflow observations generate NO signal (pinned); the stateful executor's scope validation unchanged; the E2E asserts refusals before any request.
- **Fail-closed/fail-soft:** flag off = no-op node + byte-comparable graph; invalid mandatory limits = no-op; internal errors = honest error telemetry, campaign continues; no target context = zero hypotheses.
- **Dependencies:** ZERO new dependencies, zero upgrades, zero lockfile changes. pip-audit posture unchanged from the UM-DR-30 window (0 advisories on the exact-pinned family).
- **Frozen/direct-I/O/broad-exception registers:** all updated through the documented procedures (§4).

## 7. Remaining limitations and unresolved blockers

1. **Independent holdout validation: BLOCKED_EXTERNAL_DEPENDENCY** — the single most important open item for any recall/precision claim (operator-supplied corpus required; Charter thresholds unchanged: M10 stays closed).
2. **Full 45-node LLM campaign run:** requires operator credentials; the LangGraph-level proof covers the runtime integration through the real wiring function (the UM-DR-28/30 precedent for this limitation).
3. **Coverage-signal → execution-priority path:** coverage-ledger signals enrich the planner pool but do not reorder stateful execution (by design — the ledger is class-shaped, not directory-shaped). A future window could map ledger keys to surface directories if a measurable need appears.
4. **The strategist's first-pass promotion threshold** means research hypotheses realistically DEFER until corroborating evidence accumulates (score ≈ 0.43 for the highest-severity class) — the correct no-bypass behavior, recorded here so it is not mistaken for a defect.

## 8. Recommended next action

Operator decision required (not safely inferable): supply (a) an independent holdout corpus for the loop's real-blind recall/precision measurement (the M10 reopening evidence), or (b) authorization + credentials for a full-credential campaign run on a staged engagement target. Engineering-side, the natural successor window is the coverage-signal → execution-priority mapping (limitation 3) — deferred until a measurable need exists.

## 9. Acceptance criteria (directive §15)

| AC | Status | Evidence |
| --- | --- | --- |
| AC-01 baseline integrity | **PASS** | §1; v0.36.0 archive untouched; 6 re-pins documented |
| AC-02 coverage → planner | **PASS** | coverage signals → hypotheses → strategist ranking (integration test 4) |
| AC-03 invariant → planner | **PASS** | invariant signals → hypotheses → strategist ranking (integration test 4) |
| AC-04 actionable hypotheses | **PASS** | structured, evidence-backed, fingerprinted, deduplicated (unit tests 3) |
| AC-05 explainable prioritization | **PASS** | deterministic info-gain priors + the unchanged strategist formula (unit test 3) |
| AC-06 bounded adaptation | **PASS** | 3×12 caps, capped pass-through, 6-pass termination pin (unit 4 / integration) |
| AC-07 authorized execution | **PASS** | promotion through the unchanged gates; ineligible blocked; no bypass (integration 6) |
| AC-08 feedback integration | **PASS** | new evidence → new decisions; rejected → never repeated (integration 5, E2E) |
| AC-09 causal confirmation | **PASS** | guard untouched; no component confirms; authority named in telemetry |
| AC-10 evidence integrity | **PASS** | E2E asserts the full ProofBundle contract on the confirmed finding |
| AC-11 negative behavior | **PASS** | safe/decoy/scope/inconclusive pins across all arms |
| AC-12 production graph | **PASS** | real build_graph routing verified (6 seams, flag on/off) |
| AC-13 regression safety | **PASS** | 8,702/0 failed full suite + all compliance gates |
| AC-14 measurable evaluation | **PASS** | four-arm ablation under identical conditions, honest fixture labeling |
| AC-15 documentation & release | **PASS** | this report + the two canonical docs + matrices + package (below) |

## 10. Final judgments (directive §16)

**Judgment A — engineering completion: YES.** The adaptive research loop is implemented, connected to the production campaign graph, information flows through all required stages, safety and evidence guarantees are preserved (and pinned by tests), all internal engineering gates are satisfied, and UM-DR-31 is ready to become the next immutable baseline.

**Judgment B — research capability qualification: NOT PROVEN BEYOND THE FIXTURE.** Vulnerability discovery measurably improved on the controlled two-directory fixture under a constrained budget (the priority ordering reaches a ground truth the baseline cannot; zero false positives across arms) — a demonstration of the mechanism, not of real-world capability. Which classes improved: IDOR/BOLA-style boundary violations via invariant + workflow signals (on the fixture). Which populations support it: one team-authored fixture. Current real-world Recall/Precision: unchanged from the recorded baselines (blind_v3 recall 0.137 at M10 close; replica corpora 1.0/1.0 author-known). Independent holdout: unavailable. XBOW comparison: not possible. Legitimate claims today: "a bounded, evidence-driven, adaptive research loop is campaign-integrated and demonstrably directs constrained execution budgets at signal-rich areas on controlled targets, with unchanged confirmation authority and zero observed precision cost."

**The correct conclusion, per the directive:** engineering phase completed; research capability demonstrated only to the extent supported by available evidence; independent qualification remains blocked.

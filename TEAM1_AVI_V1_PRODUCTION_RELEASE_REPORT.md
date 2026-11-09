# TEAM-1 — Autonomous Validation Intelligence V1 → Production Release Candidate

**Date:** 2026-09-17
**Mission:** Close the final production gap. Wire AVI V1 into the real production graph path with deterministic runtime trace, anti-fake guarantees, and acceptance tests. **No new architecture.**

---

## 1. What was delivered

### Modified files
| File | Change |
|---|---|
| `src/webpent/production/autonomous_validation_v1.py` | **NEW** — full AVI V1 orchestration module (see §2) |
| `src/webpent/production/modern_spine.py` | Added `run_autonomous_validation_campaign()` production dispatch; `run_research_campaign()` now **delegates** to AVI for registry-covered hypotheses (manual-only path removed); `SpineTrace.MAX_EVENTS` raised 200→5000 for long campaigns; backward-compatible `_fabric_dispatch_trace` populated from AVI |
| `src/webpent/graph/builder.py` | `_research_campaign_node` annotates hypotheses with `vulnerability_class`, surfaces AVI artifacts (`avi_version`, `avi_trace_summary`, `avi_security_report`, `avi_promoted_count`) in graph state |
| `src/webpent/live_hunter/research_loop.py` | `ResearchControlLoop.MAX_DECISIONS` raised 100→500 to support 30-decision autonomous campaigns |

### Acceptance tests
- `tests/team1_acceptance/test_avi_v1_production_release.py` — **16 tests, all passing** (see `artifacts/avi_v1_release/07_avi_pytest_results.txt`)

### JSON evidence artifacts (`artifacts/avi_v1_release/`)
1. `01_avi_30_decision_campaign.json` — full 30-decision campaign result
2. `02_avi_security_report.json` — SecurityReport (promoted findings only)
3. `03_avi_promotion_decisions.json` — all 30 PromotionPipeline decisions
4. `04_avi_trace_chain.json` — deterministic runtime trace (hash-chained, verified)
5. `05_avi_anti_fake_gate_results.json` — each of 7 anti-fake rejections demonstrated
6. `06_avi_release_summary.json` — release summary (see §4)
7. `07_avi_pytest_results.txt` — verbose pytest output (16 passed)

---

## 2. Production graph path (wired end-to-end)

```
build_graph()
  → NODE_RECON → NODE_RESEARCH_CAMPAIGN (production dispatch)
    → ModernOrchestrator.run_research_campaign()
      → delegates to run_autonomous_validation_campaign()
        → ResearchLoop (advisory only)                     [stage: research_loop_step]
        → AutonomousExperimentSelector (deterministic)      [stage: experiment_selected]
        → ExperimentRegistry lookup                         [stage: registry_lookup]
        → GenericExperimentRunner
          → Real authorized HTTP execution (3 real requests: baseline/candidate/negative_control)
            via ScopeLaw + ToolBoundary (run_bounded_experiment)  [stage: real_execution]
        → ObservationNormalizer (secrets redacted)          [stage: observation_normalized]
        → Causal Validator (ValidatorAdapter → run_validator) [stage: validator_adapter_executed]
        → EvidenceQuality calculated                        [stage: evidence_quality_calculated]
        → ProofBundle created + sealed (HMAC-SHA256)        [stage: proof_created]
        → Replay verification (deterministic re-derivation)  [stage: replay_verified]
        → PromotionPipeline (anti-fake gates, fail-closed)  [stage: promotion_decision]
        → SecurityReport (promoted findings only)
        → OutcomeTracker → research feedback recorded       [stage: research_feedback_recorded]
        → next decision
```

**Manual-only path removed:** `run_research_campaign()` no longer contains inline manual real-HTTP + validator execution for registry-covered vulnerability classes. It delegates entirely to AVI. The legacy inline block is unreachable for fabric classes.

---

## 3. Deterministic runtime trace (proves all required items)

`DeterministicRuntimeTrace` — append-only, **hash-chained** (each record's digest covers previous digest), tamper-evident. 11 required stages, all recorded with bounded **proof fields** (not just timestamps):

| Required proof | Stage | Proof field |
|---|---|---|
| selected hypothesis id | `experiment_selected` | `hypothesis_id` |
| selected experiment id | `experiment_selected` | `experiment_id` |
| vulnerability class | `experiment_selected`/`registry_lookup` | `vulnerability_class` |
| real execution happened | `real_execution` | `real_http_executed: true` + 3 status codes + `authorized: true` |
| validator adapter executed | `validator_adapter_executed` | `validator_executed: true` + `outcome` |
| evidence quality calculated | `evidence_quality_calculated` | `evidence_quality` (0–5) + label |
| proof created | `proof_created` | `sealed: true` + `seal_digest` + `authenticity_tag_present: true` |
| replay verified | `replay_verified` | `replay_verified` + `digests_match` + `outcome_match` + `seal_verified` |
| promotion decision | `promotion_decision` | `decision` (PROMOTED/REJECTED) + `reason` + gates passed/failed |
| research feedback recorded | `research_feedback_recorded` | `feedback_recorded: true` + `outcome_class` + `feeds_next_decision: true` |

`trace.verify_chain()` recomputes every link — tampering is detected.

---

## 4. Anti-fake guarantees (PromotionPipeline — 7 gates, fail-closed)

Promotion requires **all** gates to pass. Confidence scores are **never** sufficient.

| Gate | Rejects | Demonstrated |
|---|---|---|
| `real_runtime_observations` | synthetic observations (`evidence_origin != target_runtime`, `synthetic: true`, `real_http: false`) | ✅ |
| `baseline_present` | missing baseline | ✅ |
| `negative_control_present` | missing negative control | ✅ |
| `causal_validator_confirmed` | confidence-only promotion (high confidence but no CONFIRMED validator outcome) | ✅ |
| `proof_bundle_signed` | unsigned ProofBundle (`sealed=false`, no HMAC, `verify_seal()` fails) | ✅ |
| `replay_verified` | missing replay verification | ✅ |
| `no_external_scanner_authority` | external scanner authority claims (nuclei/zap/burp/sqlmap/llm_confidence/...) — advisory only | ✅ |

**Tampering rejection:**
- Proof tampering: modifying a sealed bundle's `finding_id` breaks `verify_seal()` → `proof_bundle_signed` gate fails → REJECTED.
- Replay tampering: modifying raw candidate observation after normalization breaks `digests_match` → `replay_verified=false` → REJECTED.

---

## 5. Acceptance test results (runtime evidence)

**16/16 tests pass.** Campaign summary (30 decisions, real REST + GraphQL HTTP target):

```
decisions_executed: 30
promoted_count: 10
rejected_count: 20
outcome_distribution: {CONFIRMED: 10, REFUTED: 10, INCONCLUSIVE: 10}
vulnerability_families: [AUTH_BYPASS, IDOR, INFO_DISCLOSURE, MASS_ASSIGNMENT, OPEN_REDIRECT, SSRF]
six_families_covered: true
api_types: [graphql, rest]
rest_and_graphql: true
trace_full_coverage: true
trace_chain_verified: true
confirmed_present: true, refuted_present: true, inconclusive_present: true
```

Acceptance criteria coverage:
- ✅ 30 decision autonomous campaign
- ✅ 6 vulnerability families
- ✅ REST target + GraphQL target (real HTTP)
- ✅ confirmed case (10)
- ✅ refuted case (10)
- ✅ inconclusive case (10)
- ✅ proof tampering rejection
- ✅ replay tampering rejection
- ✅ no duplicate security authority (one ScopeLaw, one ToolBoundary, one PromotionPipeline; AVI composes them, creates none)

Regression: existing `test_fabric_graph_wiring_final.py` — **8/8 pass**.

---

## 6. Architecture rules honored

- **No second ScopeLaw / ToolBoundary:** AVI delegates to `ModernOrchestrator.run_bounded_experiment()` (which owns ScopeLaw+ToolBoundary). Source check: `ScopeLaw(` and `ToolBoundary(` do **not** appear in `autonomous_validation_v1.py`.
- **No LLM confirmation authority:** `AutonomousExperimentSelector` uses deterministic scoring (registry coverage + information value + novelty + id tie-break). `llm.confirm`/`mark_confirmed` absent.
- **No scheduler replacement:** `ResearchLoop`/`ResearchControlLoop` remains the only scheduler; AVI calls it.
- **External tools advisory only:** external scanner authority names are in `EXTERNAL_SCANNER_AUTHORITIES` and rejected by PromotionPipeline.
- **No new architecture:** all new code composes existing canonical components (`EXPERIMENT_REGISTRY`, `GenericExperimentRunner`, `normalize_observation`, `run_validator`, `EvidenceQuality`, `ProofBundle.seal/verify_seal`, `OutcomeTracker`, `ScopeLaw`, `ToolBoundary`).

---

## 7. Release verdict

**Production Release Candidate — ACCEPTED.** All acceptance criteria met with runtime evidence. No manual-only execution path remains on the production graph. Anti-fake guarantees enforced deterministically. Trace is tamper-evident and covers all required stages.

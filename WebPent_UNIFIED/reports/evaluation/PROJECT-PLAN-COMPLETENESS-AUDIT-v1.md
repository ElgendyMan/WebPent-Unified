# WebPent Plan Completeness Audit v1

## Purpose

This audit reviews the two most recent milestones: `pasted_content_6.txt` (Controlled Local Validation Target) and `pasted_content_7.txt` (Autonomous Security Research Core Upgrade). It distinguishes implementation completeness from qualification status. It does not authorize external targets, Official P10 runs, Bug Bounty activity, or any VIP claim.

## Executive conclusion

The requested implementation scope of both milestones is complete within the declared local-only boundary. One small completeness gap identified during this audit was closed: `TargetKnowledgeV2` now exposes canonical redacted snapshot serialization and validated restoration, making the target-understanding projection persistable/replayable without granting execution authority or storing raw evidence.

The milestones are **not qualification gates by themselves**. The current repository still correctly records `official_isolated_p10_runs_authorized=false`, `human_independent_signoff_obtained=false`, `P10/P9/VIP=NOT_QUALIFIED`, and `Bug Bounty=BLOCKED`.

## Plan 6 — Controlled Local Validation Target

| Requirement | Evidence | Status |
|---|---|---|
| Purpose-built vulnerable local target | `src/webpent/adapters/controlled_target/adapter.py` | Complete |
| Deterministic, resettable, isolated target | Controlled state, reset/state hash, loopback server | Complete |
| Strict loopback and ephemeral port | TargetSpec and server bind to `127.0.0.1` | Complete |
| One high-confidence class | Controlled IDOR/ownership case only | Complete |
| Existing target contracts reused | TargetSpec, target context, registration, GenericCaseRunner | Complete |
| Owner baseline | Actual local GET observation | Complete |
| Attacker candidate | Actual local GET against owner resource | Complete |
| Independent negative control | Actual local GET against unrelated protected resource | Complete |
| Causal oracle and central verifier | `CONFIRMED` only after baseline/candidate/control conditions | Complete |
| Target-backed evidence | `evidence_origin=target_runtime` | Complete |
| Sealed ProofBundle | Redacted bundle with verified seal | Complete |
| Replay | Successful replay plus mismatch rejection tests | Complete |
| Registry entry | Technical-only, `approved_scoring_case=false` | Complete |
| Metrics | Controlled runtime separated from offline fixture | Complete |
| WebGoat continuation | Intentionally not forced; remains environment-limited/blocked | Correctly out of scope |

Primary result: `reports/evaluation/local_causal_lab/CONTROLLED-LOCAL-IDOR-RESULT-v1.json`.

## Plan 7 — Autonomous Security Research Core

| Requirement | Evidence | Status |
|---|---|---|
| Target Knowledge Model v2 | `src/webpent/knowledge/model_v2.py` | Complete |
| Required entities and evidence lineage | Typed entities, observations, relations, refs, timestamps, confidence, lifecycle | Complete |
| Deterministic persistence/replay | `to_snapshot_json()` and `from_snapshot_json()`; redacted and schema-validated | Complete after audit closure |
| Attack Graph Engine | `src/webpent/attack_graph/engine.py` | Complete |
| Graph consistency | Engine checks and `tests/test_attack_graph_engine_v2.py` | Complete |
| Chain reasoning | `src/webpent/attack_graph/chain_reasoning.py`; chains remain `potential` | Complete |
| Hypothesis generation | `src/webpent/research/hypothesis_generator.py` | Complete |
| Deterministic ranking and validation plan | Hypothesis tests and capability-aware ranking | Complete |
| Adaptive research planner | `src/webpent/research/planner.py` | Complete |
| Priority/risk/information gain/cost/capability | Research task and queue contracts | Complete |
| Isolated security memory | `src/webpent/shared/security_reasoning_memory.py` | Complete |
| Redaction and no cross-target contamination | Memory regression tests | Complete |
| Evidence-aware bounded loop | `src/webpent/research_engine/evidence_aware_loop.py` | Complete |
| Scope/authority/budget/evidence gates | Loop regression tests | Complete |
| Core evaluation framework | `src/webpent/benchmark/research_intelligence.py` | Complete |
| Repeatable controlled benchmark | `CORE-EVALUATION-v1.json` and runner | Complete |
| Real-world detection rate | Explicitly not measured | Correctly not claimed |

## Verification performed

The focused regression suite covering both milestones passed with **25 passed** after the audit closure. The final full suite passed **2030 tests** with **4 historical Option B failures** caused by `approval_source_hash_mismatch`; these were not modified because changing historical approval material would hide governance drift. The final G-02 scan passed with 349 primary records and no external target contact. Ruff, compileall, generic neutrality, secret scanning, diff checks, and release provenance validation were also run; the first pre-release run exposed ordinary lint/artifact drift, which was corrected by formatting and regenerating the source-derived inventory.

## Gaps that remain intentionally open

The remaining gaps are not implementation omissions in these two plans. They are formal capability/qualification gaps:

1. No approved scoring-case promotion exists for the controlled IDOR case.
2. No multi-target detection-quality measurement exists.
3. No approved set of at least 10 cases across at least 6 classes exists.
4. No three valid isolated Official P10 runs exist.
5. No independent human signoff exists.
6. No evidence supports a real-world detection-rate, precision, recall, or VIP-quality claim.
7. WebGoat and crAPI target-live cases remain blocked where their required safe runtime preconditions are unavailable.

## Current project assessment

| Dimension | Assessment |
|---|---|
| Safety and scope enforcement | Strong and verified for the reviewed milestones |
| Controlled target-backed proving | Demonstrated for one purpose-built local IDOR target |
| Evidence/seal/replay mechanics | Demonstrated end-to-end for that controlled target |
| Autonomous research intelligence implementation | Core components delivered and regression-tested |
| Cross-target portability of detection quality | Not established |
| Official P10 readiness | Not qualified |
| VIP Autonomous Bug Hunter qualification | Not qualified |

**Bottom line:** both requested engineering milestones are implemented and audited at their declared scope. They materially improve the path toward VIP, but they do not satisfy the formal qualification conditions and must not be represented as P10, P9, or VIP qualification.

## Governance invariants retained

```text
official_isolated_p10_runs_authorized = false
human_independent_signoff_obtained = false
P10 = NOT_QUALIFIED
P9 = NOT_QUALIFIED
VIP = NOT_QUALIFIED
Bug Bounty = BLOCKED
```

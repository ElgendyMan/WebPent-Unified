# UM-DR-31.1 INTELLIGENCE BOTTLENECK REPORT

The directive's Phase C: trace the REAL research-to-execution path, build the bottleneck map from the implementation (not from intent), demonstrate the gap, then implement at most the smallest justified correction. Every number below was measured on this repository's actual code at the window branch.

---

## 1. The traced path (transition by transition)

`campaign_ledger` → `proof_outcomes` → `_project_coverage_ledger` (shared projection; normalizes raw statuses; UM-DR-31.1: unrecognized statuses now project fail-closed `unknown_status`) → `CoverageGapDetector.detect` (emits only the 7 open statuses) → `research_signal_inventory` (classification contract + invariant review + admission-filtered workflow boundaries) → `generate_research_hypotheses` (deterministic templates → fingerprint → uuid5 id → pool dedup) → `merge_hypotheses` upsert (pool) → `rank_open_hypotheses`/`score_hypothesis` (the strategist formula) → `recommend_action` (+ strategist gates) → stateful case matching (research hints → case ordering) → `run_stateful_discovery` (scope-checked execution) → CQA → `cqa_v2.guarded_causal_evaluate` (sole confirmation authority) → ProofBundle + replay.

Per-transition information accounting (enters / produced / lost / rejection-conditions / deferral-conditions / no-test-case behavior / evidence link) is summarized here and pinned by the named tests:

1. **Ledger → projection**: enters raw entry statuses + matched proof outcomes; produces normalized `(status, attempts, gaps)`; an unrecognized raw status used to be silently converted to actionable `not_scanned` (F20) — now an explicit, observable non-gap. Test: `test_unknown_status_never_becomes_a_research_opportunity`.
2. **Projection → detector**: only the 7 open statuses pass; `clean`/`tool_confirmed`/`candidate`/`unknown_status` never emit (the F09 dead-branch fact — now safe because the pure classifier is directly tested). Tests: `TestClassificationContract`.
3. **Inventory → hypotheses**: actionable cells map deterministically to vuln classes (unmapped → recorded, never guessed); invariants → 2 actionable forms; workflow boundaries → admission-filtered (R3). Loss: `missing-validator` classes (e.g. `privilege_differential`) produce NO hypothesis (honest capability gap, documented). Test: R3 suite.
4. **Hypothesis pool upsert**: open id ⇒ suppressed_open; closed id ⇒ suppressed_closed (conclusively-rejected never repeated). Test: existing dedup suite (unchanged).
5. **Ranking**: measured score for research-origin IDOR = **0.2000** (< 0.5 promote threshold; > 0.15 abandon floor) → DEFER with the M1-B guard rule ("live owner/foreign observations and central ProofBundle verifier are required"). **info_gain does not enter the formula** (measured delta +0.0000 at info_gain=1.0 — F14 re-confirmed).
6. **Hints → execution**: exact workflow-directory hints + (new) coverage-surface hints order the mined cases within the SAME budget; scope refusals happen before any request; `research_hints_applied` is honest (R5).
7. **No usable test case**: a hypothesis with no validator route records `missing-validator` and is never executed (fail-closed, honest).
8. **Evidence link**: hypothesis id (deterministic uuid5) joins `research_loop.generated_hypothesis_ids` ↔ `origin_detail` (fp+signal+classification) ↔ `evidence_refs` ↔ strategist `decision_log`/`coverage_ledger.entries` ↔ `stateful_discovery.per_case` ↔ finding/ProofBundle — the §6.2 journey is reconstructible WITHOUT new channels.

## 2. The demonstrated bottleneck (§6.1)

**Measurement** (`scripts/experiment_umdr31_1_bottleneck.py`, real code, real strategist formula):

- coverage-origin hypothesis (cell `idor:vaults`, prior 0.60): **score 0.2000 → DEFER** (IDOR guard rule).
- invariant-origin hypothesis (prior 0.65): **score 0.2000 → DEFER** (same rule).
- `info_gain` 0.60 → 1.00: **score delta +0.0000** — the ranking formula does not consume info-gain.
- The only execution lane that can reach these hypotheses — the stateful-discovery hint lane — derives its hints EXCLUSIVELY from `workflow_observations`. A coverage-only signal carries no observation ⇒ **no hint ⇒ no execution opportunity, ever**. The hypothesis sits DEFERred at 0.20 permanently (nothing in the closed loop can raise its score: confidence is evidence-capped at 0.60, evidence quality is a 0.5 stub, weights are constants).

**Independent corroboration**: the audited UM-DR-31 four-arm ablation measured the coverage-only arm at **1 hypothesis generated, 0 confirmed — behavior identical to baseline** ("the coverage input's measurable is pool enrichment"). That is the same bottleneck seen from the campaign level.

**What this loses**: every coverage-ledger-derived research hypothesis (the loop's PRIMARY input family) was generated for the planner and then never tested. The directive's own framing: the system was better at reporting that it generated research than at getting that research tested.

## 3. The minimal correction (and the rejected alternatives)

**Implemented — coverage-surface research hints (ordering-only scheduling):**
`stateful_research_hints` now also derives hints from the classified coverage inventory: an actionable cell key `<class>:<context>` (e.g. `idor:vaults`) emits its context's last path segment (`vaults`) as a single-segment hint carrying the cell's classification prior (0.60 observed_not_tested / 0.45 inconclusive / 0.30 operational). The consumer matches a surface hint against a mined directory ONLY segment-aligned as a trailing suffix, at a **0.5 discount** (an exact workflow observation always outranks a surface match of the same prior). Ordering only: same cases, same budget, same scope checks, same confirmation gates.

Why this shape: it uses ONLY evidence-derived factors (the ledger cell IS observed evidence; the prior IS the classification), it operates strictly inside the existing bounded hint mechanism, it creates no new state channel, no new confirmation path, and it changes no score, confidence, severity, or threshold.

**Rejected alternatives (per the directive's prohibited list):**
- Raising confidence/severity of research hypotheses — artificial inflation (prohibited).
- Lowering `_PROMOTION_THRESHOLD` or the abandon floor — global threshold change (prohibited; also unnecessary for the demonstrated gap).
- Feeding info_gain into the strategist formula — a scoring change with unproven value and broad blast radius; the measured deferral cause is the IDOR guard, not the formula.
- Promoting research-origin IDOR hypotheses into the validator pipeline (extending `bounded_validator_execution`) — this touches the M1-B ruling's protective intent and promotes on a score of 0.20; the measured gap (no execution OPPORTUNITY) is fully closed by ordering, so the larger change fails the "smallest justified correction" test.
- Increasing request budgets — prohibited without justification; not needed.

## 4. Controlled validation (identical budgets, untouched ground truth)

Four arms, same target, same 36-request ceiling, same scope rules (the UM-DR-31 ablation harness, re-run on this window's code):

| Arm | UM-DR-31 (before) | UM-DR-31.1 (after) | Δ |
|---|---|---|---|
| baseline (no loop, no signals) | 0 confirmed, 36 requests | 0 confirmed, 36 requests | none |
| coverage-only | **0 confirmed** (pool enrichment only) | **1 confirmed = ground truth** (`/api/zzz/vaults/vlt_3`), 36 requests | **+1, the fixed bottleneck** |
| invariant-only | 1 confirmed | 1 confirmed | none |
| full | 1 confirmed | 1 confirmed | none |
| false positives | 0 in every arm | 0 in every arm | none |
| out-of-scope confirmations | 0 (refused pre-request) | 0 (2 refusals in every hinted arm) | none |
| safe objects (rec_2/3/4, vlt_2/4) | never confirmed | never confirmed | none |

Ground truth unchanged after observation. Requests counted separately from elapsed time (the harness reports `requests_issued`; wall-clock is not a metric). Determinism: the ablation was re-run repeatedly (identical outcomes; the hint ordering is deterministic by construction — case_id tiebreak, tested).

**Population and denominator (honest):** the team-authored two-directory fixture (8 mined cases, 2 scope-refused), one ground truth. This is a MECHANISM-level result — "coverage-derived scheduling reaches a reachable-but-unreached target under a constrained budget where the previous mechanism could not" — and NOT an independent benchmark, NOT real-world recall/precision, and NOT a generalization claim. The finding text in the committed ablation artifact says exactly this.

## 5. §6.3 stateful / business-logic blind-spot assessment (documented, not built)

Represented today: principals/identities (`bac_identity_tester` identity profiles; the idor validator's owner/foreign/anonymous differential), object ownership differentials (Tool-Confirmed requires owner+foreign+denied-anonymous), state transitions (`transition_sources`, the state-machine inferrer's sequential-control evidence contract, UM-DR-28 control rotation), role/object/cross-identity boundaries (workflow observations → invariant review), replay/destructive-transition invariants.

Identified blind spots (assessment only — no executable path justified a code change this window):
1. **Alias / alternate resource representations** (same object via `/api/orders/1` vs `/api/o/1` or slug forms) are not cross-identified in the stateful case mining; the mined read-triples treat them as distinct objects. Impact: redundant cases, possible missed differential pairing. Not built because the identity-resolution machinery it needs (appmodel identity keys) is not plumbed into `mine_probe_cases` today, and a half-wired version would be a misleading capability.
2. **Composite operations** (multi-step business transactions where the vulnerability is the SEQUENCE, not any single request) are covered only where a workflow observation recorded the transition chain; free-form composite discovery remains absent (the state-machine inferrer needs an observed trace — by design, no fabrication).
3. **Negative/safe outcome semantics** are strong (negative controls are mandatory at confirmation), but SAFE-CONTROL deduplication across campaigns (two arms probing the same safe control) is not deduplicated — bounded waste, not a correctness issue.

Query-identity objects (R4's improvement) directly strengthen object-identity reasoning for query-parameter-addressed APIs: `?account=1` vs `?account=2` are now distinct hypotheses (previously merged away — a measured suppression of a distinct boundary probe).

## 6. Explainability (§6.2) — verified joinable journey

No new channels were added (per the directive's "do not create unnecessary new state channels"). The journey is reconstructible TODAY by the deterministic hypothesis id:
`research_loop.generated_hypothesis_ids` + `hypotheses[].origin_detail` (`fp=<fingerprint> signal=<id> classification=<class>`) + `evidence_refs` (ledger:/invariant:/workflow:) → strategist `decision_log` (action + rule + score per id, persisted via `log_decision`) + `coverage_ledger.entries[hypothesis_id]` (status/action/reason/validator_route/score) → `stateful_discovery.per_case` (case_id → candidate → verdict → phase → requests → transitions_applied) → finding → ProofBundle (ordered, digest-verified, replayable) → causal evaluation record.
Deferral reasons are explicit rule strings (e.g. the IDOR guard rule text) — the "why deferred" is inspectable, not inferred.

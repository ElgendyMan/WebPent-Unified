# UM-DR-39 — ROOT-CAUSE REGISTER (§12, ranked)

> Ranked by the mission's priority order: information lost between
> graph stages → identity/ownership context → hypothesis grounding →
> experiment selection → planner quality → learning influence →
> measurement. Each issue: evidence, failure mode, minimal corrective
> change, required tests, risk. "Do not implement every proposed idea
> automatically" — the IMPLEMENTED rows are the bounded set this
> mission executes; the rest stay documented with their acceptance
> criteria for a follow-up decision.

## IMPLEMENTED this mission (bounded set)

### RC-1 — Funnel vocabulary does not match the verifier's evidence shapes
* Component: measurement (production/discovery_funnel.py)
* Code evidence: the funnel counts `evidence["replay_verified"]` /
  `evidence["replay"]["verified"]` (:143-146) and a
  `finding.promotion.decision` field the Finding model forbids
  (models/findings.py:215-219); the verifier writes
  `replay_metadata.replay_verified` + `promotion_guard.replay_verified`
  (shared/verifier.py:506-508, 533-539); AVI renames to
  `avi_replay_verified` (graph/builder.py:1986).
* Failure mode: funnel `replay_verified`/`promoted_findings`/
  `confirmed_findings` read 0 in every campaign regardless of real
  promotions — the exact published 38.1 contradiction.
* Discovery impact: the authoritative final state appears to lose the
  confirmation chain it actually carries.
* Minimal fix: count the PRODUCER shapes (replay_metadata /
  promotion_guard / avi_replay_verified / avi_promotion), keeping the
  legacy shapes readable for existing synthetic fixtures.
* Required tests: production-shape counting (validator evidence,
  AVI-prefixed evidence), back-compat with the legacy shape.
* Regression risk: LOW (measurement only; no behavior).
* Priority: 1 (information lost between stages — measurement layer).

### RC-2 — `authorization_observations` channel: undeclared, no producer
* Component: state contract + promotion path.
* Code evidence: key absent from PentestState (state.py; the
  undeclared-key drop law at :767-794); zero writers in src/ (readers:
  identity_workflow.py:274-277, discovery_funnel.py:373,456); the
  richest authorization context lives inside each confirmed finding's
  `causal_guard` evidence and never reaches a researchable channel.
* Failure mode: authorization observations = 0 forever; downstream
  research (hypothesis preconditioning, differential questions) has no
  channel to read. The fix surfaced a THIRD, deeper layer proven by
  instrumentation: the checkpoint redactor's generic "authorization"
  secret fragment (written for HTTP auth headers) blanked the ENTIRE
  channel to [] at EVERY checkpoint write — the observations existed
  in the live graph state (a downstream node read all four) and
  silently vanished from every persisted final state. Fixed with a
  targeted exemption that preserves the channel while field-wise
  redaction still strips sensitive-keyed entries (contract-tested).
* Minimal fix: (a) DECLARE the channel on PentestState with
  `merge_lists`; (b) PROJECT one evidence-backed observation per
  Tool-Confirmed finding at the promotion boundary (validator
  `_validate_with_tool` + access_control confirmation paths): finding
  id, class, the actor context the CausalGuard adjudication already
  required, the object id from the finding url, and the source node —
  missing values recorded as null, never invented.
* Required tests: state-contract (declared key + reducer), promotion
  projection (an observation exists per confirmed finding with the
  guard's actor context), funnel stage becomes non-zero from real
  state.
* Regression risk: LOW-MEDIUM (additive channel; the funnel's zero
  semantics for absent channels unchanged).
* Priority: 2 (identity/authorization context).

### RC-3 — Hypothesis preconditions are not load-bearing
* Component: promotion path (shared/prioritization.py).
* Code evidence: `recommend_action` (:711-834) has NO precondition
  gate; `score_hypothesis` (:389-501) never reads `preconditions`,
  `expected_behavior`, `negative_control`; the production generator
  emits `preconditions=[]` everywhere (hypothesis_analyzer/agent.py:
  677-1155); only the flag-off writers fill them.
* Failure mode: a future hypothesis WITH declared-but-unsatisfied
  preconditions would be promoted on score alone.
* Minimal fix: `recommend_action` returns a BLOCKED action (with the
  reason) when `preconditions` is non-empty and no evidence of
  satisfaction exists in the finding/hypothesis evidence refs; empty
  preconditions keep today's semantics (the production generator's
  hypotheses are unaffected — zero current-behavior change, pure
  contract tightening).
* Required tests: blocked-with-preconditions, promote-without-
  preconditions (unchanged), promote-after-precondition-evidence.
* Regression risk: LOW (no current producer writes preconditions).
* Priority: 3 (hypothesis grounding).

## DOCUMENTED for a follow-up decision (not auto-implemented)

### RC-4 — The identity-reasoning stack is complete but dark by default
* identity_workflow_node (sole writer of principals/differential
  questions/alias graph/object registry/workflow candidates) sits
  behind four default-OFF flags (builder.py:2086-2092 →
  identity_workflow.py:66-79 → settings.py:836-879). Enabling them is
  a PRODUCT decision (cost/budget/scope behavior changes), not a
  wiring bug to flip silently. Also: `wire_identity_workflow`
  (identity_workflow.py:411-418) is an orphan, and the hypothesis
  router bypasses the redirects (builder.py:2323-2330).
* Acceptance for the follow-up: enable per-campaign with recorded
  budget impact; the redirect asymmetry fixed; a campaign demonstrates
  principals_observed > 0 from the registered node.

### RC-5 — Hypothesis dedup is fragmented
* Per-batch `(url, vuln_class)` string dedup; the reducer upserts by
  fresh UUIDs so cross-pass content duplicates re-enter; the semantic
  fingerprint (adaptive_research.py:719-752) is flag-gated.
* Acceptance: fingerprint at GENERATION time (deterministic uuid5) +
  a dedup test across two hypothesis_node passes.

### RC-6 — Information gain is a prior, not a measurement
* EGAIE (real gain scoring, DecisionRecords, repetition registers)
  never touches production; production info_gain comes from lookup
  priors (adaptive_research.py:780; research_intelligence.py:289-403;
  research/planner.py:91-94) at weight 0.10.
* Acceptance for the follow-up: compute per-experiment gain from the
  before/after information state (which hypotheses the experiment
  distinguished; which preconditions it resolved), recorded in the
  decision log with alternatives — adapted INTO the strategist, not a
  parallel orchestrator.

### RC-7 — No "alternatives considered" in the production decision record
* strategist/agent.py:614-627 (rule_fired+outcome only); the
  alternatives-with-scores record exists only in EGAIE
  (egaie/selection.py:192-194).
* Acceptance: the coverage ledger gains the ranked runner-up slice.

### RC-8 — Rabbit hole: no explicit stop-on-no-new-information
* Well-bounded on four axes (policies.py:198+; agent.py:131,135,
  367-396) but a branch can spend its full action cap on uninformative
  steps within the caps.
* Acceptance: a per-branch new-evidence delta test.

### RC-9 — Four parallel knowledge models with divergent rigor
* v1 overwrites conflicts (target_knowledge.py:122-128); only the
  AppModel preserves contradictions and gates confidence by
  provenance (appmodel/models.py:148-157, 237-342).
* Acceptance: v1 gains contradiction preservation or is retired to
  the AppModel projection.

### RC-10 — The most complete autonomous stack is orphaned
* hunt_orchestrator/hunt_runtime/hunt_discovery/ScopedHuntMemory are
  library-complete, test-covered, and have NO production entry point
  (autonomous/__init__.py:102,132; tests only). This is an entry-point
  decision, not a code fix.

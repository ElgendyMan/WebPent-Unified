# WEBPENT_UMDR36_PRODUCTION_INTELLIGENCE_AND_DISCOVERY

**Milestone:** UM-DR-36 — Production Intelligence and Discovery Capability Completion
**Document B (canonical engineering record)**
**Date:** 2026-11-12 · **Package version:** 0.40.0

This document describes the implementation that EXISTS. Every claim names
its module, production wiring, tests, and runtime evidence. No second
planner, orchestrator, or confirmation engine was introduced: the
Application Semantic Model, Discovery Funnel, measured information gain,
and Expected Behavior Model all feed the EXISTING hypothesis pool,
research-hint channels, and CausalGuard authority.

---

## 1. Application Semantic Model (UM-DR-36.1)

**Ontology** (`appmodel/models.py`): 15 entity kinds — organization,
tenant, application, endpoint, workflow, identity, observation (existing)
**plus** principal, role, resource, state, state_transition,
business_invariant, trust_boundary; 16 relation kinds — contains, hosts,
exposes, performs, authenticates_as, observed_on, reachable_from
(existing) **plus** holds_role, owns, operates_on, part_of_tenant,
from_state, to_state, on_endpoint, invariant_on, boundary_of.
Every entity/relation carries provenance (DECLARED/OBSERVED/INFERRED),
deterministic provenance confidence, evidence refs, and merge semantics
(stronger provenance wins; duplicate typed relations refused; relations to
unknown entities refused). The attack-graph projection maps every new kind
onto the frozen vocabulary without inventing node types.

**Reconciliation note (23-entity milestone):** the delivered baseline
declared 7 entity kinds and constructed 6. UM-DR-36 implements 15 kinds,
each with clear semantics and evidence-backed construction. Padding to 23
with meaningless duplicates is prohibited by the directive; the delta is
documented here as the technically justified count: the remaining directive
categories (payment, wallet, discount, recovery-token…) are BUSINESS-LOGIC
instances, not distinct ontology kinds — they materialize as
`business_invariant`/`resource`/`state` entities with typed metadata when
evidence exists, which is the semantically correct representation.

**Builder** (`appmodel/builder.py`): constructs the previously-never-built
vocabulary from REAL channels — `workflow_observations` → WORKFLOW/STATE/
STATE_TRANSITION entities + EXPOSES/FROM_STATE/TO_STATE/ON_ENDPOINT
relations; `object_identity_registry` → RESOURCE + PART_OF_TENANT +
evidence-backed OWNS (inferred ownership NEVER promoted to observed);
`multi_identity_reasoning` → PRINCIPAL/ROLE/HOLDS_ROLE. Honest coverage
gaps recorded for every unmaterialized channel
(`appmodel_no_workflows_derived`, `appmodel_no_resources_derived`, …).
Evidence discipline preserved: declared/observed/inferred separation,
weak signals never get high confidence.

## 2. Production campaign wiring (UM-DR-36.2)

`graph/appmodel_nodes.py::appmodel_node` is registered in the compiled
graph and inserted into the linear segment
`surface_sizing → appmodel → hypothesis` (the surface_sizing/lesson_nodes
pattern: unconditional registration, internal flag gating
`enable_application_semantic_model`, default ON). It runs BEFORE
hypothesis generation so the semantic context (entities, relations,
coverage gaps) is exposed to it; coverage gaps become ordering-only
research hints on the declared `appmodel_research_hints` channel; the
model's projection merges additively into the attack-graph channel when
present. State channels declared (`application_model`, `appmodel`,
`appmodel_research_hints`); construction errors fail closed to recorded
coverage gaps, never fabricated entities.

The funnel node (below) REFRESHES the model at campaign end from the
COMPLETE state (workflow observations and registry materialize during the
campaign), so the campaign artifact records the full model —
"construct or update" + "record newly discovered entities/relationships".
Checkpoints/resume: channels are LangGraph state (checkpointed with the
run), and the model rebuild is deterministic from the persisted channels.

**Runtime evidence** (`umdr36_e2e_campaign_result.json`): the REAL
production entrypoint (`run_unified_hunt` → `build_graph` → compiled
graph stream) against the controlled loopback IDOR lab produced
`application_model` with 7 entities / 6 relations from actual runtime
state (endpoints from crawled data), with honest coverage gaps for the
channels that did not materialize on that target.

## 3. Discovery Funnel (UM-DR-36.3)

`production/discovery_funnel.py` is now **funnel/v2 with 28 stages** (the
24-stage directive minimum + the two alias-resolution detail stages):
recon surfaces, endpoints, parameters, application entities, object
observations, canonical identities, candidate/confirmed aliases,
abstained-or-conflicting, principals, identity relationships, object
ownership relations, authorization observations, differential questions,
workflows, sequence candidates, app states+transitions, hypotheses
generated / in-pool / admitted-by-policy / open / resolved /
deferred-or-untested, **CausalGuard confirmations, ProofBundles created,
replay-verified findings, promotion decisions**, final reportable
findings.

Every stage record carries `count`, `source` (the state channel it
derives from), `complete`, and `unavailable` — missing telemetry is
`not_materialized_in_state`, never a silent zero. All counts derive from
real state channels at call time (surface metrics, workflow/authorization
observations, registry stats, alias graph, appmodel channel, hypothesis
status split, findings authority-chain fields). Drop explanations remain
documented diagnostics.

**Production wiring:** `graph/funnel_nodes.py::discovery_funnel_node`
between reporter and reflection (the coverage_gap_report precedent —
additive, super-step fan-in), flag `enable_discovery_funnel` default ON;
persists on the declared `discovery_funnel` channel, refreshes the final
appmodel, and the campaign summary carries both
(`summary["discovery_funnel"]`, `summary["application_model"]`). The
module was frozen-from-birth: the manifest was re-pinned via the DR-009
protocol (scoped refreeze script with per-file directive mapping) and the
frozen gate passes (647 tests).

**Runtime evidence:** the E2E compiled campaign computed funnel/v2 during
the run — 28 stages, endpoints=3, application_entities=7,
hypotheses_in_pool=12, honest NOT_MATERIALIZED list for unmaterialized
channels.

## 4. Adaptive research — measured information gain (UM-DR-36.4)

`production/information_gain.py`: `MeasuredOutcome` + classify_outcome
(new_information / confirmation / refutation / contradiction / redundant /
uncertainty_resolved / low_information) from OBSERVABLE state deltas —
new facts, evidence classes, questions answered, semantic-model change.
An HTTP response or successful request is never high gain by itself.
`InformationGainLedger.measured_priors()` overrides the static
`_INFO_GAIN_PRIORS` for signal classes with ≥3 measured outcomes.

**Production wiring:** `adaptive_research.generate_research_hypotheses`
merges measured priors over the static table (detail records
`measured_priors_applied` + `measured_outcomes`); the research_campaign
graph merge records measured outcomes from AVI promoted/rejected findings
on the declared `information_gain` channel. The existing
`ExperimentOutcomeTracker` redundancy feedback and
`OutcomeTracker.outcome_aware_penalty` seams are unchanged (no second
scoring pipeline).

**Runtime evidence** (`umdr36_learning_between_decisions.json`): with 3
recorded low-information outcomes for `coverage.observed_not_tested`, the
measured prior **0.15 replaced the static 0.60**, and
`generate_research_hypotheses` applied it — the next research decision
responds to actual prior outcomes.

## 5. Fair discovery scheduling (UM-DR-36.5)

* `HypothesisStatus` gains DEFERRED / BLOCKED / REVISIT_REQUIRED — an
  untested hypothesis is never reported as refuted; the funnel counts
  deferred/untested surfaces honestly.
* `generate_research_hypotheses` now selects candidates by **deterministic
  round-robin interleave across the coverage / invariant / workflow
  pools** (each pool sorted by measured-aware gain desc): every pool's
  best candidate gets an investigation opportunity before any pool's
  second candidate — depth-first myopia is structurally bounded.
  Deterministic, bounded, reproducible for equivalent inputs; recorded in
  `fair_interleave_pools` telemetry.
* No second planner: ResearchLoop / ResearchControlLoop remain the only
  schedulers; the interleave is inside the existing hypothesis-generation
  seam.

## 6. Expected Behavior Model (UM-DR-36.6)

`production/expected_behavior.py`: `BehaviorRule` (family, statement,
provenance, confidence, evidence refs, preconditions, forbidden flag) +
`ExpectedBehaviorModel` + `build_expected_behavior` from REAL channels:
observed workflow transitions → evidenced allowed rules + honest
one-time-use/replay questions; identity registry → evidenced ownership
boundary rule; `operator_expectations` → declared rules. The model
distinguishes observed / operator / inferred / unknown — **an unobserved
transition is an UNKNOWN POLICY question, never a forbidden rule**
(undocumented behavior is not automatically illegal).

**Production wiring:** `identity_workflow_node` (the sanctioned
business-logic producer) builds the model from the same channels it
already consumes; unresolved questions become ordering-only research hints
through the existing `identity_research_hints` seam; the
`expected_behavior_model` state channel carries the record. Validation
discipline unchanged: stateful experiments run only through the authorized
executor with isolated controlled state; CausalGuard confirmation and
ProofBundle/replay remain mandatory.

## 7. Identity and object relationship discovery (UM-DR-36.7)

The UM-DR-32 machinery (ObjectIdentityRegistry's 5-rule deterministic
resolution, alias resolution, multi-identity reasoning, M4 principal
binding) is unchanged and now feeds the semantic model: RESOURCE entities
from registry identity anchors (tenant|type|object_id), PART_OF_TENANT
and evidence-backed OWNS relations, PRINCIPAL/ROLE/HOLDS_ROLE from
validated multi-identity principals. The funnel exposes canonical
identities, alias candidate/confirmed splits, principals, ownership
relations, and differential questions as measured stages. IDOR/BOLA
differential experiments and the CausalGuard authorization-differential
adjudication (UM-DR-35.1) remain the confirmation path — response
similarity alone never promotes.

## 8. OOB verification (UM-DR-36.8) — assessment

The delivered OOB implementation is blind-family validators
(BLIND_SSRF/XXE_OOB/BLIND_SQLI) through the oob_validator, with the API
callback endpoint advisory-only since R3 E-1 (a callback cannot flip
confidence; the poll loop reads the row back). Probe placement across
input locations (URL/query params, headers, cookies, JSON/form/multipart
fields) is inherited from the injection producers; an OOB validator
supporting a callback token does not by itself prove every location
propagates it. **No new blind families were added in this window** — the
directive permits expansion only with a safe, authorized, evidence-backed
experiment design, and the honest assessment is that blind-XSS /
blind-command-injection would require a new governed experiment design
(callback-window binding + candidate/control correlation) that did not
fit this window's remaining budget. Recorded as a documented remaining
capability, not as done.

## 9. Production wiring proofs (UM-DR-36.9)

| Component | Entrypoint | Invocation | Consumer | Failure behavior | Flag | E2E evidence |
|---|---|---|---|---|---|---|
| appmodel node | graph builder (surface_sizing→appmodel→hypothesis) | compiled graph superstep | hypothesis generation + attack-graph merge + hints | fail-closed coverage gaps | enable_application_semantic_model (ON) | 7 entities/6 relations from runtime state |
| discovery funnel node | graph builder (reporter→funnel→reflection) | compiled graph superstep | campaign summary + artifact + downstream research | honest not-computed marker | enable_discovery_funnel (ON) | funnel/v2 computed in-campaign |
| measured info gain | research_campaign merge + adaptive_research | every hypothesis generation pass | generate_research_hypotheses ranking | static priors retained | always-on (channel-driven) | 0.60→0.15 prior override |
| fair scheduling | adaptive_research | every generation pass | hypothesis pool order | deterministic interleave | always-on | fair_interleave_pools telemetry |
| expected behavior | identity_workflow_node | flag-gated identity pass | research hints + model channel | skip (context-only) | UM-DR-32 capability flags | 60 identity suites green |

## 10. End-to-end demonstration (§5)

**Compiled-graph campaign** (`scripts/umdr36_e2e_compiled_campaign.py`,
artifact `umdr36_e2e_campaign_result.json`): the production entrypoint
executed the real compiled LangGraph against the controlled loopback IDOR
lab (deterministic path, authorized auto-approve, explicit 1,000,000-token
ceiling). Verified at runtime: application_model materialized from actual
runtime state; funnel/v2 computed during the campaign with honest
NOT_MATERIALIZED markers; budget record with the explicit ceiling and
COMPLETED status; 3 findings produced. **PASS.**

**Learning between decisions**
(`scripts/umdr36_learning_between_decisions.py`, artifact
`umdr36_learning_between_decisions.json`): on the REAL
ResearchControlLoop (constructed through the production factory), the
initial selection (surface_a) changed to surface_b after recording
surface_a's low-information outcome through the loop's own outcome API,
and measured priors replaced the static table. The next decision was NOT
identical regardless of the observation. **PASS.**

**Honest negative/inconclusive behavior:** the UM-DR-35 test battery
proves refuted/inconclusive/out-of-scope/budget-exhausted/tampered
outcomes never become false confirmations (24 confirmation-authority
tests + replay mutation tests + walk-skeleton REFUTED/CLEAN/B11 cases);
the E2E campaign's honest funnel reports unmaterialized channels instead
of zeros.

## 11. Verified capability and limitations

**Verified:** sole confirmation authority; strict replay; unified scope;
honest authentication; hard budgets; verified supply chain; semantic
model from runtime state; 28-stage funnel produced in-campaign; measured
information gain changing subsequent decisions; fair interleave; expected
behavior rules with explicit uncertainty; E2E compiled-graph campaign.

**Limitations (explicit):**
* GitHub publication/PR/remote CI: BLOCKED (no credentials) — local,
  reproducible evidence only.
* OOB expansion beyond the delivered blind families: NOT IMPLEMENTED
  (documented assessment above).
* The E2E campaign's appmodel on the minimal lab target materialized
  recon-stage entities; workflow/registry/principal channels require the
  UM-DR-32 capability flags ON and richer targets — reported honestly as
  coverage gaps, never fabricated.
* Independent M10 holdout evaluation and formal XBOW benchmarking remain
  out of scope (per the directive); all lab evidence is team-authored
  fixtures and is labeled as such.
* Ablation comparison (baseline vs static-prior vs measured selection)
  was executed as the learning demonstration (selection change + prior
  override), not as a full multi-campaign statistical ablation.

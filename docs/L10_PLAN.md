# Mission L10 Plan — Cross-Application Stateful Reasoning & Generalization

Executed against the L9 release state (commit `98be8c6`, ZIP
`webpent_l9.zip` SHA-256
`243de532525f576c8980259c8f87ad1b48670113d2c82988f19c5849f46bc3d4`,
verified). Every phase ends in its own commit(s); gates run before
any release. Standing constraints carried from L8/L9: no weakening
of ActionAuthority / ActionExecutor / G-02 / scope / CausalGuard /
ProofBundle; LLM output never establishes a finding; synthetic
loopback fixtures only, no real-world generalization claims; the
held-out blocks are measured once, after dev freezes, and never
tuned against. `download/econ/portfolio_transitions.jsonl` stays
untracked and out of every release ZIP.

## Phase 0 — Baseline reproduction & preservation (§Phase 0)

- Verify HEAD is `98be8c6` and the ZIP digest matches the manifest.
- Full `make ci` gate at the release state, log captured
  (`docs/l10_gate_logs/`).
- Re-run `scripts/l9_planner_matrix.py dev` and `heldout_l9`;
  compare aggregates field-by-field (outside wall-clock seconds)
  against the committed L9 JSONs. Any discrepancy is investigated
  before L9 is used as the comparison baseline.
- Held-out hygiene check: the engine and planner packages must not
  reference the held-out apps (`ledgerflow`, `berth`); pinned by
  the existing isolation tests, re-verified.
- Deliverable: `docs/L10_BASELINE.md` (reproduction report).
- No code changes in this phase.

## Phase 1 — Independent application corpus (dev block)

A NEW generation-3 appsuite block, independently implemented —
different endpoint naming, state representations, ownership models,
transition mechanisms, enforcement locations, response formats,
prerequisite shapes, and architecture patterns from the L6-L9
corpora. Two new applications, four variants each (defective,
secured, plus two adversarial variants drawn from §Phase 9:
transition-succeeds-no-vuln, unavailable/forbidden prerequisite).
Ground truth declared in `appsuite/groundtruth.py` with precise
oracles and explicit negative-control expectations. No held-out
route names, identities, labels or state sequences anywhere in
engine or planner code. Isolation tests extended (vocabulary
disjointness, import independence). Red-first: the corpus is built
BEFORE the engine work that must discover it.

## Phase 2 — Generalized state and workflow model

Extend the L9 state model (`prerequisites.py`, `planner.py`) into a
generalized assertion ledger with provenance and a four-valued
epistemic status: VERIFIED (authoritative observation), INFERRED
(hypothesized, unverified), UNKNOWN (insufficient evidence),
INVALIDATED (contradicted by later evidence). Inferred/unknown
state can never auto-promote to verified; contradictions trigger
explicit invalidation and downstream re-evaluation of dependent
assertions. No fixture-specific state machine: the model reads only
surface observations through the existing relationship view.
Red-first unit tests for promotion, invalidation and reconciliation.

## Phase 3 — Cross-application prerequisite reasoning

Generalize the L9 planner's setup derivation so it operates on the
assertion ledger rather than on the L9 workflow-transition kind
alone: multi-step dependency graphs over any precondition kind,
minimal-sequence derivation, read-only preference, postcondition
verification by re-read, replanning on unexpected results, and the
mission's outcome vocabulary (authorization denied / identity
unavailable / ownership unmet / transition unavailable / executed
but state not reached / established / established-but-not-vuln /
boundary violation / inconclusive / blocked) mapped onto the
existing fail-closed dispositions — operational failure is never a
finding, and successful setup execution is never evidence of a
vulnerability. Red-first tests on the Phase 1 corpus.

## Phase 4 — Novel workflow discovery

A bounded workflow-discovery component: candidate transition
discovery from observed operations and response changes, dependency
inference, state-reachability reasoning, information-gain/cost
prioritization, contradiction detection, recovery from failed
transitions, duplicate suppression, and resumable investigation
memory. Explicit budgets on discovery rounds and setup actions; no
uncontrolled combinatorial exploration; nothing "invents" a
transition that was not observed to succeed. Red-first tests.

## Phase 5 — Researcher-quality selection + strategy matrix

Selection integrates expected information gain, prerequisite
availability, hypothesis confidence, expected cost, historical
outcomes, evidence quality, reversibility, and remaining budget;
experiments whose prerequisites are known-unavailable are not
retried; redundant mutations are suppressed. Matrix script
`scripts/l10_matrix.py`: A = L9 baseline engine, B = L10 planner,
C = B with prerequisite reasoning disabled, D = fixed prerequisite
strategy (equivalent budget), E = B with information-gain selection
disabled (hypothesis generation and state reasoning preserved).
Budgets 2/4/8/16/32. DEV block measured first; results in
`docs/l10_matrix_dev.json`.

## Phase 6 — Evidence integrity preserved

All L8/L9 evidence contracts unchanged and re-verified by the §5
invariant suite extended to the new components: CausalGuard
confirmation + sealed replay-valid ProofBundle for every finding;
confirmed / rejected / inconclusive / blocked / failed-prerequisite
/ operational-error stay distinct; the planner can never
manufacture a finding or bypass the pipeline. Invariant tests added
for the generalized planner (state assertions are not evidence;
setup success is not a verdict; invalidated state forces
inconclusive, never clean).

## Phase 7 — Blind generalization evaluation

A fresh held-out block (new applications, independently implemented,
including unfamiliar state representations, multi-step identity
scenarios, unavailable/forbidden prerequisites,
transition-succeeds-no-vuln controls, and replanning cases), built
and frozen BEFORE the dev matrix is analyzed in detail, measured
once after the dev configuration freezes. Every miss classified in
`docs/L10_FAILURE_ANALYSIS.md` by failed reasoning stage (§Phase
10 taxonomy). If tuning follows, a NEW held-out block is cut; a
rerun is never presented as untouched.

## Phase 8 — Metrics and scientific evaluation

Machine-readable records (JSON per run + JSONL summary): unique
TP/FP/FN, precision, recall, F1, requests per unique confirmed
finding, first-confirmation budget and time, prerequisite
accounting (identified/verified/invalidated/unavailable), state
transitions succeeded/failed, replanning frequency, duplicate
experiments and mutations, hypothesis status tallies, ProofBundle
and replay validity, findings with complete causal evidence.
Defect-level deduplication (a defect counts once); duplicate
confirmations reported separately; failed setups never mixed with
findings; every miss carries a causal failure analysis.

## Phase 9 — Adversarial negative controls

Woven into the corpus (Phase 1) and held-out block (Phase 7):
owned-by-other resources with correct enforcement, valid
transitions that cross no boundary, identity switches with intact
session isolation, legitimate business-logic response differences,
unavailable prerequisites that must stop the engine, idempotent
repeats, correctly-denied authorizations. Target: real defects
found at zero unsupported findings; no FP-for-recall trade.

## Phase 10 — Failure-driven improvement

Every missed defect on DEV (and, after freeze, held-out)
reproduced, attributed to a reasoning stage, classified general
vs benchmark-specific, fixed with a general mechanism plus a
minimal regression test and a secure negative control — never a
label/route/ID patch. Prior fixes verified not to regress earlier
capabilities.

## Phase 11 — Full regression and release

Full `make ci` (regression suite, coverage, lint, Bandit), plus the
L10 test additions. Release from the exact release commit:
`docs/L10_ARCHITECTURE.md`, `docs/L10_BENCHMARK_DESIGN.md`,
`docs/L10_DELIVERABLES.md`, `docs/L10_FAILURE_ANALYSIS.md`,
`docs/L10_RELEASE_MANIFEST.md`, machine-readable records,
`webpent_l10.zip` cut with `git archive`, SHA-256 published and
verified, exclusion of `download/econ/portfolio_transitions.jsonl`
confirmed, clean tree. Honest acceptance statement against the
mission's twelve criteria, including whether the L10 planner
outperformed the baselines.

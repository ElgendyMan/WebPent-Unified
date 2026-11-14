# Mission L9 Plan — Stateful Investigation Planning & Prerequisite Reasoning

Executed against the L8 release state (commit `48eb45b`, ZIP SHA-256
`435c0e32…650734`, verified at the start of this session). Every
phase below ends in its own commit(s); gates run before any release.

## Phase 0 — Baseline reproduction (§1)

1. Verify release commit and ZIP digest (done above).
2. Fresh full `make ci` gate at the L8 release commit; log to
   `docs/l9_gate_logs/`.
3. Re-run `scripts/l8_discovery_matrix.py dev` and `heldout`; compare
   raw per-run records field-by-field against the committed L8
   artifacts (wall-clock excluded, as in L8's §1). Record the exact
   held-out result (all four strategies 2/0/4) in
   `docs/L9_BASELINE.md`.
4. The L8 held-out set (ticketflow, slots) is reproduced here and
   NEVER used for L9 implementation or tuning: its workflow-identity
   failure mechanism was already diagnosed in L8, so a fresh
   held-out is mandatory (Phase 5).

## Phase 1 — Architecture: structured preconditions (§2)

New module `src/webpent/egaie/prerequisites.py`:

- `Precondition` record: kind (identity | ownership | app_state |
  prior_observation | workflow_transition | capability | budget |
  evidence), target, status (observed | inferred | establishable |
  unattainable), and the observation or action that would verify or
  establish it. Inferred is never reported as observed; `status` is
  machine-enforced by construction (only `observed` entries can be
  set from recorded observations).
- Each hypothesis gains a `prerequisites` list; existing hypothesis
  generation fills it from the same wire view the probes use (no
  new authority assumptions). A hypothesis with an `unattainable`
  precondition is parked, not executed and not scored as secure.

Red-first tests: a hypothesis built only from observations shows
`observed`; a hypothesis whose precondition references an
unobserved state shows `inferred` and cannot be confirmed until the
precondition is verified.

## Phase 2 — Bounded stateful planner (§3)

New module `src/webpent/egaie/planner.py`, consumed by the
strategies layer (opt-in via strategy configuration, so strategy A
runs the unchanged L8 engine):

- Dependency graph over hypotheses × observations × prerequisite
  actions, built from the wire view and the hypothesis
  prerequisites.
- Selection: prefer read-only observations that resolve
  uncertainty; propose a state-changing setup action only when
  authorized, in-scope, and the cheapest path to a discriminating
  experiment; each setup action carries an idempotency key through
  the existing ActionAuthority/ActionExecutor path and is recorded
  as an explicit investigation action (never silent).
- Re-evaluate after every result (no fixed sequences); a failed
  setup records the block reason (authorization | unavailable |
  transition_without_effect) and the hypothesis becomes blocked or
  inconclusive — never a negative verdict, never a finding.
- Stop conditions: falsified, evidence sufficient, precondition
  unattainable, budget exhausted. Budget accounting counts setup
  actions in the same request budget as probes.

Preserved untouched: ActionAuthority, ActionExecutor, G-02, scope,
CausalGuard, ProofBundle, sealing, replay. The planner proposes
through the same channels the proposer uses today.

## Phase 3 — Workflow-identity root cause and fix (§4)

Development case: the L8 failure analysis documents the mechanism
(identity checked before order; the probe never drives the
candidate action's required source state; a 409 from the edge table
reads as enforcement). To honor "do not tune against the L8
held-out set", the fix is developed on a NEW dev-corpus workflow
application that exhibits the same shape without reusing
ticketflow's implementation, route names, identities or labels:

- `src/webpent/appsuite/requisitions.py` (5th appsuite app, DEV
  block, WORKFLOW_IDENTITY family, defect = identity check skipped
  for one collection's tickets, transition table enforced
  elsewhere). Wired into ground truth, corpus and the isolation
  tests.
- Fix in the engine (generic, smallest justified): when a
  transition probe requires a source state, the planner derives the
  prerequisite transition chain from observed state data (the
  app's own state description), executes authorized setup
  transitions through ActionAuthority, and distinguishes the five
  §4 outcomes (auth-denied before state reached / prerequisite
  unavailable / transition succeeded without establishing state /
  precondition met then genuine boundary violation /
  inconclusive-evidence). No held-out names, identities, or labels
  anywhere.
- Red-first tests on the new dev app: before the fix the scoped
  workflow-identity defect is a FN; after, it is confirmed; the
  secured variant remains unflagged.

## Phase 4 — Invariants (§5)

Regression sweep asserting: no planner path bypasses ActionAuthority;
HTTP 200 alone never confirms a transition (state re-read required);
blocked/inconclusive never become findings or secure negatives;
all sealed bundles replay. Existing suites stay green.

## Phase 5 — Fresh blind held-out (§7 data)

Two new applications, authored independently, never opened before
the DEV work is committed:

- `src/webpent/appsuite/ledgerflow.py`: approval-chain state
  machine (single active state pointer; transitions declare
  required role and required prior state) with a multi-step
  identity-boundary defect and a secured variant.
- `src/webpent/appsuite/berth.py`: booking/hold pipeline with
  timestamped stage windows (different state representation), an
  unavailable-prerequisite case (the setup transition is
  legitimately forbidden for the investigator), a
  transition-succeeds-but-implies-nothing case, and negative
  controls.

Variant taxonomy extended for L9: defective, secured,
unavailable_prereq, transition_no_vuln, negative_control. Both apps
join a fresh `heldout_l9` block; isolation tests extended to them.

## Phase 6 — Fair-baseline evaluation (§6)

`scripts/l9_planner_matrix.py` over DEV (incl. requisitions) and
the fresh held-out, budgets matched to L8 (2/4/8/16/32):

- A: L8 engine unchanged.
- B: stateful planner enabled.
- C: planner with prerequisite reasoning disabled, candidate
  generation equivalent to B (ablation inside the planner).
- D: fixed prerequisite strategy, independently generated (a
  static per-family setup recipe list built without reading B's
  planner logic), same execution budgets.

Per-instance metrics as listed in §6, including prerequisites
identified/verified/failed/unknown, hypotheses
rejected/inconclusive/blocked, duplicate mutation count, sealing
and replay validity, by family and implementation.

## Phase 7 — Blind evaluation and per-miss root cause (§7)

Run Phase 6's held-out legs once, after DEV analysis freezes.
Every miss classified: prerequisite inference | planning |
execution | state interpretation | evidence | classification.
Recorded in `docs/L9_FAILURE_ANALYSIS.md`.

## Phase 8 — Deliverables (§8)

`docs/L9_BASELINE.md`, root-cause doc, architecture/data-flow
section, red-first test results, budget-matched per-instance
tables, raw JSON records, gate logs, commit inventory, manifest,
`webpent_l9.zip` + verified SHA-256, and the explicit statement of
whether prerequisite reasoning improved untouched held-out
discovery (or did not).

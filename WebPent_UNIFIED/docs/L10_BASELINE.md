# L10 Baseline Reproduction Report (Phase 0)

Baseline: the L9 release, commit `98be8c6` ("docs: L9 release
manifest and final gate log"). ZIP `webpent_l9.zip`, SHA-256
`243de532525f576c8980259c8f87ad1b48670113d2c82988f19c5849f46bc3d4`,
recomputed and matched the `docs/L9_RELEASE_MANIFEST.md` value at
session start. No result below was reproduced by re-running only
some of it; everything is re-executed at this baseline.

## Test suite and quality gates

Full `make ci` re-run at the release state, log captured at
`docs/l10_gate_logs/gate_baseline_20261030T042041Z.log`:
regression suite (target 4536 passed, floor 1940), coverage above
its 35% floor, lint all checks passed, Bandit high-severity clean.
The L9 release gate result is reproduced.

## Benchmark reproduction

`scripts/l9_planner_matrix.py` re-run for BOTH blocks at the
baseline, and the regenerated JSONs compared field-by-field
(structural walk over every run record and aggregate) against the
committed `docs/l9_planner_dev.json` and
`docs/l9_planner_heldout_l9.json`:

- DEV block: 0 differing fields outside the wall-clock `seconds`
  fields (200 run records, 4 strategies × 10 instances × 5 budgets,
  plus aggregates).
- heldout_l9 block: 0 differing fields outside `seconds`.

The L9 §6 headline is therefore reproduced exactly: held-out at
budget 32, A 0/0/2 (recall 0.0), B 2/0/0 (recall 1.0), C 0/0/2,
D 2/0/0; zero false positives anywhere on the block; B confirms
lf-151 at budget 8 and bh-161 at budget 16; the DEV block ties all
four strategies with the pre-existing dv-103 ambiguous FP disclosed
in `known_preexisting_fp`. The committed JSONs were restored after
the comparison so the baseline tree stays byte-identical to the
release commit's content.

## Held-out hygiene

`grep` over `src/webpent/egaie/` finds zero references to
`ledgerflow` or `berth`: the engine, planner, prerequisites and
benchmark modules carry no held-out app names, routes, identities
or state sequences. The mechanical isolation tests
(`tests/appsuite/test_isolation.py`, 24 tests) pass in the full
suite: external vocabulary disjoint from both prior corpora, no
appsuite module imports fixture or labsuite implementation
modules, no appsuite module imports the ground truth. One latent
fragility was FOUND and recorded, not hidden: the isolation test
resolves `webpent.appsuite.<name>` via package attributes, which
are registered as a side effect of `corpus` being imported by
other tests; run standalone, the file fails on that attribute
lookup rather than on any real independence violation. L10 will
fix the test to import the corpus itself so the assertion is
deterministic (a test-robustness fix; the independence claim it
asserts is unchanged and was never violated).

## Architecture inventory (what L10 builds on)

- **Prerequisite model** (`src/webpent/egaie/prerequisites.py`):
  per-precondition kinds (identity, ownership, app state, prior
  observation, workflow transition, capability, budget, evidence),
  ledger statuses `observed | inferred | establishable |
  unattainable`, and `UnattainableEffect.NEVER_A_VERDICT` pinning.
- **StatefulPlanner** (`src/webpent/egaie/planner.py`): per-
  hypothesis precondition ledger, dependency-graph setup
  derivation (minimal authorized transition sequences), read-only
  preference, re-read verification, setup-failure blocking, parked
  hypotheses, `PlannerConfig(prerequisite_reasoning=...)` ablation.
- **Orchestrator remediation hook**
  (`src/webpent/egaie/orchestrator.py`): one bounded cycle per
  ACTION_BLOCKED-inconclusive outcome; delegates to an optional
  independent `remediator` (baseline D) or the planner (B/C);
  setup rides the production ActionAuthority/ActionExecutor path
  with G-02 idempotency; remediated re-runs get their own tokens
  (distinct investigation steps) while plain repetitions
  deduplicate.
- **Selection** (`src/webpent/egaie/selection.py`):
  InformationGainSelector over pending experiments.
- **Differential engine** (`src/webpent/egaie/differential.py`):
  DifferentialProposer, RelationshipTracker's surface view,
  fail-closed dispositions (ACTION_BLOCKED, IDENTITY_BOUNDARY, ...),
  CausalGuard-style validation oracle.
- **Evidence path**: sealed ProofBundle port, replay verification,
  observation ledger — unchanged from L8, re-verified by
  `tests/egaie/test_l9_invariants.py` and the suites below.

All existing user changes and project data are preserved; no
protected files modified in this phase.

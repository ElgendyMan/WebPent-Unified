# L9 Deliverables — Stateful Investigation Planning & Prerequisite Reasoning

Scope statement first, so nothing else in this document can be
misread: every number below is measured on synthetic loopback
fixture applications running inside this repository's own benchmark
harness. They characterize the engine against independently
implemented test applications; they support no claim about
real-world systems of any kind. LLM output never establishes a
finding anywhere in the loop; every verdict rests on observed
request/response pairs and sealed, replay-verified proof bundles.

## 1. Reproduction of the L8 release (starting point)

Recorded in `docs/L9_BASELINE.md`: the L8 release commit `48eb45b`
and ZIP `webpent_l8.zip` (SHA-256
`435c0e32e2b6a0ff1a2c78139c8a912b43b4026ac8584594ab94fceb34650734`)
verified at session start; full gate reproduced (4491 passed,
coverage 61.64%, lint and Bandit high-severity clean, both authority
gates OK); the 160-run L8 discovery matrix re-run field-identical
(0 differing fields outside wall-clock) on both blocks. The L8
held-out set is never used for L9 implementation or tuning, and its
instances are excluded from the fresh L9 held-out block.

## 2. Architecture and data flow

What L9 adds to the L8 engine, in one flow:

1. **Structured preconditions (§2).** Every hypothesis now carries
   declared preconditions with kinds (identity, ownership, app
   state, prior observation, workflow transition, capability,
   budget, evidence), each holding a ledger status
   (`observed | inferred | establishable | unattainable`) and, for
   the unattainable ones, a verdict effect that is hard-pinned to
   `NEVER_A_VERDICT`. An inferred precondition is recorded as
   inferred and is never treated as a verified fact: only the
   re-read of an executed setup step moves a status to observed.
   Module: `src/webpent/egaie/prerequisites.py`.
2. **The stateful planner (§3).** `StatefulPlanner`
   (`src/webpent/egaie/planner.py`) keeps a per-hypothesis
   precondition ledger, derives setup transitions from a dependency
   graph over the surface's observed workflow view (minimal
   sequences: the fewest authorized transitions that reach the
   source state the probe needs), prefers read-only establishment,
   executes setup only through the production action path
   (ActionAuthority → ActionExecutor, scope, capability checks,
   G-02 idempotency, observation ledger — unchanged), verifies each
   transition by a read-only re-read (never the setup's own HTTP
   status), records setup failures as blocks, and parks hypotheses
   whose preconditions cannot be established. `max_setup_actions`
   bounds the total setup spend; `round_budget_exhausted` still
   terminates the run on budget.
3. **The remediation hook (§3/§5).**
   `InvestigationOrchestrator._remediate`
   (`src/webpent/egaie/orchestrator.py`) fires exactly once per
   blocked outcome, and only when the oracle classified the outcome
   as `inconclusive` with disposition `ACTION_BLOCKED` — a state
   refusal naming the surface's own state field is a precondition
   failure, never an identity decision and never a clean verdict.
   A failed setup blocks the hypothesis in the ledger and never
   becomes a negative security verdict, and never strands the other
   establishable preconditions of the same hypothesis.
4. **Remediated re-runs are distinct investigation steps (§5).**
   The experiment port gains a remediation ordinal:
   `mark_remediated()` derives the re-run's idempotency tokens from
   the ordinal, so the executor's replay guard no longer collapses
   a post-remediation re-run into the first pass, while plain
   repetitions keep the original tokens and deduplicate (G-02
   intact for repetitions). Regression tests:
   `tests/egaie/test_remediation_replay.py`.
5. **Workflow-identity discrimination fixed generically (§4).** The
   judge (`_judge_workflow_identity` in
   `src/webpent/egaie/differential.py`) classifies a candidate
   refusal by the surface's own response vocabulary: a body naming
   the workflow's state field is a state-machine refusal (blocked
   precondition, inconclusive), and an identity-shaped refusal
   consults the control before any clean verdict — a
   granted-and-applied third-party control while the candidate was
   refused on its target IS the defect under test, unless the
   accepting path is the surface's own documented-open intake.
   Nothing in the change references any held-out route name,
   identity or label; the shared `documented_open` scan is derived
   from each surface's own published strings.
6. **Baseline D, the independent fixed prerequisite strategy (§6).**
   `src/webpent/egaie/benchmark/fixed_prerequisites.py` holds a
   static per-family recipe list and fires it verbatim on blocked
   outcomes through the same production path. It imports nothing
   from `webpent.egaie.planner` (pinned structurally in
   `tests/egaie/test_strategy_baselines.py`), derives no dependency
   graph, and computes no minimal sequences.

Baseline wiring for the §6 matrix (only one line changes between
strategies): A = the L8 adaptive engine unchanged (no planner, no
remediator); B = `orch.planner = StatefulPlanner(PlannerConfig())`;
C = `StatefulPlanner(PlannerConfig(prerequisite_reasoning=False))`
— identical candidate generation, remediation gated off; D =
`orch.remediator = FixedPrerequisiteRemediator()`.

## 3. Red-first test results

The §4 fix on the NEW dev application (`requisitions.py`, the fifth
appsuite app) was developed red-first: before the judge change the
scoped workflow-identity defect on a defective requisitions
instance was never confirmed (the candidate 409 read as clean);
after it, the defect confirms and the secured/ambiguous variants
stay unflagged (evidence recorded in commit `de5ace1`). The full
L9 regression surface at release state: 54 tests across
`test_l9_invariants.py` (6, §5 invariant sweep), `test_planner.py`
(11), `test_prerequisites.py` (7), `test_strategy_baselines.py` (4),
`test_remediation_replay.py` (2), plus the appsuite discovery and
isolation suites extended to `requisitions`, `ledgerflow` and
`berth`. All green; the full gate (below) passes with 4536 tests.

## 4. Budget-matched results (§6)

Four fair baselines (A `l8-engine`, B `planner`, C
`planner-no-prereq`, D `fixed-prereq`), round budgets 2/4/8/16/32,
identical observation contract, oracle, sealed-bundle port,
authority/execution path, idempotency discipline and budgets.
Raw records: `docs/l9_planner_dev.json` (DEV block, measured
first), `docs/l9_planner_heldout_l9.json` (held-out, measured once
after DEV froze). Metric units are declared in each JSON.

### DEV block (docvault, market, slots, ticketflow, requisitions) at budget 32

| strategy | tp | fp | fn | P | R | requests | req/tp | first-conf |
|---|---|---|---|---|---|---|---|---|
| A `l8-engine` | 6 | 1 | 0 | 0.857 | 1.0 | 395 | 65.8 | 4.33 |
| B `planner` | 6 | 1 | 0 | 0.857 | 1.0 | 395 | 65.8 | 4.33 |
| C `planner-no-prereq` | 6 | 1 | 0 | 0.857 | 1.0 | 395 | 65.8 | 4.33 |
| D `fixed-prereq` | 6 | 1 | 0 | 0.857 | 1.0 | 419 | 69.8 | 4.33 |

Per-instance (budget 32, tp/fp/fn@requests): dv-101 1/0/0@36 (all
strategies), dv-103 0/1/0@39 (the pre-existing ambiguous
`/orbit/osier-notice` IDENTITY_BOUNDARY FP, identical under all
four strategies including A and already recorded in the frozen L8
dev matrix — L9 introduced no new FP), dv-104 1/0/0@36, mk-111
1/0/0@21, mk-114 1/0/0@21, rq-141 1/0/0@41, rq-144 1/0/0@41 (49 for
D). The DEV block's defects do not sit behind unmet prerequisites,
so all four strategies tie; the planner's ledger shows 6
`establishable` workflow-transition preconditions for B and zero
establishment activity for C, and D's recipe verified 6/6.

### Held-out L9 block (ledgerflow, berth; five variants each), measured once

At budget 32:

| strategy | tp | fp | fn | P | R | requests | req/tp | first-conf |
|---|---|---|---|---|---|---|---|---|
| A `l8-engine` | 0 | 0 | 2 | — | 0.0 | 317 | — | — |
| B `planner` | 2 | 0 | 0 | 1.0 | 1.0 | 495 | 247.5 | 12.0 |
| C `planner-no-prereq` | 0 | 0 | 2 | — | 0.0 | 317 | — | — |
| D `fixed-prereq` | 2 | 0 | 0 | 1.0 | 1.0 | 541 | 270.5 | 12.0 |

Per-instance (budget 32, tp/fp/fn@requests): lf-151 defective
0/0/1@31 (A, C) vs 1/0/0@57 (B) and 1/0/0@63 (D); bh-161 defective
0/0/1@51 (A, C) vs 1/0/0@77 (B) and 1/0/0@83 (D); all six clean
variants (lf-152, bh-162 secured, bh-163 unavailable_prereq, bh-164
transition_no_vuln, bh-165 negative_control) unflagged under every
strategy at every budget — zero false positives anywhere on the
block.

Discovery curves on the two defective instances:

| budget | A | B | C | D |
|---|---|---|---|---|
| 2 | miss ×2 | miss ×2 | miss ×2 | miss ×2 |
| 4 | miss ×2 | miss ×2 | miss ×2 | miss ×2 |
| 8 | miss ×2 | lf-151 ✓ | miss ×2 | lf-151 ✓ |
| 16 | miss ×2 | lf-151 ✓ bh-161 ✓ | miss ×2 | lf-151 ✓ bh-161 ✓ |
| 32 | miss ×2 | both ✓ | miss ×2 | both ✓ |

Prerequisite accounting at budget 32: B's ledger on the block
totals `observed` 34, `establishable` 23, `unattainable` 1 (the
bh-163 unavailable-prereq entry, carrying `NEVER_A_VERDICT`, so the
count `unattainable_never_a_verdict` = 1); C's ledger is empty of
transition preconditions and records zero establishment (the
ablation's honest record); D's recipe tallies 56 identified, 55
verified, 1 failed (bh-161's gated path; failed closed, no
verdict), 1 unknown. Every miss on the block is classified per-miss
in `docs/L9_FAILURE_ANALYSIS.md`: A and C miss both defects at
every budget (prerequisite inference — a mechanism gap), B and D
miss only at budgets 2–4 (and 8 for berth) as a round-budget
artifact that resolves by rounds 8–16 (planning under budget).

## 5. Invariants held (§5)

All locked by `tests/egaie/test_l9_invariants.py` and the
regression suites: no ActionAuthority bypass (planner setup rides
the production path); an HTTP 200 from a setup step never proves a
transition (the re-read decides; a reported-applied transition
whose re-read shows the pre-submission state is inconclusive
EVIDENCE_MISSING, never a finding); blocked and inconclusive
outcomes never become findings or secure negatives; unattainable
preconditions are hard-pinned to NEVER_A_VERDICT; sealed bundles
replay-verify; the G-02 replay guard still deduplicates plain
repetitions while remediated re-runs execute on their own tokens.

## 6. Raw records, gate logs

Raw JSON: `docs/l9_planner_dev.json`, `docs/l9_planner_heldout_l9.json`
(full run records for all 4 strategies × 10 instances × 5 budgets,
plus aggregates, strategy definitions, metric units, the
`known_preexisting_fp` disclosure and the phase-order note). Root
causes: `docs/L9_FAILURE_ANALYSIS.md`. Gate logs:
`docs/l9_gate_logs/gate_baseline_adc6a39_20261026T171521Z.log`
(L8 baseline) and `docs/l9_gate_logs/gate_run_20261029T183832Z.log`
(release gate: 4536 passed, coverage 62.28%, lint clean, Bandit
high-severity clean).

## 7. Honest statement: did prerequisite reasoning help?

Yes, on the mission's own terms. On the untouched blind held-out
block, baseline A (the unchanged L8 engine) and baseline C (the
planner with prerequisite reasoning ablated) confirmed 0 of the 2
ground-truth defects at every budget — recall 0.0. Baseline B, the
same engine plus the stateful planner's prerequisite reasoning,
confirmed both at zero false positives (recall 1.0), with the gap
closing at budgets 8–16; baseline D, the independently written
fixed recipe, reaches the same recall at 46 more requests and
fails closed on its one failed setup. Because C is byte-identical
to B except for the ablated reasoning and reproduces A's miss
exactly, the ablation isolates prerequisite reasoning as the
component that closes the gap. On the DEV block, where no defect
sits behind an unmet prerequisite, all four strategies tie, so the
planner bought nothing there and cost nothing. The measured
advantage is specific to defects behind state prerequisites, and
these are synthetic two-stage fixtures: deeper chains would widen
the planner's advantage over the fixed recipe by construction, but
that claim is extrapolation, not a measured result on these blocks,
and nothing here generalizes to real-world systems.

## 8. Release

Commit inventory, key file digests, and the archive are in
`docs/L9_RELEASE_MANIFEST.md`; the ZIP is `webpent_l9.zip`, cut
with `git archive` from the release commit. The never-committed
`download/econ/portfolio_transitions.jsonl` stays untracked and is
structurally excluded from the archive (it is not in the
repository).

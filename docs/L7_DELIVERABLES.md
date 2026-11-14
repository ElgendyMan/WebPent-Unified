# L7 Deliverables — Independent Discovery Benchmark & Ablation Integrity

Mission L7 is complete as of this document's commit. This file states
what was built, what was measured, and what those measurements do and
do not support. The standing honesty constraints were binding through
every step and are repeated where they apply:

- LLM output may propose or rank hypotheses but never independently
  establishes a finding; only executed, sealed, replay-verified
  differentials confirm.
- Fixture-local or synthetic loopback performance is never reported as
  real-world bug-hunting capability.
- No claim of adaptive superiority unless the measured results
  demonstrate it (see the measured verdict in section 8).
- `download/econ/portfolio_transitions.jsonl` was never staged or
  committed by L7 work; an early review-baseline commit had tracked
  it, and the deliverables commit untracks it and ignores it going
  forward, so the release ZIP (cut from committed content only)
  structurally excludes it.

## 1. Reproduction (done pre-L7, commit `87f00ca` baseline)

The L6 release was reproduced before any L7 change: gates green, L6
evaluation artifacts intact. L7 commits build on that state.

## 2. Equal-budget tie instrumentation (commit `e800a6d`)

`webpent.egaie.benchmark.instrumentation` adds, per run:
`run_trace` (candidate pool, executed signature sequence, outcome
tally, rounds used, terminal reason, budget binding, duplicate
experiments) and `compare_traces` (executed-set overlap, order
divergence, confirmed-set overlap) for two runs at the same budget.
`proposal_log` records every proposal decision. The point of this
step: when two configurations tie at equal budget, the tie is
measurable in execution traces rather than asserted. Red-first tests
pin the trace shape and the comparison semantics.

## 3. Independent held-out corpus (commit `3b7bce0`)

`webpent.labsuite` is a separately implemented loopback evaluation
suite: `lab_target.py` (deployment profiles), `corpus.py`
(DEV 101-104, HELD-OUT 201-203/211-213, negatives 301-302),
`evaluator.py` (ground truth from implementation profiles, applied
only AFTER investigation). No L6 fixture logic is imported anywhere
under `labsuite`; the isolation tests in `tests/labsuite/` enforce
this by construction (fresh interpreters with no fixture code loaded
must still exercise the engine, and the evaluator refuses to leak
labels into the engine path). Lab family keys map to the engine's
canonical labels only after a run finishes. The corpus carries at
least one invariant family L6 tuning never saw (the grant-replay
family), plus secured lookalikes in every family so false positives
on secured deployments are detectable.

## 4. Four fair configurations (commit `2c92e32`)

`webpent.egaie.benchmark.strategies` builds, from one factory, the
four section-4 configurations:

| config | name | proposer | selection |
|---|---|---|---|
| A | `adaptive` | engine generators | adaptive scheduler |
| B | `independent-fixed` | `IndependentProposer` (own generators, own view API, advisory-only origins) | fixed order |
| C | `adaptive-no-selector` | engine generators | no selection policy |
| D | `observation-baseline` | `ObservationDrivenProposer` (one explicit rule per family) | fixed order |

Every strategy generates and executes real candidate experiments for
every family (granted in section 6: B and D grew grant rules only
after the failure analysis demonstrated the gap for all four
configurations). Origins are advisory-only strings
(`differential:recon:`, `independent:recon:`, `baseline:rule:`); no
evaluator reads them. Red-first tests pin that each configuration
proposes, executes and confirms on defective instances, and that a
zero-request ablation cannot occur (an ablation that proposes nothing
fails the test that asserts confirmation).

## 5. Per-confirmed-finding provenance (commit `3e4fb43`)

`webpent.egaie.benchmark.provenance` builds a machine-readable record
per CONFIRMED hypothesis from a finished state: initial-observation
inventory (count + SHA-256 digests), experiments with outcomes, the
confirmation evidence, selection decisions, proposal-log entries, and
the sealed-bundle replay summary. `classification` is None at build
time and `attach_classification` verifies the record's digest before
attaching, so ground truth touches results only after investigation
and any tampering before classification is detected. An isolation
test builds a record in a fresh interpreter with no lab code loaded.

## 6. Failure-driven improvement (commit `f240487`)

`scripts/l7_failure_analysis.py` ran all four configurations on the
DEV block and classified every false negative. Pre-fix findings:

- `grant` (all four strategies): cause `hypothesis_generation`. No
  engine generator covered the token-authorization invariant, and the
  probe language could not carry a minted token into later steps.
- `identity_mutation` on lab-104 (A, B, C): cause
  `hypothesis_generation`. The surface is open-read, so no denial
  differential exists to correlate credentials to owners.
- `workflow_*` (D): hypotheses existed but the rules' single probe
  returned clean on defective deployments (see below).

Changes implemented, each justified by the demonstrated failure mode:

- **ProbeStep response capture** (`value_from`/`value_key`): the
  placeholder `"{captured}"` in a step's params resolves at execution
  from an earlier step's response field; unresolvable capture fails
  closed to an `unresolved_parameters` observation, never to a guessed
  value.
- **GRANT_REPLAY family**: engine generator (baseline grant, three
  consumes against the declared use count, a never-minted-token
  control) and its oracle (declared use count read from the grant
  response; control must be denied or the verdict is inconclusive,
  not confirmed). The evaluator now scores the family; its former
  absence is pinned in the failure analysis, never forgiven in
  scoring.
- **Independent and baseline grant rules** (B and D): the ablation
  isolates selection, not generation coverage; a family only A could
  generate would confound the comparison (section 4 fairness).
- **Open-read identity fallback** (engine, B and D): when no read is
  ever denied, the distinct owner strings the surface itself exposed
  (two minimum) become the candidate identities; surfaces with
  denied reads keep the strict correlation path.
- **`h-` record-id alignment**: strategy-proposed hypothesis records
  now carry the engine's id prefix so experiment bindings and the
  failure analysis attribute outcomes to the right hypothesis.

Post-fix DEV results: A, B and C close every defect on lab-101..104
(FN=0). D retains four `interpretation` FNs (its fixed
one-probe-per-family rules are less discriminating than the engine's
context-routed generators); this is a documented baseline capability
limit, not an invalid comparison: D generates and executes real
candidates for every family. The held-out set was not touched during
any of this work.

## 7. Full ablation matrix (commit `f81b8e3`)

`scripts/l7_ablation_matrix.py` ran the four configurations on every
instance at budgets 16/48/96 (144 runs) into
`docs/l7_ablation_matrix.json`: per instance x family TP/FP/FN with
precision/recall, requests and seconds per run and per confirmed
finding, hypothesis/outcome tallies, budget binding and terminal
reason, seal/replay validity over confirmed findings (457 bundles, all
valid where applicable), and pairwise cross-strategy traces.

Measured results at budget 96 (confirmed / defects):

| block | instance | A adaptive | B independent | C no-selector | D baseline |
|---|---|---|---|---|---|
| dev | lab-101 | 3/3 | 3/3 | 3/3 | 2/3 |
| dev | lab-102 | 6/6 | 6/6 | 6/6 | 5/6 |
| dev | lab-103 | 4/4 | 4/4 | 4/4 | 3/4 |
| dev | lab-104 | 4/4 | 4/4 | 4/4 | 3/4 |
| held-out | lab-201 | 5/5 | 5/5 | 5/5 | 3/5 |
| held-out | lab-202 | 5/5 | 5/5 | 5/5 | 3/5 |
| held-out | lab-203 | 3/3 | 3/3 | 3/3 | 1/3 |
| held-out | lab-211 | 4/4 | 4/4 | 4/4 | 3/4 |
| held-out | lab-212 | 4/4 | 4/4 | 4/4 | 3/4 |
| held-out | lab-213 | 4/5 | 3/5 | 4/5 | 3/5 |
| negative | lab-301/302 | 0 | 0 | 0 | 0 |

Totals at budget 96, dev+held-out: A 42 confirmed, 1 FN, 0 FP;
B 41, 2 FN, 0 FP; C 42, 1 FN, 0 FP; D 29, 14 FN, 0 FP. At budget 16:
A 42, C 37, B 41, D 29 — the adaptive selector's measurable advantage
appears only at the tightest budget.

Held-out lab-213 is reported as measured: A and C each missed
`workflow_identity`, B additionally missed `price`. The held-out set
was never touched during tuning, so no fix was applied for it here;
it is the honest generalization number of this release.

## 8. What the measurements do and do not support

- **Supported by measurement:** on this synthetic loopback corpus, at
  equal budget, all four configurations reach precision 1.0 (zero
  false positives, including on secured lookalikes and both negative
  instances); adaptive selection beats no selection only at budget
  16 and ties it at 48 and 96; the independent proposer tracks the
  engine within one confirmed finding; the rule-based baseline
  sacrifices recall on workflow and price families.
- **Not supported, and not claimed:** real-world bug-hunting
  capability; adaptive superiority in general (the equal-budget tie
  at 48/96 is measured, and stated); any result on surfaces outside
  the lab's shapes.
- **A finding of no measurable adaptive advantage at higher budgets
  is an acceptable scientific result.** The metrics and baselines are
  valid (every strategy generates and executes candidates; ground
  truth applied only after investigation; provenance sealed and
  replay-verified).

## 9. Gates

Fresh gate run at the deliverables commit
(`docs/l7_gate_logs/gate_run_20261025T030834Z.log`):

```json
{
  "pytest": "4477 passed, 0 failed (coverage run)",
  "coverage": "62.07% >= 35% floor",
  "lint": "make lint: all checks passed (includes both L7 scripts)",
  "test_count": "4477 collected >= floor 1940",
  "bandit_lll": "exit 0"
}
```

## 10. Commit inventory (L7)

```
42e72ef docs: L7 plan and L6 reproduction run evidence
e800a6d egaie: L7 strategy instrumentation — proposal_log, run_trace/compare_traces, red-first tests
3b7bce0 L7 step 3: independent lab corpus (labsuite) with isolation gates
2c92e32 egaie: L7 step 4 — four fair ablation configurations with red-first tests
3e4fb43 egaie: L7 step 5 — per-confirmed-finding machine-readable provenance
f240487 egaie: L7 step 6 — failure-driven engine improvements from the DEV-corpus ablation
f81b8e3 egaie: L7 step 7 — full ablation matrix across budgets 16/48/96
<this commit> docs: L7 deliverables and release manifest
```

## 11. Release

`docs/L7_RELEASE_MANIFEST.md` carries the release name, key-file
digests, gate results and the evaluation summary. The ZIP is cut from
the manifest commit with `git archive` (committed content only, which
structurally excludes the never-committed
`download/econ/portfolio_transitions.jsonl`), and its SHA-256 is
published beside it, since an archive cannot contain its own digest.

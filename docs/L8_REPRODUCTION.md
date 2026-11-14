# L8 §1 — Reproduction of the L7 release

Mission L8 §1 requires starting from the exact L7 release commit,
verifying the reported archive SHA-256, and reproducing every reported
result BEFORE any engine change. This document records that work. No
engine behaviour was changed during it; the two corrections made were
documentation digests and a measurement-instrument defect in the
matrix script's trace capture (details below), neither of which
touches discovery, scoring, authorization or proof logic.

## 1. Starting point and archive verification

The L7 release ZIP was cut from commit `73b8484` ("docs: L7
deliverables and release manifest"). Verification performed at the
start of L8:

| artifact | check | result |
|---|---|---|
| working-tree `webpent_l7.zip` | SHA-256 | `077feb0821f95c80bd0ceb3a49866067063c1e95460b385108166648e48c547c` |
| delivered `/mnt/user-data/outputs/webpent_l7.zip` | SHA-256 | identical |
| recorded value in `webpent_l7.zip.sha256` and `docs/L7_RELEASE_MANIFEST.md` | comparison | identical |

All three references agree. The delivered archive is the recorded one.

### Manifest digest audit (one correction found)

L8 §1 also audited the thirteen key-file digests inside
`docs/L7_RELEASE_MANIFEST.md` against the committed files. Eleven
matched exactly. Two did not:

- `docs/L7_DELIVERABLES.md`: the manifest recorded the digest taken
  before the document's final edit.
- `docs/l7_gate_logs/gate_run_20261025T030834Z.log`: the committed
  snapshot of the log was truncated mid-run (the gate process was
  still streaming when the deliverables commit captured it); the
  manifest digest had been taken from an even earlier partial state.
  The working tree holds the complete, genuine output of that run
  (4477 passed, coverage 62.07%), now committed.

Both corrected values are committed, with a corrections section in the
manifest stating what happened. The ZIP itself is unchanged and was
not regenerated: its top-level digest is the verified one, and this
bookkeeping error does not alter any evaluation result. This is
exactly the class of packaging defect §1's verify-first requirement
exists to catch.

## 2. Gates reproduced

Fresh full gate run at commit `ebdeb92` (the digest-correction commit,
two commits after the release):

```
docs/l8_gate_logs/gate_run_20261025T142459Z.log

make ci:
  test-count   4477 collected >= floor 1940
  coverage     4477 passed, 0 failed; 62.07% >= 35% floor
  lint         make lint: all checks passed
  security     bandit -lll: clean
authority gates:
  scripts/check_orchestrator_construction_authority.py  OK
  scripts/check_vault_import_authority.py               OK
ALL GATES GREEN
```

The 4477-passed count and 62.07% coverage match the L7 release gate
run exactly.

## 3. The 144-run A/B/C/D evaluation reproduced

`scripts/l7_ablation_matrix.py` was re-run end to end (4 strategies ×
12 instances × budgets 16/48/96). Comparing the fresh artifact against
the committed one with wall-clock seconds excluded (the only
nondeterministic field), **the two documents are byte-equal in every
other field**: all per-run confirmed counts, TP/FP/FN, requests,
families, seal summaries, terminal reasons and 108 cross-strategy
comparison records.

Reported headline numbers all reproduce:

- budget 16, dev+held-out unique defects confirmed: A 42, B 41,
  C 37, D 29;
- budget 48: A 42, B 41, C 42, D 29 (the A/C tie);
- budget 96: A 42, B 41, C 42, D 29 (tie again);
- false positives: zero in all 144 runs, including the secured
  lookalikes and both negative instances;
- 457 sealed proof bundles across the matrix, all replay-valid;
- held-out lab-213 as measured: A 4/5 and C 4/5 (both miss
  `workflow_identity`), B 3/5 (also misses `price`), D 3/5;
- per-instance budget-96 results match the table in
  `docs/L7_DELIVERABLES.md` section 7 line for line.

## 4. Instrument defect found by reproduction, and fixed

The reproduction exposed a defect in the matrix script itself, not in
the engine or the headline numbers. `InvestigationOrchestrator.run`
works on a deterministic copy of the state and returns the finalized
copy; `run_one` built its execution trace from the pre-run seed
object. Every per-run `executed_count` / `outcome_tally` /
`rounds_used` / `budget_binding` / `terminal_reason` in the committed
artifact therefore came from an empty state, and all 108
cross-strategy `compare_traces` records were vacuous (empty executed
sets, Jaccard 1.0 by convention).

Fixes, both committed with L8 §1:

- `scripts/l7_ablation_matrix.py` now builds the trace from the
  RETURNED state (the same object `confirmed_entries`, `seal_summary`
  and the status tally already used).
- Red-first regression test
  `test_run_trace_reflects_the_returned_state_not_the_seed` in
  `tests/egaie/test_ablation_strategies.py` pins the pitfall itself:
  for every strategy, the seed state must be execution-free while the
  returned state must carry the executed experiments, a nonempty
  outcome tally, nonzero rounds, and a confirmed set matching the
  experiment outcomes.

The corrected matrix (same headline numbers, now with real traces)
replaces the committed artifact. What the real traces add:

- 2088 experiment outcomes across the matrix: 1631 `clean`, 457
  `confirmed`, zero `inconclusive`, zero `blocked`;
- zero duplicate experiment signatures within any run (144/144);
- budget binding is now measured: 16 runs exhausted the round budget
  (all at budget 16), 16 more ended `objectives_complete` exactly at
  their final round, 112 finished early;
- A vs C share on average 93% of their executed experiments (same
  proposer pool; the selector's only measured effect is order and
  early-round prioritization), and order on the shared ids agrees in
  all 36 pairs;
- A vs B and A vs D have Jaccard 0.0 by construction: B and D mint
  experiment ids in their own namespaces, so id-level confirmed
  overlap across those pairs is structurally zero and cross-strategy
  comparison for those pairs must be made at the family level (which
  the TP/FP/FN families records do).

## 5. The exact metric behind each count

The mission requires identifying the unit of every reported number.
These are the definitions the artifacts implement, and the checks that
were run to confirm them.

**Unique vulnerable case (defect).** One `(instance, lab-family)`
entry in the evaluator's ground-truth roster, derived by the evaluator
independently from the deployment's implementation profile and applied
only AFTER an investigation finished. The dev+held-out corpus carries
43 unique vulnerable cases (17 in dev 101-104, 26 in held-out
201-203/211-213); the negative block carries zero. This is the only
denominator for recall.

**Confirmed finding (per run).** A hypothesis the engine marked
CONFIRMED after executed, sealed, replay-verified differentials. A
scoring check over all 144 runs verified that per-run
`confirmed_count` equals the sum of family-level TPs in every single
run: within a run, the engine never confirmed two distinct hypotheses
on the same defect family, so the per-run confirmed count is already
defect-level. Summed over the 12 non-negative instances at one
budget, it is "unique vulnerable cases confirmed by this strategy at
this budget."

**Experiment outcome.** One executed experiment's verdict
(`confirmed` / `clean` / `inconclusive` / `blocked`). The corrected
matrix records 2088 of them (1631 clean + 457 confirmed, 0
inconclusive, 0 blocked). These are experiment-level events, never
defect counts.

**Repeated discovery.** The same defect re-confirmed across runs. The
457 figure is the sum of confirmed findings over all 144 runs (up to
12 confirmations for one fully-reproduced defect: 4 strategies × 3
budgets) and equals the 457 sealed bundles, one seal per confirmed
finding per run. It is a repeated-detection count, not a defect
count; unique defects confirmed never exceed 43 anywhere in the
artifacts.

**The 42-vs-37 metric.** Unique vulnerable cases confirmed (sum of
family-level TPs over dev+held-out) out of 43, by A versus C, at
budget 16. It is a unique-defect recall comparison at equal round
budget, not a count of experiment outcomes or of repeated
detections.

**The ties at 48/96.** A and C each confirm the same 42 of 43 unique
defects at both budgets. "Ties" refers to unique-defect recall, and
the corrected traces add that A and C execute 93% overlapping
experiment sets in the same relative order: with the pool exhausted,
the selector has nothing left to prioritize.

**Held-out lab-213.** Reported as measured: A and C confirm 4 of 5
defects (missing `workflow_identity`), B confirms 3 (also missing
`price`), D confirms 3. The held-out set was never touched during any
tuning.

**Discovery curves.** Unique-defect recall at the three measured
budgets: A 42/42/42, B 41/41/41, C 37/42/42, D 29/29/29 (budgets
16/48/96). These are the measured curves; per-defect
first-confirmation budgets are bracketed by them (≤16, 17-48, 49-96,
or not within 96 rounds) rather than timed within a run. At budget 16
requests actually issued were A 818, C 800, B 776, D 520, i.e.
requests per unique confirmed defect A 19.5, C 21.6, B 18.5, D 17.9:
D is the cheapest per confirmation and also confirms the fewest; the
adaptive selector's measured advantage over no-selector is recall at
budget 16, not request efficiency.

## 6. Status

§1 is complete: the archive verifies, gates are green, the full
evaluation reproduces exactly, every count's metric unit is defined
and checked, and the one instrument defect the reproduction surfaced
is fixed with a red-first test. Engine behaviour is untouched. L8
§2 (independent application families) starts from here.

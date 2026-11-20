# L9 Failure Analysis — blind held-out per-miss root causes

Mission: **L9 — Stateful Investigation Planning & Prerequisite
Reasoning**, §7. This document records every miss on the fresh
blind held-out block (`heldout_l9`: ledgerflow, berth, five
variants each), measured ONCE by `scripts/l9_planner_matrix.py
heldout_l9` after the DEV block and its analysis were frozen
(`docs/l9_planner_dev.json` is the pre-registered dev record; the
held-out run happened after it was written and its outcomes
influenced nothing).

Raw data: `docs/l9_planner_heldout_l9.json`. All figures are
engine observation counts on synthetic loopback fixtures of
independently implemented applications; nothing here supports a
real-world generalization claim.

## The held-out block at a glance (budget 32)

| strategy | tp | fp | fn | recall | requests |
|---|---|---|---|---|---|
| A `l8-engine` | 0 | 0 | 2 | 0.0 | 317 |
| B `planner` | 2 | 0 | 0 | 1.0 | 495 |
| C `planner-no-prereq` | 0 | 0 | 2 | 0.0 | 317 |
| D `fixed-prereq` | 2 | 0 | 0 | 1.0 | 541 |

No strategy produced any false positive on any clean variant
(ledgerflow secured; berth secured, unavailable_prereq,
transition_no_vuln, negative_control) at any budget. Every miss on
the block is a false NEGATIVE on one of the two defective
instances (lf-151 ledgerflow defective, bh-161 berth defective).

## Discovery curves on the defective instances

| budget | A | B | C | D |
|---|---|---|---|---|
| 2 | miss ×2 | miss ×2 | miss ×2 | miss ×2 |
| 4 | miss ×2 | miss ×2 | miss ×2 | miss ×2 |
| 8 | miss ×2 | lf-151 ✓ | miss ×2 | lf-151 ✓ |
| 16 | miss ×2 | lf-151 ✓ bh-161 ✓ | miss ×2 | lf-151 ✓ bh-161 ✓ |
| 32 | miss ×2 | both ✓ | miss ×2 | both ✓ |

## Per-miss root causes

Root-cause taxonomy (mission §7): prerequisite inference |
planning | execution | state interpretation | evidence |
classification. A miss may carry more than one cause; the PRIMARY
cause is listed first.

### M1–M2 — A (`l8-engine`) on lf-151 and bh-161, budgets 2–32

- **Primary: prerequisite inference (engine lacks the
  mechanism).** The candidate leg of the workflow-identity
  differential POSTs the countersign/confirm action on the
  identity target. On both held-out apps the defect is skipped
  for a transition whose SOURCE state is the chain's second
  stage, so the surface refuses the leg with a state-naming 409
  until the machine has been moved forward by the holder's
  earlier transition. The pre-L9 engine declares no transition
  preconditions, derives no setup, and re-runs nothing: the
  differential is judged ACTION_BLOCKED → inconclusive, the
  hypothesis stays parked, and the defect is never confirmed at
  any budget. This is the L8 workflow-identity FN shape
  (documented in `docs/L8_*.md`) manifesting on two
  independently implemented state machines, including one whose
  state is timestamped windows rather than a pointer — the
  engine's miss is invariant to the state representation because
  it never attempts the prerequisite at all.
- **Secondary: none.** No state misinterpretation (the 409 was
  read correctly as a blocked precondition, not as enforcement —
  the fail-closed oracle did its job: the miss is a non-verdict,
  not a wrong clean verdict).

### M3–M4 — C (`planner-no-prereq`) on lf-151 and bh-161, budgets 2–32

- **Primary: prerequisite inference (deliberately ablated).**
  Identical mechanism to M1/M2 with the planner's reasoning
  switched off by the `prerequisite_reasoning` flag: candidate
  generation, oracle, and budgets are byte-identical to B, the
  ledger records zero transition preconditions and zero
  establishments, and every blocked outcome stays inconclusive.
  That C reproduces A's miss exactly while B does not is the
  ablation isolating prerequisite reasoning as the component that
  closes the gap — the mission's §6 comparison result.

### M5 — B (`planner`) on lf-151, budgets 2 and 4

### M6 — B (`planner`) on bh-161, budgets 2, 4, and 8

- **Primary: planning under budget (remediation needs rounds).**
  The mechanism works at these budgets: the run reaches the
  candidate leg, the judge classifies ACTION_BLOCKED, the planner
  declares the workflow-transition precondition, and (on the
  first successful remediation) the setup applies. What does not
  fit is the ROUND BUDGET: at budget 2 the investigation cannot
  complete reconnaissance plus the blocked first pass plus
  setup plus the re-run and the confirming re-judgment before
  `round_budget_exhausted` terminates it; at budget 4 (and 8 for
  bh-161, whose timestamped-window machine costs extra
  reconnaissance rounds) the same shortfall persists. The
  terminal reason on these runs is round_budget_exhausted, with
  the defect experiment present but unresolved — the miss is a
  scheduling/budget artifact, not an inference or execution
  failure.
- **Secondary: planning (selection order).** Information-gain
  selection schedules other families' experiments before the
  workflow-identity defect hypothesis at low budgets; a
  defect-first ordering would confirm earlier. No tuning was
  done to change this: the ordering is the L8 engine's, held
  fixed across all four strategies by the fairness requirement.

### M7–M12 — D (`fixed-prereq`) on lf-151 (budgets 2, 4) and
bh-161 (budgets 2, 4, 8)

- **Primary: planning under budget, aggravated by the fixed
  recipe's inefficiency.** Same budget mechanism as M5/M6, but D
  pays MORE per remediation: the static recipe cannot tell which
  POST path of the blocked plan is the one the candidate leg
  needs, so it fires on EVERY probed workflow path (advancing the
  control resource too), then re-runs. The extra setup pairs
  consume observations that at low budgets the investigation
  needed for reconnaissance and the re-run. D confirms both
  defects at the same budgets as B on these two-stage machines
  (8 and 16) but spends 46 more requests at budget 32 (541 vs
  495); on deeper chains the recipe would fail where the
  planner's minimal-sequence derivation succeeds, by
  construction — the recipe advances one step per fire and never
  reasons about which state is required.
- **Secondary: one failed setup recorded** (bh-161, verified-8 /
  failed-1): the recipe fired on a path whose owner was the
  harbormaster-gated berth in the unavailable_prereq rotation's
  neighborhood — the re-read showed no movement, the cycle
  failed closed, and no verdict resulted (§3 discipline held).

## What did NOT go wrong

- **State interpretation:** no strategy ever misread a state
  refusal as enforcement (that would have been a clean-verdict
  FN of a different kind); the re-read-after-write and
  HTTP-200-proves-nothing invariants held throughout.
- **Evidence:** every confirmed finding sealed a bundle that
  replayed valid; no finding rested on the setup's own HTTP
  status.
- **Classification:** no false positive occurred anywhere on
  the block; the unavailable_prereq case produced an UNATTAINABLE
  ledger entry with NEVER_A_VERDICT, not a negative verdict.
- **Execution:** the remediated re-runs executed with their own
  idempotency tokens (G-02 replay guard intact for plain
  repetitions); no duplicate-mutation anomalies were recorded on
  the block.

## Conclusion

Every miss on the blind held-out block is the same story in two
acts: without prerequisite reasoning (A, C) the defect behind the
prerequisite is unreachable at ANY budget — a mechanism gap; with
it (B, D) the miss is only a budget artifact at budgets 2–4 (and
8 for berth), resolved by round 8–16. Prerequisite reasoning
improved untouched held-out discovery from recall 0.0 to 1.0 at
zero false positives; the independently generated fixed recipe
achieves the same recall on these two-stage machines at higher
request cost and would degrade on deeper chains, which is the
planner's reasoning advantage the mission asked us to measure.

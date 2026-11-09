# L7 Release Manifest

Release: **webpent-l7-independent-discovery** (2026-10-25)
HEAD commit: recorded in the inventory below as the deliverables commit

ZIP: `webpent_l7.zip`, cut with `git archive` from the deliverables
commit (committed content only; the never-committed
`download/econ/portfolio_transitions.jsonl` is structurally excluded
because it is not in the repository). The archive cannot contain its
own digest; the SHA-256 of the final zip is published alongside the
release and in the handover note.

## Commit inventory (L7, oldest first)

```
42e72ef docs: L7 plan and L6 reproduction run evidence
e800a6d egaie: L7 strategy instrumentation — proposal_log, run_trace/compare_traces, red-first tests
3b7bce0 L7 step 3: independent lab corpus (labsuite) with isolation gates
2c92e32 egaie: L7 step 4 — four fair ablation configurations with red-first tests
3e4fb43 egaie: L7 step 5 — per-confirmed-finding machine-readable provenance
f240487 egaie: L7 step 6 — failure-driven engine improvements from the DEV-corpus ablation
f81b8e3 egaie: L7 step 7 — full ablation matrix across budgets 16/48/96
+ deliverables commit (docs: L7 deliverables and release manifest;
  untracks the pre-rule committed download/econ/
  portfolio_transitions.jsonl and ignores it going forward)
```

## Key file digests (SHA-256)

| file | sha256 |
|---|---|
| `src/webpent/egaie/differential.py` | `2751c0d3d0080f67b8176a4542b628bf5f80b35d4b398e49b2d833ff348c8592` |
| `src/webpent/egaie/benchmark/strategies.py` | `404c2591a8b558d84a82e88445eeec862bea382f031311a8a2609b5c7934471e` |
| `src/webpent/egaie/benchmark/instrumentation.py` | `6a572159bfd453576aa8767c749cc498cb2d0cb303eda93b38017affe93fcf61` |
| `src/webpent/egaie/benchmark/provenance.py` | `e87e6979911ad5348d74357673d72993dab1981d6511a809afa4f83d8218fbed` |
| `src/webpent/labsuite/evaluator.py` | `582cdb2ce941e19ee5f236b0c6a932abbc8e67f11837337bafad20da875aadfb` |
| `src/webpent/labsuite/lab_target.py` | `8822f27259bf2d0872c6f7d33c20241e76fe3123e488f4db099b27ee87820f0d` |
| `src/webpent/labsuite/corpus.py` | `fc2071aa480d091354bb97d87dd27943ea67d0d32c8bfe72574fe8d5d2b52083` |
| `scripts/l7_failure_analysis.py` | `e9045d5e1b07ac4f2a31ad96fe7ef5933c5fceb06a81fda2ce3f84c894ed6a05` |
| `scripts/l7_ablation_matrix.py` | `d92b52d13a7c7287acadfd2fa6c4d02001fdd3ff31fd56d32c5aa1608a19dcc4` |
| `docs/l7_failure_analysis.json` | `9340723b6e24017ac974cc02aa924f3419795ced4ff1b506e4ddaa9863a57e42` |
| `docs/l7_ablation_matrix.json` | `c56a326e59d8056e7178a52ec0210208eda4b40907e6e786918c06221cbe91b5` |
| `docs/L7_DELIVERABLES.md` | `772696ca08206a158597cf9b1b43a8401c36ee0fe556b7a10aacf5b875dae567` |
| `docs/l7_gate_logs/gate_run_20261025T030834Z.log` | `9e9f48166c8e6c768c1bb8bb6f15d250b446159970865ab9b5db123359beb494` |

## Digest corrections (L8 §1 reproduction)

The delivered L7 ZIP's manifest recorded two digests that did not match
the committed files, found when L8 §1 verified this table: the
deliverables document (recorded before its final edit) and the gate log
(recorded from a partial snapshot while the gate run was still
streaming; the committed snapshot truncated mid-run, the working-tree
file holds the complete genuine output of run 20261025T030834Z —
4477 passed, coverage 62.07%). The corrected values above are the
SHA-256 of the files as committed. The ZIP itself is unchanged: its
top-level SHA-256 (`077feb08…547c`) was verified against the delivered
file, and this correction does not alter any evaluation result.

## Gates

```json
{
  "pytest": "4477 passed, 0 failed (coverage run)",
  "coverage": "62.07% >= 35% floor",
  "lint": "make lint: all checks passed (both L7 scripts included)",
  "test_count": "4477 collected >= floor 1940",
  "bandit_lll": "exit 0",
  "log": "docs/l7_gate_logs/gate_run_20261025T030834Z.log"
}
```

## Evaluation summary

- All four configurations: precision 1.0 (zero false positives,
  secured lookalikes and negatives included), every confirmed finding
  sealed and replay-verified (457 bundles).
- Budget 96, dev+held-out confirmed: A 42, B 41, C 42, D 29.
  Adaptive selection measurably beats no selection only at budget 16
  (42 vs 37) and ties at 48/96 — stated as measured, not claimed
  beyond it.
- Held-out lab-213 reported as measured (A/C miss workflow_identity,
  B also misses price); the held-out set was untouched during tuning.
- Synthetic loopback results support no real-world generalization
  claim. See `docs/L7_DELIVERABLES.md` section 8.

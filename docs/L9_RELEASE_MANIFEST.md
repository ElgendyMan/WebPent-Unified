# L9 Release Manifest

Release: **webpent-l9-stateful-investigation-planning** (2026-10-30)
ZIP: `webpent_l9.zip`, cut with `git archive` from the release
commit (committed content only; the never-committed
`download/econ/portfolio_transitions.jsonl` is structurally excluded
because it is not in the repository). The archive cannot contain its
own digest; the SHA-256 of the final zip is published alongside the
release.

## Commit inventory (L9, oldest first; L8 release HEAD was 48eb45b)

```
702dfde egaie: L9 §2 — structured preconditions with status tracking
93bdc79 egaie: L9 §2 Phase 1 — hypotheses carry structured preconditions
514a862 docs: L9 §1 baseline — L8 reproduction verified (gate, 160-run
        dev+heldout field-identical)
29ff5ed egaie: L9 §3 Phase 2 — bounded stateful planner
de5ace1 egaie+appsuite: L9 §4 Phase 3 — workflow-identity state-machine
        discrimination on the requisitions dev case
85ebd98 L9 phase 3: workflow-identity FN closed on new dev app; planner wired
7707b8a L9 phase 4: §5 invariant regression sweep
c200913 L9 phase 5: remediated re-runs as distinct investigation steps
ed2d3ea L9 phase 6: budget-matched planner strategy matrix (§6)
4927426 L9 phase 7: blind held-out measured once, every miss classified (§7)
+ deliverables commit (docs: L9 deliverables — architecture/data-flow,
  red-first results, budget-matched tables, honest prerequisite-
  reasoning statement)
+ release commit (docs: L9 release manifest and final gate log)
```

## Release gate

Full `make ci` at the release state: **4536 passed, coverage 62.28%
(floor 35%), lint all checks passed, Bandit high-severity clean,
GATE_OK**. Log: `docs/l9_gate_logs/gate_run_20261029T183832Z.log`
(the bandit step's explicit exit-status confirmation appended at the
end).

## Key file digests (SHA-256)

| file | sha256 |
|---|---|
| `src/webpent/egaie/prerequisites.py` | `57dbabf04969995473f262ec3a1528d6b7cb8cfeb8e55a246f79b1ec66363573` |
| `src/webpent/egaie/planner.py` | `29617e6494bef736d627ef1c3a2a1672385ead09af6837385bae482361f42e3b` |
| `src/webpent/egaie/orchestrator.py` | `870b8fde889b016e1c13962c5207c0ac80835bd548483df4e2aebe7499359087` |
| `src/webpent/egaie/differential.py` | `4f814dc7de2d11d996bd71887f59fa4142e5b63d176388ce8baad7d217240e73` |
| `src/webpent/egaie/benchmark/fixed_prerequisites.py` | `8056bcfc7236cc45226cf0dc790c1a17eea3d65ce34466ebceaec4530821813a` |
| `src/webpent/appsuite/requisitions.py` | `dbd556424837383328ace435a84fb273abddb7735a36767992e2b1f9a14ed90c` |
| `src/webpent/appsuite/ledgerflow.py` | `a4c2f67b6c6c59c7a5a15f05428b7ab753b63c7dd472689df974601aee108dcc` |
| `src/webpent/appsuite/berth.py` | `c61e5420612e418a616fb5a4571d0704aefa769996e2ff81a11bfabb9314866b` |
| `src/webpent/appsuite/corpus.py` | `dc9802c5f57c74759411af7a704d0470e42b8bf17c9995beb31b357363aca9dd` |
| `src/webpent/appsuite/groundtruth.py` | `0c98becf56c841eea3b4bbefb0775082c8d18c694e959a0a32d58a02f38c83ff` |
| `scripts/l9_planner_matrix.py` | `52fca95cef77f4ceae5b1b7eb118e15c999aa5ba29fe0eb4407e02900bdeeb6e` |
| `docs/L9_PLAN.md` | `3480dab062ea021a8dd80d7eb9d53b0fd76483ac82bf2e56a3b3234a36ec550f` |
| `docs/L9_BASELINE.md` | `25790f197fc634a9c062e73ee5c7b00b9bad3438e19c9323a9b75c9bf52ab446` |
| `docs/L9_FAILURE_ANALYSIS.md` | `d295608f309969799a05d415e16647dbf3fe75c2bdf3e73a32095f99f8cb466f` |
| `docs/L9_DELIVERABLES.md` | `8abd0b34ed9437255be579ae91292e5bbbe7fe3e90ca6c9abd9bd79f891dd137` |
| `docs/l9_planner_dev.json` | `2e9682f7b865ca12d6eab50b6af27f1e28976ec78ce9e7b7b200839bf6185a9f` |
| `docs/l9_planner_heldout_l9.json` | `8b3ffe3f9e4968d15f10b85ccc712086e4021cc93b0609ed9199c4756322d435` |

## Result in one line

On the untouched blind held-out block, the L9 planner took discovery
from recall 0.0 (baselines A and C) to 1.0 at zero false positives;
the independent fixed recipe (D) matched the recall at 46 more
requests. Synthetic loopback fixtures; no real-world generalization
claim.

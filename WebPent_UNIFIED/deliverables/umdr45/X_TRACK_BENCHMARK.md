# UM-DR-45 X-track benchmark — the measured ultimate (local authorised lab)

3 campaigns per target per battery. LLM disabled; CausalGuard/ProofBundle sole confirmation authority; every number below comes from the saved run file `X_TRACK_BENCHMARK.json`.

| Battery | Entrypoint | Seed | Block | GT | TP | FP | FN | Precision | Recall | F1 | Reqs | Reqs/confirmed | Mean elapsed s |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | `webpent.cli.unified_hunt.run_unified_hunt (`webpent hunt` core)` | 101 | dev | 3 | 0 | 0 | 9 | None | 0.0 | 0.0 | 324 | None | 1.84 |
| A | `webpent.cli.unified_hunt.run_unified_hunt (`webpent hunt` core)` | 102 | dev | 6 | 0 | 0 | 18 | None | 0.0 | 0.0 | 324 | None | 1.51 |
| A | `webpent.cli.unified_hunt.run_unified_hunt (`webpent hunt` core)` | 201 | heldout | 5 | 0 | 0 | 15 | None | 0.0 | 0.0 | 324 | None | 1.557 |
| A | `webpent.cli.unified_hunt.run_unified_hunt (`webpent hunt` core)` | 301 | negative | 0 | 0 | 0 | 0 | None | None | None | 285 | None | 1.263 |
| B | `webpent.egaie.discovery_runner adaptive orchestrator (labsuite engine)` | 101 | dev | 3 | 9 | 0 | 0 | 1.0 | 1.0 | 1.0 | 417 | 27.8 | 0.963 |
| B | `webpent.egaie.discovery_runner adaptive orchestrator (labsuite engine)` | 102 | dev | 6 | 18 | 0 | 0 | 1.0 | 1.0 | 1.0 | 354 | 13.11 | 0.817 |
| B | `webpent.egaie.discovery_runner adaptive orchestrator (labsuite engine)` | 201 | heldout | 5 | 15 | 0 | 0 | 1.0 | 1.0 | 1.0 | 417 | 19.86 | 0.993 |
| B | `webpent.egaie.discovery_runner adaptive orchestrator (labsuite engine)` | 301 | negative | 0 | 0 | 0 | 0 | None | None | None | 417 | None | 0.98 |

## Per-campaign detail

| Battery | Seed | Run | Status | Confirmed | Requests | Elapsed s | Hypotheses |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: |
| A | 101 | 1 | COMPLETED | 0 | 108 | 2.5 | 20 |
| A | 101 | 2 | COMPLETED | 0 | 108 | 1.52 | 20 |
| A | 101 | 3 | COMPLETED | 0 | 108 | 1.5 | 20 |
| A | 102 | 1 | COMPLETED | 0 | 108 | 1.46 | 20 |
| A | 102 | 2 | COMPLETED | 0 | 108 | 1.59 | 20 |
| A | 102 | 3 | COMPLETED | 0 | 108 | 1.48 | 20 |
| A | 201 | 1 | COMPLETED | 0 | 108 | 1.57 | 20 |
| A | 201 | 2 | COMPLETED | 0 | 108 | 1.61 | 20 |
| A | 201 | 3 | COMPLETED | 0 | 108 | 1.49 | 20 |
| A | 301 | 1 | COMPLETED | 0 | 95 | 1.27 | 1 |
| A | 301 | 2 | COMPLETED | 0 | 95 | 1.3 | 1 |
| A | 301 | 3 | COMPLETED | 0 | 95 | 1.22 | 1 |
| B | 101 | 1 | COMPLETED | 5 | 139 | 0.97 | 31 |
| B | 101 | 2 | COMPLETED | 5 | 139 | 0.98 | 31 |
| B | 101 | 3 | COMPLETED | 5 | 139 | 0.94 | 31 |
| B | 102 | 1 | COMPLETED | 9 | 118 | 0.8 | 24 |
| B | 102 | 2 | COMPLETED | 9 | 118 | 0.83 | 24 |
| B | 102 | 3 | COMPLETED | 9 | 118 | 0.82 | 24 |
| B | 201 | 1 | COMPLETED | 7 | 139 | 1.01 | 31 |
| B | 201 | 2 | COMPLETED | 7 | 139 | 1.0 | 31 |
| B | 201 | 3 | COMPLETED | 7 | 139 | 0.97 | 31 |
| B | 301 | 1 | COMPLETED | 0 | 139 | 0.96 | 31 |
| B | 301 | 2 | COMPLETED | 0 | 139 | 1.03 | 31 |
| B | 301 | 3 | COMPLETED | 0 | 139 | 0.95 | 31 |

## Honest notes

* Battery A measures the CLI hunt surface exactly as shipped. The lab target authenticates per request via the actor query parameter; the CLI surface carries credentials only via cookies/headers, so battery A documents that wiring gap by measurement instead of hiding it. This is a recorded finding, not a scoring carve-out.
* Battery B is the labsuite investigation engine (the in-tree A4 pattern extended to a battery), which speaks the probe-credential protocol natively.
* Requests are counted by the lab target itself (LabTarget.request_count delta).
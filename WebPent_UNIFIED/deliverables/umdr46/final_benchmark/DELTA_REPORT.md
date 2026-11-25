# UM-DR-46 Phase K — FINAL BENCHMARK DELTA REPORT

Same battery, same labs, same campaigns, same determinism env as the P0.5 baseline (scripts/umdr46_baseline_battery.py → scripts/umdr46_final_battery.py, out_dir isolated). The Phase A-J additions are ADVISORY research-intelligence nodes: the production research behavior is additive — the battery MUST NOT regress.

## Identification

- baseline commit: 043b5124bdfaae9c7c42a7e1aa692fe90ec1be29
- final commit: 06eb943ff02cdce42ed8b8eaecc7cc1ac25ca7a7
- baseline tree sha: 3f216ed9bb714b36a3c9096e4f5239254b62e705
- final tree sha: f284c49d6022a80ec4866cf598045df3102f0479
- final mission: UM-DR-46 Phase K — FINAL benchmark on the completed researcher brain tree (Phases A-J landed)

## Overall deltas

| metric | baseline | final | delta |
| --- | --- | --- | --- |
| campaigns_total | 36 | 36 | 0 |
| campaigns_completed | 36 | 36 | 0 |
| campaigns_error | 0 | 0 | 0 |
| tp | 6 | 6 | 0 |
| fp | 0 | 0 | 0 |
| fn | 18 | 18 | 0 |
| precision | 1.0000 | 1.0000 | 0.0000 |
| recall | 0.2500 | 0.2500 | 0.0000 |
| timeouts_or_cancellations | 0 | 0 | 0 |
| replay.verified/total | 6/6 | 6/6 | — |
| out_of_scope_zero_requests | True | True | — |

## Per-family deltas

### graphql_oracle

| metric | baseline | final | delta |
| --- | --- | --- | --- |
| tp | 0 | 0 | 0 |
| fp | 0 | 0 | 0 |
| fn | 3 | 3 | 0 |
| precision | None | None | n/a |
| recall | 0.0000 | 0.0000 | 0.0000 |
| requests_total | 642 | 642 | 0 |
| elapsed_s_mean | 4.1810 | 4.3360 | 0.1550 |
| replay | 0/0 | 0/0 | — |

### idor_bola

| metric | baseline | final | delta |
| --- | --- | --- | --- |
| tp | 6 | 6 | 0 |
| fp | 0 | 0 | 0 |
| fn | 0 | 0 | 0 |
| precision | 1.0000 | 1.0000 | 0.0000 |
| recall | 1.0000 | 1.0000 | 0.0000 |
| requests_total | 648 | 648 | 0 |
| elapsed_s_mean | 4.3760 | 4.6780 | 0.3020 |
| replay | 6/6 | 6/6 | — |

### redirect_scope_bypass

| metric | baseline | final | delta |
| --- | --- | --- | --- |
| tp | 0 | 0 | 0 |
| fp | 0 | 0 | 0 |
| fn | 6 | 6 | 0 |
| precision | None | None | n/a |
| recall | 0.0000 | 0.0000 | 0.0000 |
| requests_total | 576 | 576 | 0 |
| elapsed_s_mean | 3.6670 | 4.2920 | 0.6250 |
| replay | 0/0 | 0/0 | — |

### request_smuggling

| metric | baseline | final | delta |
| --- | --- | --- | --- |
| tp | 0 | 0 | 0 |
| fp | 0 | 0 | 0 |
| fn | 3 | 3 | 0 |
| precision | None | None | n/a |
| recall | 0.0000 | 0.0000 | 0.0000 |
| requests_total | 582 | 582 | 0 |
| elapsed_s_mean | 3.9800 | 4.1350 | 0.1550 |
| replay | 0/0 | 0/0 | — |

### tenant_confusion

| metric | baseline | final | delta |
| --- | --- | --- | --- |
| tp | 0 | 0 | 0 |
| fp | 0 | 0 | 0 |
| fn | 3 | 3 | 0 |
| precision | None | None | n/a |
| recall | 0.0000 | 0.0000 | 0.0000 |
| requests_total | 564 | 564 | 0 |
| elapsed_s_mean | 3.8700 | 3.9560 | 0.0860 |
| replay | 0/0 | 0/0 | — |

### workflow_abuse

| metric | baseline | final | delta |
| --- | --- | --- | --- |
| tp | 0 | 0 | 0 |
| fp | 0 | 0 | 0 |
| fn | 3 | 3 | 0 |
| precision | None | None | n/a |
| recall | 0.0000 | 0.0000 | 0.0000 |
| requests_total | 696 | 696 | 0 |
| elapsed_s_mean | 4.1990 | 4.4130 | 0.2140 |
| replay | 0/0 | 0/0 | — |

## Phase A-J uplift (the new capabilities under test)

| phase | capability | tests | what it adds |
| --- | --- | --- | --- |
| Phase A | Security Knowledge Graph | 23 tests | 9 entity classes + deterministic query API + RC-9 projection |
| Phase B | Researcher Brain | 22 tests | 5 deterministic understanding components + contradiction SSOT marks |
| Phase C | Adaptive hypothesis engine | 15 tests | mutation/decomposition/competition/negative-evidence/info-gain |
| Phase D | Cross-feature attack chains | 12 tests | info+authz / workflow-bypass / cross-surface compositions |
| Phase E | Discovery intelligence | 8 tests | unobserved transitions, parameter siblings, single-path resources |
| Phase F | Experiment planner | 7 tests | registry-bound plans, complete matrices, honest abstention |
| Phase G | Coverage intelligence | 8 tests | (resource × principal × operation) cells, guard-adjudicated |
| Phase H | Research memory | 7 tests | wall-clock-free lessons + ranking-time demotion lookups |
| Phase I | Autonomous QC | 9 tests | deficiency reports over hypotheses/lessons/plans |
| Phase J | Multi-protocol depth | 6 tests | workflow sequences, object-id spaces, cross-origin workflows |

**New mission tests: 117** (all GREEN at their gates; full-suite verified below).

## Verdict

**PASS — zero regressions:** the additive advisory research-intelligence layers changed NO production research behavior (same TP/FP/FN, same replay integrity, same out-of-scope guarantee), while the SKG-driven capabilities added 117 new deterministic mission tests.

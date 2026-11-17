# UM-DR-38 — Learning Causality Report

Generated: 2026-11-17T04:55:50.934837+00:00 — from `docs/UMDR37_FULL_LOOP_LEARNING.json` and `docs/UMDR37_LEARNING_ABLATION.json`.

## Classification (kept strictly separate)

| Evidence scope | Classification |
|---|---|
| Selector-level evidence influence (learning ablation) | MEASURED — the ablation artifact is present and covers selector-level evidence influence on experiment selection |
| Full-loop evidence → reordered execution → changed outcome | PROVEN ONLY WITHIN THE CONTROLLED FIXTURE — a full-loop proof through the production research/execution path on a team-authored lab, NOT generalized real-world learning |
| Learning that survives into subsequent campaign decisions | NOT CLAIMED beyond the full-loop artifact's own window |

The full-loop experiment exercises the intended production research and execution path (`scripts/umdr37_full_loop_learning.py` drives `run_unified_hunt` with pinned evidence channels per arm); it is NOT a shadow experiment or a test harness only. Its limitation is the fixture: team-authored ground truth, no independent holdout.

## The eight §8 evidence points (verified from the artifact)

| # | Requirement | Holds | Measured evidence |
|---|---|---|---|
| 1 | the evidence channel changed between arms | **yes** | `arm signals: none=none, coverage=coverage, invariant=invariant, full=full` |
| 2 | the budget is identical across arms | **yes** | `request_budget = {36}` |
| 3 | the seed and configuration are controlled | **yes** | `harness: tests/test_umdr31_campaign_e2e_ablation.py machinery (_run_arm: research_loop_node + family_execution_node over the controlled two-directory target)` |
| 4 | the actual selected experiments differ between arms | **yes** | `confirmed paths per arm: {'none': [], 'coverage': ['/api/zzz/vaults/vlt_3'], 'invariant': ['/api/zzz/vaults/vlt_3'], 'full': ['/api/zzz/vaults/vlt_3']}` |
| 5 | the changed experiments actually execute | **yes** | `requests_issued per arm: {'none': 36, 'coverage': 36, 'invariant': 36, 'full': 36}` |
| 6 | the resulting outcomes differ | **yes** | `confirmed per arm: {'none': 0, 'coverage': 1, 'invariant': 1, 'full': 1}` |
| 7 | the ground-truth case is confirmed only when supported by the actual evidence | **yes** | `ground truth: /api/zzz/vaults/vlt_3` |
| 8 | no authority or safety gate is bypassed | **yes** | `scope refusals honored per arm: {'none': 0, 'coverage': 2, 'invariant': 2, 'full': 2}; CausalGuard remains the sole confirmation authority` |

## Consistency statement

`full_loop_proven` in the artifact: **True**. This report, `UMDR38_READINESS.json` and the acceptance matrix describe the SAME experiment (the four-arm full-loop at the recorded budget) and do not contradict each other; the umdr37-era learning documents remain historical records of the same experiment family, not broader claims.

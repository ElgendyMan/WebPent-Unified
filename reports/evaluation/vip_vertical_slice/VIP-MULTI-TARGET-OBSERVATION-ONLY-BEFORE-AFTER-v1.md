# VIP Multi-Target Observation Classification — Before/After v1

## Scope

This comparison covers one bounded generic classification improvement in the VIP Autonomous Vertical Slice. It was executed only against the authorized local loopback validation slice for Juice Shop, WebGoat, and crAPI. The transport remained anonymous, GET-only, loopback-only, status/content-type metadata-only, with no credentials, payloads, state mutation, external contact, or Official P10 execution.

## Change

The orchestrator already defined `OutcomeStatus.OBSERVATION_ONLY`, but the non-causal path never used it. The generic status decision now classifies a case as `observation_only` only when the baseline is present and the independent negative control passes while no causal signal exists. Otherwise, the existing `inconclusive` classification remains available for incomplete or insufficient evidence. A sealed/promotable ProofBundle is still required for `confirmed`; this change cannot create a finding, enable scoring, or bypass governance.

The implementation is limited to the status decision in `src/webpent/shared/vip_vertical_slice.py`. The runner acceptance check was updated to require the explicit `observation_only` label. No TargetSpec, frozen ground truth, threshold, policy, ActionAuthority, CampaignExecutor, ProofBundle semantics, or qualification state was changed.

## Before and after

| Property | Before | After | Interpretation |
|---|---|---|---|
| Juice Shop root observation | `inconclusive` | `observation_only` | Reachability metadata is explicit, not a vulnerability result |
| WebGoat root observation | `inconclusive` | `observation_only` | Same generic behavior on a different TargetSpec |
| crAPI health observation | `inconclusive` | `observation_only` | Same generic behavior on a third TargetSpec |
| Causal signal | `false` | `false` | No new causal claim |
| Independent negative control | `true` | `true` | Safety/control evidence preserved |
| ProofBundle promotion | `false` | `false` | No non-causal evidence promoted |
| Seal/replay for promotion | `not_run` | `not_run` | Correctly withheld because no causal proof exists |
| Scoring promotion | `false` | `false` | No metrics or case-set inflation |
| Official P10 gate | `false` | `false` | Gate remains closed |

## Verification

The targeted VIP regression suite passed with `11 passed`. The same-condition multi-target runner passed all acceptance checks: three campaigns present, complete lifecycle for each target, explicit `observation_only` status for all three, independent negative controls, no quality scoring without admitted ground truth, no credentials, no state mutation, no external contact, closed Official P10 gate, and no qualification claim.

This improvement demonstrates generic classification portability across three TargetSpecs. It does not establish vulnerability-discovery quality portability, because the three selected root/health observations remain non-causal and no additional WebGoat or crAPI ground-truth/oracle contract was admitted.

## Rollback

Rollback is a single isolated revert of the status-classification change and the associated regression/runner expectation updates. The prior fail-closed behavior would return, but the explicit distinction between observation-only evidence and incomplete evidence would be lost. No data migration or target-state cleanup is required.

## Governance result

This is an AI-attributable technical implementation review within bounded local scope. It is not human signoff, P10 qualification, P9 qualification, VIP qualification, or authorization for an Official P10 run. The authoritative state remains: `human_independent_signoff_obtained=false`, `official_isolated_p10_runs_authorized=false`, `P10=NOT_QUALIFIED`, `P9=NOT_QUALIFIED`, `VIP=NOT_QUALIFIED`, `Bug Bounty=BLOCKED`, and `scoring_promotion=false`.

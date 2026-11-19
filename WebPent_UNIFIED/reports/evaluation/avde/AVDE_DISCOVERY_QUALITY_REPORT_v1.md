# AVDE Discovery Quality Report v1

## Executive result

This report evaluates AVDE using the previously recorded ASROS controlled artifact at `reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json`. The AVDE runner is offline and sent zero requests. It created no observations, no synthetic ProofBundles, and no new findings. Therefore the report measures replayable recorded-case disposition only; it does not claim a real-world vulnerability detection rate.

| Metric | Result | Interpretation |
|---|---:|---|
| Recorded cases | 4 | One confirmed recorded case and three blocked cases |
| Scorable cases | 1 | Only the recorded IDOR case met the source/ground-truth/proof conditions |
| Canonical scorable classes | 1 of 6 | IDOR is mapped to Broken Access Control; five required classes remain absent |
| Hypothesis relevance within scorable replay | 1.00 | The single scorable case had a recorded generated hypothesis; this is not production precision |
| Proof completeness within scorable replay | 1.00 | The single scorable case was recorded as proof-complete |
| Runner requests | 0 | Offline replay; no network activity by this runner |
| Blocked/inconclusive cases | 3 | Excluded from TP/FN/clean scoring |
| Real-world detection rate | Not measured | Deliberately preserved as `false` |

## Case disposition

The single scorable case is `controlled.idor.owner_resource.v1`, recorded against `controlled_local_idor_target_v1`, with the raw class `idor` normalized to the canonical class `broken_access_control`. Its recorded rank is 1, recorded request count is 3, and its source artifact marks the ground truth and proof as complete. These facts are replayed from the artifact; AVDE did not recreate the campaign.

The cases `asros-blocked-business_logic-v1`, `asros-blocked-information_disclosure-v1`, and `asros-blocked-privilege_escalation-v1` remain blocked because the source artifact states that no approved local causal fixture and candidate/control observations were available. They are not treated as false negatives, clean results, confirmed findings, or evidence of poor detection.

## Quality interpretation

The measured `1.00` values are conditional metrics over one already recorded, scorable case. They do not establish stable discovery quality, cross-target portability, six-class coverage, three isolated official runs, or VIP readiness. The source artifact's overall evidence quality remains `0.25`, while the AVDE report separately exposes the conditional scorable-case quality as `1.00` to avoid mixing blocked cases into the denominator.

The required six-class inventory is incomplete. Broken Access Control is represented through the IDOR alias; Privilege Escalation, Business Logic Abuse, Information Disclosure, Authentication Boundary Issue, and Data Exposure have no scorable cases in this recorded artifact. No synthetic cases were added to close that gap. AVDE now records six target-neutral adapter/oracle contracts, but each absent class remains `blocked` and `not_executed` until an actual compliant candidate/control artifact exists.

The benchmark also exposes bounded research-quality indicators: hypothesis relevance `1.00`, validation efficiency `0.333`, evidence completeness `1.00`, research-path efficiency `1.00`, duplicate-investigation reduction `1.00`, and registered-class coverage `1/6`. These are conditional measurements over the recorded artifact, not production precision, production recall, or real-world detection rate. AVDE's optional pipeline memory projection writes only redacted, target-isolated reasoning records through the existing `SecurityReasoningMemory`; it cannot authorize execution or promote a hypothesis.

## Governance state

The governing state remains unchanged: `official_isolated_p10_runs_authorized=false`, `P10=NOT_QUALIFIED`, `P9=NOT_QUALIFIED`, `VIP=NOT_QUALIFIED`, `Bug Bounty=BLOCKED`, `human_signoff=false`, and `qualification_effect=false`. The next legitimate quality milestone requires additional approved local causal fixtures and actual candidate/control observations, followed by central verification and sealed/replayable proof. It must not be achieved by relabeling blocked or observation-only records.

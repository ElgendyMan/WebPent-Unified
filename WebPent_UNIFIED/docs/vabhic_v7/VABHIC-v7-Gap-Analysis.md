# VABHIC v7 Gap Analysis

## Requirement coverage

| Requirement area | Implementation | Verification | Current limitation |
|---|---|---|---|
| Research Commander | `commander.py` | command-plan tests | Plans are advisory and do not execute |
| Security Mental Model | `mental_model.py` | model completeness and unresolved-question tests | Missing recorded fields remain unresolved |
| Unknown discovery v2 | `discovery.py` | hypothesis and fail-closed tests | No confirmation without target-backed causal evidence |
| Attack narratives | `narrative_budget.py` | narrative construction tests | Narratives remain hypotheses |
| Budget intelligence | `narrative_budget.py` | duplicate-path penalty test | No live cost or outcome feedback |
| Multi-agent coordination | `coordination.py` | five-specialist contribution test | Specialists do not possess authority or execute |
| False-positive skepticism | `coordination.py` | blocked assessment tests | Missing oracle/proof intentionally blocks |
| Controlled benchmark v6 | `benchmark.py` | six-class offline benchmark test | Empty recorded input leaves all cases blocked |
| Research analytics | `analytics_review.py` | null-metric test | Precision/recall/F1 and production rate unavailable |
| VIP readiness review | `analytics_review.py` | blocked governance test | No qualification or P10 gate opening |
| Safety and governance | contracts and result invariants | focused tests and static gates | Existing legacy blockers remain outside v7 |

## Evidence boundary

No target execution was performed. No credentials, cookies, login flow, mutation, destructive action, external callback, or external scope was used. The benchmark is therefore an **offline readiness benchmark**, not an operational detection benchmark. The absence of observations is represented as blocked or unavailable rather than as a false negative, clean result, or confirmed finding.

## Remaining path to qualification

The next legitimate evidence step would require a separately authorized local causal lab with immutable target/runtime identity, safe preconditions, candidate/control observations, a causal oracle, redacted sealed evidence, replay verification, and independent review. That step is outside this implementation because the current governing boundary does not authorize credentials, login, mutation, target execution, or P10/VIP gate changes.

Even after a local lab is authorized, qualification would still require the frozen governance thresholds, approved case/class minimums, valid ground truth, independent controls, repeated isolated runs, recomputed metrics, and formal owner/human decisions. VABHIC v7 does not manufacture any of those artifacts.

# The Learning Loop — statistical significance threshold (NC-ECON-1, U-ECON-11)

## The threshold

**No insight is ever produced from fewer than `MIN_DATA_POINTS = 10` records in
its group.** The gate is applied per group, not per journal:

| Insight kind | The group that must reach 10 |
|---|---|
| `class_focus` | submissions of that one vuln class |
| `program_focus` | accepted, paid submissions of that one program |
| `timing_adjust` | accepted submissions with a resolvable time-to-acceptance |
| `dup_pattern` | duplicate-rejected submissions |

A 2/2 acceptance rate says nothing. A 7/10 acceptance rate is the weakest
signal the loop will act on, and its confidence is scaled accordingly
(`confidence = min(1.0, group_size / (2 * MIN_DATA_POINTS))`, so the floor of
10 records yields confidence 0.5 and the ceiling of 20 records yields 1.0).

## Why 10

The charter fixes the floor. It is also the smallest group size at which a
single flip moves the rate by ten percentage points or less, which keeps the
increase/decrease/hold bands (≥75% increase, ≤25% decrease, else hold) stable
against one lucky or unlucky result.

## What the gate produces

Under the threshold the group is skipped entirely: no insight, no log line,
no scheduler delta. Empty or corrupt journals produce zero insights and never
raise. Everything the loop emits is advisory data (L-1, L-8):
`LearningInsight` records carry `{kind, recommendation, confidence,
data_points, rationale, timestamp, advisory:true}` and are appended to
`download/econ/learning_insights.jsonl`; `apply_to_scheduler` returns a
`SchedulerDelta` — a plain data record of suggested multipliers that mutates
nothing and calls nothing. The scheduler (or the operator) decides.

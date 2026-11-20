# UM-DR-37 Adaptive Planning Report

Generated 2026-11-16T05:24:44.894368+00:00.

Selection is deterministic and explainable: score = expected gain +
unresolved-family bonus - cost - risk - repetition penalty +
state-record terms (evidence tally +/-0.25, supported-confidence lift,
blocked-history penalty, budget-scaled cost/risk). Exhausted
signatures score -1000 and are never re-selected (pinned
adversarially). Decision records persist in three forms (decision_log
channel with closed DecisionType set, EGAIE DecisionRecord, research
loop telemetry). Repetition + budget terms make redundant low-value
experiments structurally unattractive — measured, not asserted.

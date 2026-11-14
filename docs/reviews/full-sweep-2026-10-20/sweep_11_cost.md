# Axis 11/12 — COST (what does this cost to run, and is the spend bounded?)

Depths: (a) LLM/token spend, (b) request budget honesty, (c)
compute/storage cost.

## Shallow (LLM spend)

The recent layers declare their LLM cost mechanically: the DEEP
bridge's probe hypotheses carry estimated_llm_calls=0 (verified in
deep/bridge.py — one request, zero LLM calls per finding); the
campaign BudgetGuard tracks max_llm_calls as an advisory dimension
and the report sums recorded llm_calls_used from phase results. No
unbounded LLM surface exists in forge/deep/campaign (they contain no
LLM client at all — source-locked in the storyteller tests).

## Medium (request budget honesty)

BudgetGuard rules on requests only (documented deviation from the
spec's three-dimensional ruling, with time/LLM flagged advisively).
The report generator sums only what phase results recorded — the
operator sees the authorized dimension ruling and the recorded spend
of the others. Honest by construction; no finding.

## Deep (compute/storage cost)

- CampaignMemory._all() re-reads every record file per recall query
  (O(n) reads, no cache). At operator scale (tens of campaigns) this
  is milliseconds; recorded as **F-07 LOW** for the roadmap.
- SQLite corpora grow with outcomes; no pruning exists. Assessed:
  operator-owned files, bounded by usage; noted in the roadmap, no
  finding at current scale.

## Verdict for this axis

F-07 LOW. Cost surfaces are bounded and honestly reported.

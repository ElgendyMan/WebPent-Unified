# UM-DR-38.1 — Discovery Funnel Integrity Report (Phase 5)

Generated: 2026-11-17T04:58:58.441174+00:00.

## The published contradiction, diagnosed

The UM-DR-38 records showed `causal_guard_confirmed = 2, proof_bundle_valid = 2, replay_verified = 0` while the same records carried two `passed = true` verification events. Root cause: TWO measurement sources were presented as one — the funnel derives its metrics from the authoritative GRAPH STATE (whose channels carry no replay flag for these findings) while replays happen in the promotion path, measured by the counted_verify instrumentation.

## The fix (stage definitions unchanged)

* scripts/confirmation_chain.py builds ONE per-finding view joined on finding_id across the run-summary artifacts and the instrumentation events, with every value's SOURCE labeled;
* the CausalGuard authority interface exposes no finding identity — its per-finding ids are recorded NOT_MATERIALIZED with the reason (never invented); confirmation stays at count level and the funnel stays OUT of the confirmation authority;
* duplicates are de-duplicated by id; missing evidence is null/NOT_MATERIALIZED — never 0; orphan replays (a replay bound to a non-promoted finding) surface as divergence flags;
* the invariants replay_verified <= proof_bundle_valid <= causal_guard_confirmed <= eligible_candidates are verified across BOTH sources; seven regression tests pin each failure mode.

## Measured chain per campaign

| Run | Guard confirmed | Sealed bundles | Replay verified | Promoted | Invariants |
|---|---|---|---|---|---|
| 1 | 2 | 2 | 2 | 2 | True |
| 2 | 2 | 2 | 2 | 2 | True |
| 3 | 2 | 2 | 2 | 2 | True |

The funnel's stage metrics (endpoints, candidate resources, hypothesis stages) remain graph-state-derived and unchanged; its authorization_observations/differential_questions channels are absent from this campaign's graph state — recorded as a MEASUREMENT LIMITATION, with the lab request log as the ground truth for the access behavior.

# UM-DR-39 — Before/After Comparison (§12.4)

Generated: 2026-11-17T12:44:18.931520+00:00 — the AFTER side is the FRESH campaign regeneration at this revision (the production entrypoint, authoritative final state via graph.get_state); the BEFORE side is the UM-DR-38.2 campaign record measured before the RC fixes.

| run | funnel replay_verified | promoted | confirmed | authorization_observations |
|---|---|---|---|---|
| 1 | replay=2 | promoted=2 | confirmed=2 | auth_obs=4 |
| 2 | replay=2 | promoted=2 | confirmed=2 | auth_obs=4 |
| 3 | replay=2 | promoted=2 | confirmed=2 | auth_obs=4 |

## What changed and what it means

* BEFORE (UM-DR-38.2 record): funnel replay_verified=0, promoted=0, confirmed=0 while the instrumentation recorded passing replays and CONFIRMED adjudications — the producer/consumer vocabulary mismatch (RC-1); authorization_observations=0 with NO producer in existence (RC-2) and the checkpoint redactor blanking the persisted channel (RC-2 layer 3); the lab log observed User_A/User_B while principals_observed=0 (the flag-gated identity stack, RC-4 — documented, not auto-enabled).
* AFTER (this record): the same authoritative final state now reports the confirmation chain it actually carries (RC-1) and the authorization context the CausalGuard evidence always held, projected at the promotion boundary (RC-2) and now SURVIVING checkpoint persistence.
* NOTHING was inflated: no counter was edited, no flag was flipped to manufacture numbers — every AFTER value is read from the real graph state by the same funnel, now counting the real producer vocabulary; the raw engine classes and the confirmation authority are untouched.

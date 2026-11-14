# UM-DR-34 Rate Governance Report

**Phase 5 deliverable — default-on request and concurrency
governance.** Implementation: `shared/http.py` (transport gate),
`shared/global_rate_governor.py` (coordination), `config/settings.py`
(fields), `agents/hunter_runner.py` (permits) — all re-pinned per
DR-009.

---

## 1. The new safety contract (§5.1)

Inside an **ACTIVE ENGAGEMENT** context, every request through a safe
client (sync AND async) is admitted through the process-wide
`GlobalRateGovernor` — **regardless of `stealth_mode` and regardless of
the legacy `rate_limit_enabled` switch**. Stealth mode adds jitter; it
is no longer (and never again) the mechanism responsible for bounding
request volume. Outside an engagement (plain library/tool use), the
legacy settings-gated posture is preserved unchanged.

Defaults, tuned against the measured campaign workload (§5.1's
"verify current campaign workloads"):

| Parameter | Value | Rationale |
|---|---|---|
| Concurrency | 16 in-flight requests | the differential-discovery engine's real burst width |
| Window budget | 900 requests / 60 s | measured egaie differential bands fire >120 requests in seconds; 120/min (the old default) starved the engine while still being arbitrary — 900 keeps a hard bounded ceiling that accommodates verified workload |
| Per-scope limits | `ScopeLimits` (1 rps / 1 concurrent default) | unchanged, enforced for the first time via HunterRunner permits |
| Operator overrides | settings fields, within the hard cap | `global_rate_governor_max_concurrent` / `_requests_per_minute` |

The default is **not unlimited** — it is a hard ceiling that a runaway
loop or hostile target cannot exceed.

## 2. One coherent governor (§5.2)

Coverage after this window: sync HTTPX ✓ (gate in
`SSRFPinningTransport.handle_request`), **async HTTPX ✓ (new — the
async transport had NO gate on the baseline)**, Playwright ✓
(transports its sub-resources through Chromium but navigation requests
are gated at the route-handler level by scope, and browser-level
pacing is governed by the crawl config's per-host interval —
documented, not re-implemented), external tools ✓ (bounded pacing via
the existing per-tool rate configs + the new origin gate),
business-logic concurrent bursts ✓ (per-host governor +
contextvar-correct per-thread contexts, preserved).

`ScopeEnforcer.acquire()/release()` are now part of actual request
execution: HunterRunner's `exploit_callback` acquires one permit per
candidate request phase and **releases in `finally`** — including
denial returns, cancellation, and network exceptions (the AVI
execution window runs INSIDE the permit scope).

## 3. Multi-process coordination (§5.3)

* `global_rate_governor_redis_url` (new setting): when configured, the
  singleton is built with a Redis client — the ceiling coordinates
  across worker PROCESSES.
* `snapshot()["coordination_scope"]` (new required field): `"memory"`
  backends report `"process-local"` — a process-local limit is never
  again describable as a globally coordinated limit (the baseline
  in-memory default was exactly that silent over-claim).
* `global_rate_governor_require_coordination` (new setting,
  fail-closed production posture): when True, a Redis construction
  failure or a mid-flight Redis failure **DENIES** every acquisition —
  a Redis outage can never silently turn one institution-wide limit
  into N uncoordinated process-local limits. Local development keeps
  the explicit, auditable process-local mode.

## 4. Failure behavior (§5.4)

| Failure | Baseline | Now (active engagement) |
|---|---|---|
| Settings-load failure | ceiling silently off | **ceiling stays on** (engagement mode is settings-independent) |
| Governor internal exception | fail-OPEN + CRITICAL log | **request DENIED** (`RateLimitExceeded`) + CRITICAL log |
| Invalid limits | constructor errors | constructor errors (unchanged, fail-closed) |
| Exhausted window budget | n/a (off by default) | request denied until the window rolls |

Non-engagement traffic keeps the legacy fail-open-on-governor-bug
posture so a governor bug cannot take down unrelated tooling; the
fail-closed posture is scoped to active campaigns exactly as
chartered. Control-plane traffic continues under its own explicit
configuration.

## 5. Latent async defect found and fixed (§4.2, evidence)

The async factory registered the **sync** `_redirect_guard` as a
response hook; httpx awaits every async response hook, so `await
(sync_hook)(response)` returned None into the event loop —
**every successful async response crashed with TypeError** once the
hook chain ran. Baseline coverage only exercised transport-level
denials (which bypass the hooks), which is why it survived. Fixed with
an async twin delegating to the identical decision function
(`_redirect_guard_async`); pinned by
`TestAsyncBoundary::test_async_in_scope_request_proceeds`.

## 6. Regression evidence

`tests/test_umdr34_boundary_enforcement.py::TestRateCeilingParity` —
sync ceiling, **async ceiling parity**, governor-explosion ⇒ denial
(fail-closed), ceiling independent of `rate_limit_enabled`;
`tests/test_global_rate_governor.py` — coordination_scope honesty,
coordination-required denial paths; `tests/conftest.py` — window-budget
test hygiene fixture (documented; per-test enforcement unchanged).

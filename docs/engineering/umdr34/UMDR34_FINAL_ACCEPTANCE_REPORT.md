# UM-DR-34 Final Acceptance Report

**Window:** UM-DR-34 — Unified Scope Authority, Safe Egress & Execution Governance
**Baseline:** `features/v0.39.0-umdr33` @ `4795f02`
**Final revision:** `umdr34-scope-authority-egress-hardening` @ `ed51ca10`
**Verdict: ACCEPTED WITH LIMITATIONS — 11 of 14 gates PASS, 3 PARTIAL
(each PARTIAL remains PARTIAL; none was turned green through wording).**

---

## Gate table (§14)

| Gate | Requirement | Status | Evidence |
|---|---|---|---|
| **A — Canonical policy** | One authoritative engagement policy, deterministic decisions | **PASS** | `scope/authority.py`; ONE strict wildcard compiler (fnmatch deleted); determinism/deny-precedence pinned; contract doc |
| **B — Missing context** | Active campaign without valid scope cannot send requests | **PASS** | atomic `EngagementContext`; invalid/no-policy engagement denies EVERYTHING (lifecycle tests; boundary test with 0 network attempts) |
| **C — Complete egress** | Sync, async, redirects, browser, WebSocket, tools use the policy | **PASS (with documented residuals)** | enforcement matrix: all 13 routes ENFORCED or CONTAINED; async parity incl. the latent hook-crash fix; residuals: 3/6 Playwright callers without launch-time pinning (documented backstop), APEX optional-scope (non-campaign-path), forms-channel state filter |
| **D — Private targets** | Exact, explicit private-target authorization; metadata blocked | **PASS** | bare-host declarations bind default HTTP(S) ports only; full-origin binding enforced before the blocklist exemption; link-local denied unconditionally under any engagement |
| **E — Wildcards** | No ambiguous glob expansion or inconsistent compilers | **PASS** | one compiler; `?`/`[seq]`/misplaced `*` rejected at compile; apex excluded; suffix-domain denial pinned |
| **F — Paths** | Include/exclude rules enforced at request time | **PASS** | segment boundaries, exclusion precedence, ambiguous-encoding conservative denial — all at the request boundary, zero-attempt pinned |
| **G — Rate control** | Default-on bounded execution independent of stealth mode | **PASS** | engagement ceiling always-on (sync+async), `rate_limit_enabled=False` asserted while the ceiling still denies; governor failure denies |
| **H — Multi-process** | No false global-limit claim when coordination is process-local | **PASS (unit-level)** | `coordination_scope` honest reporting; `require_coordination` fail-closed denial path tested; a REAL multi-worker Redis-outage drill was not executable here (see LIMITATIONS) |
| **I — LLM secrets** | Credential-bearing inputs rejected before provider I/O | **PASS** | key-aware recursion fix; cookie families; invoke/ainvoke/batch/stream pinned with a recording fake provider (`provider.received` empty/credential-free) |
| **J — Checkpoints** | No silent context loss or unsafe resume | **PASS** | degraded marker (structured, secret-free, logged); resume refuses blank-runtime rebuild; valid restore unchanged |
| **K — Audit** | Every denial explainable without exposing secrets | **PASS** | decision records carry reason tokens + fingerprints + matched rules; secret-free logging pinned (hidden-secret test) |
| **L — Regression** | Full suite green with exact accounting | **PASS** | 9,056 collected → 9,047/0/6/3, 13/13 chunks, exact reconciliation, zero removed tests, zero unexplained failures |
| **M — Release** | Version, branch, revision, archive and manifest agree | **PASS (publication blocked)** | v0.40.0 identity chain consistent (pyproject/init/Dockerfile/BUILD_INFO/CHANGELOG); deterministic archive built twice bit-identical; NOT pushed (no credentials — blocker recorded with exact commands); no public release claimed |
| **N — Security invariants** | CausalGuard, ProofBundle, replay, negative controls unchanged | **PASS** | no confirmation-authority changes anywhere in the window; full suite green over the untouched authority layer |

## The PARTIAL items (kept PARTIAL, per the charter)

1. **Compiled-graph execution of the E2E scenarios** — the transport
   boundary, redirect chain, guarded runnable, and checkpoint paths are
   the exact production chokepoints and are exercised with
   zero-network-attempt proofs; a full compiled-graph campaign run
   (live LLM + browser) was not executable in this sandbox.
2. **Campaign demonstration** — the direct HunterRunner path carries
   the new permits and target-only mode; no live-target campaign was
   run in this window.
3. **Independent validation** — NOT CLAIMED. M10 holdout remains
   BLOCKED_EXTERNAL_DEPENDENCY. No Recall/Precision/generalization/XBOW
   claims.

## Constitutional compliance

CausalGuard remains the sole confirmation authority. ProofBundle
generation and replay verification remain mandatory. Negative controls
remain mandatory. Authorization and scope enforcement are fail-closed
— strictly more so than the baseline. Per-request validation is now
literal at every network boundary. Budget ceilings, kill switches,
HITL, and execution boundaries are unchanged and additionally guarded
by the default-on request ceiling. LLM output remains advisory. No new
agents, planners, MCP, M10, or benchmark claims. No security check was
weakened — every test-contract change is a documented one-way
strengthening.

## Objective check (§Mission)

1. An authorized campaign cannot issue a request outside its declared
   scope — **demonstrated pre-network (0 attempts)** across sync,
   async, and redirect paths.
2. Missing/malformed/corrupted/expired scope context cannot silently
   grant network access — **fail-closed admission pinned**.
3. Redirects, browser requests, WebSockets, async HTTP, external
   tools, and direct invocation all face the same authorization
   contract — **enforcement matrix**.
4. Request-rate limits remain effective with `stealth_mode=False` —
   **pinned with the legacy switch off**.
5. Sensitive authentication material cannot enter LLM provider
   requests through alternate data structures — **key-aware recursion
   + cookie families + message-adjacent attributes, provider-recorder
   proof**.
6. Every denial is observable and auditable without leaking secrets —
   **decision records + secret-free logging proof**.
7. CausalGuard, ProofBundle, replay, negative-control, authorization
   and budget invariants remain intact — **gate N**.

*The objective was never to make WebPent send more requests. Every
request is now intentional, authorized, bounded, observable, and
reproducible.*

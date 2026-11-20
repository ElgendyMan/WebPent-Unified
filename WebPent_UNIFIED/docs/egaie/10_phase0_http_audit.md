# EGAIE Phase 0: Real-HTTP Source Audit and Integration Plan

Scope: connect the existing EGAIE loop to the real production HTTP
execution path against controlled local targets. No new discovery
engine; EGAIE's architecture is reused end to end.

## Source-grounded integration map

The production execution facade is `ActionExecutor`
(src/webpent/shared/campaign_executor.py:628), an alias over
`CampaignExecutor` (:255). Its real entry point is
`CampaignExecutor.execute(task, handler)` (:336), where task is a
`CampaignTask` (:48, frozen dataclass: task_id, engagement_id,
asset_id, vulnerability_class, hypothesis_id, risk_tier, budget,
method, capability, target_url, metadata, tenant_context) and the
handler is the caller-provided transport. Enforcement inside the
executor: context acquisition (:357), preconditions (:370),
idempotency dedup (:380), then `ActionAuthority.execute(request,
handler)` (:400), which authorizes first and invokes the handler
exactly once, reserving and completing the action in a SQLite ledger
(src/webpent/shared/action_authority.py:310-368). Authorization
checks, in order: foreign-writer capability patterns (:175),
`EngagementSafetyGate.authorize_request` (:193), engagement/task
identity (:198), target-package scope via
`ScopeCompiler.decide` (:200, src/webpent/shared/package_scope.py:219),
allowed action families (:250), origin scope (:252), read-method
autonomy vs human approval (:256), capability manifest (:265), G-02
adapter contract (:267, adapter_name + g02_inventory_ref +
g02_proof_contract validated against the registered adapter), and
budgets `smart_max_actions` / `smart_action_budget` (:295-303).
`ToolBoundary` (src/webpent/llm_researcher/tool_boundary.py:48) is a
pre-execution capability gate used by ModernSpine's experiment paths;
it is not needed for a CampaignTask flow, which is already gated by
ActionAuthority.

The production HTTP transport is NOT the executor; it is the
registered G-02 adapter's handler. `RuntimeFactory.create`
(src/webpent/shared/runtime.py:593) builds the whole spine:
EngagementSafetyGate, CapabilityRegistry, optional SQLiteActionLedger,
AdapterRegistry, ScopeCompiler, ActionAuthority (require_g02=True),
and `ActionExecutor(authority, proof_bundle_store=bundle_store)`
(:676-690), registering the `smart_http` adapter
(src/webpent/autonomous/hunt_runtime.py:120-137) whose handler is
`build_smart_campaign_handler` (src/webpent/agents/smart_campaigns/
agent.py:1515). That handler performs real HTTP with
`make_safe_httpx_client` (src/webpent/shared/http.py) after
`set_engagement_target_hosts(root)` (agent.py:1541) allowlists the
declared loopback/private target through the SSRF guard, and enforces
same-origin against the root (:1526). This CLI entry
(`webpent hunt-auto`, src/webpent/cli/commands.py:1298) wires it all
through `build_hunt_runtime` (src/webpent/autonomous/hunt_runtime.py:57)
with a written authorization document
(src/webpent/autonomous/authorization.py) required for any
non-dry-run.

EGAIE side: the loop needs exactly two ports implemented for HTTP -
`scope_allowed: bool` and `execute(experiment) -> (baseline, candidate,
control)` (src/webpent/egaie/orchestrator.py:73, 89). Each observation
must satisfy the CausalGuard completeness contract
(src/webpent/cqa_v2/causal_guard.py:94-117): status_code,
non-empty semantic_digest, no _placeholder key, and actor context
(X-Actor-Echo / X-Auth-State) plus resource context (X-Resource-Type /
X-Resource-Id / X-Resource-Owner). CONFIRMED additionally requires
X-Authorization-Outcome=granted_full with a foreign owner/tenant in
the candidate and a denied/403 control
(src/webpent/cqa_v2/causal_guard.py:569-578). Validation and proof
ports are already wired: CausalValidationPort delegates to
guarded_causal_evaluate; ProofBundlePort to
build_complete_proof_bundle + verify_replay
(src/webpent/egaie/causal_adapter.py). One honest gap:
runtime_provenance is hardcoded offline=True there; the HTTP path must
report real provenance.

## What already exists and will be reused (no duplication)

- Loopback vulnerable-server pattern:
  `ControlledIDORTarget` (src/webpent/adapters/controlled_target/
  adapter.py:151): stdlib ThreadingHTTPServer on ("127.0.0.1", 0),
  deterministic, reset()-able. The ASGI alternative is
  `serve_loopback` (src/webpent/rta/local_server.py:14).
- Production runtime construction: `RuntimeFactory.create` +
  G-02 `smart_http`-style adapter registration + `ActionExecutor`,
  exactly as `build_hunt_runtime` does.
- Safe HTTP client: `make_safe_httpx_client` with
  `set_engagement_target_hosts` for the loopback allowlist.
- Authorization discipline: a written
  EngagementAuthorization document verified by
  `verify_authorization` before the run, mirroring the CLI gate.
- Observation normalization: the port projects the ActionResult /
  handler output into the observation triple; no raw-body storage,
  digests only.

## Baseline (recorded before any change)

- tests/egaie: 32 passed.
- Six-case in-process benchmark (docs/egaie/02_benchmark_results.json):
  adaptive recall 1.0, FP 0, 7 experiments for 4 confirmed,
  experiments-per-confirmed 1.75, reproducible over 2 runs;
  baseline recall 0.75, FP 0, 6 experiments; thresholds pass.
- Known limitations (docs/egaie/05): fixture-only observations (no
  HTTP), hand-declared ground truth of 6 cases, scripted follow-up
  proposer, opaque world-model annotations.

## Smallest implementation plan (Phases 1-4)

1. `src/webpent/egaie/http_target.py`: a deterministic controlled
   HTTP ground-truth target (stdlib ThreadingHTTPServer on 127.0.0.1:0,
   reset()-able) implementing: IDOR/BOLA/AUTH_BYPASS-style positives
   with real authorization logic and role/ownership identities,
   one multi-step case where stage2's path is revealed only in
   stage1's stored-input response, negative controls that resemble
   vulnerable cases but deny, an inconclusive case, and an
   unavailable-capability case. The app computes and emits the
   X-Actor-*/X-Resource-*/X-Authorization-Outcome headers from its
   own authorization decisions; nothing is labeled for the detector.
2. `src/webpent/egaie/http_port.py`: `HTTPExperimentPort` with
   `scope_allowed` tied to a verified authorization document, and
   `execute()` performing every request as a `CampaignTask` through
   the production `ActionExecutor` (RuntimeFactory-built authority,
   G-02 adapter, ledger, budgets), with the transport handler using
   `make_safe_httpx_client` + `set_engagement_target_hosts`. Requests
   bounded, GET-only for read cases, deterministic idempotency keys
   per (experiment, role). Observations built from the real HTTP
   response (status, body sha256 digest, body_length, path, response
   X-headers). Tool-failure/blocked/capability-unavailable map to
   blocked observations, never to silent inconclusive.
3. `src/webpent/egaie/benchmark/http_runner.py`: versioned
   HTTP_GROUND_TRUTH_V1 with case definitions; adaptive vs
   fixed-order baseline over the same live target, per-case results,
   requests-per-confirmed and wall-time recorded, repeated runs for
   reproducibility, resume-correctness check via save/load; artifacts
   written to docs/egaie/. The six-case in-process benchmark stays
   reported separately and is never pooled with HTTP results.
4. Tests (red-first): real-HTTP execution through the executor,
   negative controls staying negative over HTTP, multi-step
   discovery, sealed replay-valid bundles with truthful provenance,
   scope denial, budget exhaustion, resume.

Acceptance thresholds (declared before the HTTP evaluation): HTTP
recall >= 0.6 on positives, FP == 0, all confirmed findings
replay-valid through real HTTP observations, negative controls
unconfirmed in both loops, adaptive >= baseline under the same
comparison rule as the fixture benchmark.

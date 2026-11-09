# Mission 0 — Logic Breaker: Repository Audit and Integration Plan

Date: 2026-10-22. Baseline: WebPent v0.14.0 (4388/4388 tests green, seals
13/13 OK, construction-authority gate exit 0). This phase delivers an
audit and a plan only — no feature implementation.

Constraints honored: `verdict/`, `emulator/`, `rehearsal/` untouched;
`production/modern_spine.py` and `live_hunter/profile.py` untouched
(frozen-manifest digest re-verified before and after audit:
`scripts/verify_frozen_manifest.py` → `FROZEN MANIFEST: OK (13 files)`).
No duplicate orchestration, evidence, graph or execution engine is
proposed; everything below reuses the existing ActionExecutor evidence
chain.

---

## 1. Integration map (actual source files, verified by reading)

### 1.1 The execution boundary (the only path a new probe may use)

| Component | File:line | Role |
|---|---|---|
| `ActionAuthority` | `src/webpent/shared/action_authority.py:81` | authorize → ledger reserve → invoke handler once. `_ALLOWED_FAMILIES` :84-96 = {http_read, browser_read, browser_action, recon, validation, workflow, form_submit, file_upload, oob}; `_READ_METHODS` :97 = {GET, HEAD, OPTIONS}; non-read requires `AUTHORIZED_ACTIVE` + `human_approved` (:256-260); DESTRUCTIVE always denied; capability manifest check :265-266; G-02 adapter metadata check :267-294; budgets :295-348 (per-request cost, `smart_max_actions`, `smart_action_budget`, idempotency, `SQLiteActionLedger.reserve/complete`). Foreign-writer guard :104/:175-187 (capability names containing report/writer/persist/ledger/finding/export are refused). |
| `CampaignTask` / `ActionExecutor` | `src/webpent/shared/campaign_executor.py:49`, `:628` | Task → `ActionRequest` mapping :326-330; idempotency dedupe :390-391; proof/ledger-integrated executor. |
| G-02 smart_http adapter | `src/webpent/egaie/g02_contract.py` + `shared/runtime.py` registry | `static_inventory_ref` docs/direct_io_inventory.json#native-http, proof contract `response-causal-negative-control-proof-bundle`. |
| Engagement auth | `src/webpent/autonomous/authorization.py:49` | `EngagementAuthorization` + target/scope verification. |
| EGAIE port (the demonstrated pattern) | `src/webpent/egaie/http_port.py` | `build_http_experiment_port` :410+; manifest `MANIFEST_CAPABILITIES = ("http_read","http_write")` :51; transport handler with SSRF allowlist; `_observation()` :64-77 (status_code, semantic_digest, body_length, headers, structured, request); stage-1 GET :122+ / POST :131+ (`_observe_post` with `method="POST"`, `capability="http_write"`, `action_family="form_submit"`, `risk_tier=ACTIVE`, deterministic idempotency key); stage-2 dispatch on `:stage2` signature suffix :125-127; case resolution via `HTTP_CASE_INDEX`/`HTTP_CASE_V2_INDEX`. |

Registration points a new family would touch (none of them sealed):
`shared/action_authority.py:84` (only if a new family string is needed —
price probes can reuse `form_submit`/`http_write`, so no change), the
port's own `MANIFEST_CAPABILITIES` (ours), and the case registry.

### 1.2 The evidence chain (sealed; call-only)

| Component | File:line | Key facts |
|---|---|---|
| `guarded_causal_evaluate` | `src/webpent/cqa_v2/causal_guard.py:503-605` (sealed) | Observation contract :51-91 (X-Actor-*, X-Resource-*, X-Authorization-Outcome, X-Effective-Privilege, status_code, semantic_digest, body_length, request.path, `_placeholder`); Gate-1 completeness :94-117 (fail-closed BLOCKED); `_authorization_mismatch` :246-367; `_authorization_enforced` :370-410; CONFIRMED requires mismatch(candidate) is True AND enforced(control) is True + same actor/resource + path-analogy + semantic diff :552-605. **CONFIRMED is hardwired to authorization differentials** — there is no price/amount/quantity signal. |
| `CompleteProofBundle` | `src/webpent/cqa_v2/proof_bundle_builder.py:29-102` (sealed) | One observation triple per bundle; SHA-256 evidence digests :57-64; deterministic seal :69-84; `to_native_proof_bundle()` :104-173 (native `ProofBundle` is `extra="forbid"`); `build_complete_proof_bundle(..., runtime_provenance=...)` :185+ accepts free-form provenance and stamps `native_proof_bundle_valid` :224-225. |
| `verify_replay` | `src/webpent/cqa_v2/replay_verifier.py:62-125` (sealed) | In-process reload + `verify_seal()` + **re-runs `guarded_causal_evaluate`** and compares verdict/seal/digests. Replay is logic re-evaluation, not re-issuing HTTP. **Consequence:** a bundle whose verdict came from any other oracle cannot pass this gate — multi-step evidence is expressed as stage-1/stage-2 bundles (already demonstrated by `pos-mutmulti-1`: POST stage-1 → inconclusive → GET stage-2 → confirmed, each with its own replay-valid bundle). |
| CausalValidationPort / ProofBundlePort | `src/webpent/egaie/causal_adapter.py:26-42`, `:56-103`, `HTTPProofBundlePort` `http_port.py:475-488` | Duck-typed ports on the orchestrator; HTTP port overrides only `runtime_provenance` to `{"mode":"controlled_local_http_target","offline":False,"transport":"action_executor"}`. |

### 1.3 The investigation loop (family-generic; clean seams)

`src/webpent/egaie/schemas.py`: `HypothesisRecord.family` is a free
string (:37-68); `ProposedExperiment.family/signature` free strings
(:71-108); `InvestigationState.observations` is `list[dict]` (:176-284).
Adding a hypothesis family requires **zero schema changes**.
`orchestrator.py:36-52` takes five duck-typed ports; `run()` :54-84;
`_confirm` :139-179 (hypothesis confirmed only if `replay_valid is
True`); `_update_hypothesis` :181-228. `selection.py:26-104`
(gain − cost − risk − repetition penalty; deterministic tie-break).
`seeds.py:17-42` (one hypothesis + one stage-1 experiment per case).
`persistence.py:15-23` (whole-state JSON snapshot; `RepetitionRegister`
ledger and port caches do not survive resume — tolerated by
deterministic idempotency).

Family-specific parts that DO need per-family extension:
`http_port._case_of` (ground-truth index dispatch) and
`benchmark/runner.py:44-80` `FollowUpProposer` (hardcoded to the three
ground-truth tuples; `multi_step` + stage-1 `inconclusive` → proposes
`:stage2`).

### 1.4 Recon / world model / tool scopes (reusable)

`live_hunter/world_model.py` `EvidenceGraph` :250-309 (bounded
principal→action→resource→observation→hypothesis chains, provenance
allowlist, secret redaction); `live_hunter/deep_recon.py`
`DeepReconEngine` :181 (route/OpenAPI/GraphQL ingest, trust boundaries,
hypothesis candidates); `live_hunter/research_loop.py`
`ResearchControlLoop` :93-159 (prioritization only — no execution port;
not a duplicate of EGAIE's causal-triple engine). `ScopeLaw`
(`tool_scope.py:335-349`) is the modern spine's separate gate — **not**
the path for this capability. `llm_researcher/tool_boundary.py:48` is
an LLM-researcher-scoped gate — likewise out of scope.

### 1.5 Browser path (gated; no free-form recording)

`shared/playwright_adapter.py:92` (observation handler: navigate,
screenshot, DOM, network capture, SSRF-guarded context :199);
`shared/control_plane_runtime.py` `BrowserActionAdapter` :461-570
(scope decision + engagement/session + operation allowlist :489-502 +
redaction-safe output), `WorkflowStateMachine` ~:700-764 (step-order
guard, idempotency), `seal_control_plane_proof` :806-847;
`shared/browser_proof_runner.py:146` (canonical three-observation
browser proof, operation allowlist :204-206); `shared/workflow_replay.py`
`ActionReplayEngine` (deterministic replay of recorded chains).
There is **no free-form workflow recording** by design; observation-level
workflow extraction exists in `shared/workflow_understanding.py:254`.

### 1.6 Existing business-logic package (prior partial attempt — reuse, don't duplicate)

`src/webpent/business_logic/` (357 lines, **zero importers, zero
tests**): `workflow_analyzer.py` (adapter over workflow understanding,
`promotion_status="candidate_only"` :48), `state_transition.py`
(`StateTransitionAnalyzer` :127, `TransitionCandidate.required_validation`
:112-119 names target-backed observation + negative control + sealed
replayable bundle), `invariant_checker.py` (`InvariantChecker.check`
:252-309, three network-free invariants, `status="candidate_violation"`
:236), `abuse_case_generator.py` (`AbuseCaseProposal` with
`required_controls` naming `scope_compiler_and_action_authority`
:334-342). Underlying engine: `shared/workflow_understanding.py:377-547`
(five hypothesis kinds: replay, cross_account_object, identity_boundary,
state_confusion, missing_transition_authorization; evidence contracts).
**No e-commerce/price-integrity semantics exist anywhere** (only the
generic transaction regex `workflow_understanding.py:36`).

### 1.7 Reporting and promotion

`reporter/export.py` `build_report_data` :151 (single source of truth;
expects `Finding` + native `ProofBundle`; JSON/markdown/HTML/PDF/SARIF
:411-906); `reporter/bounty_report.py` `build_bounty_report` :432;
`reporting/engagement_report.py` :272-281. **No EGAIE-state → Finding
mapping exists today** — that bridge is missing and must be built (new
file). Modern-spine promotion: `FindingLifecycle.can_promote`
(`modern_spine.py:1074`, read-only reference) and
`production/advisory_registration.py` (spine-caller guard :45-57) — the
EGAIE path does not route through these; EGAIE results land in
`InvestigationState` + benchmark reports.

---

## 2. Capability vs missing functionality

**Already capable (reusable as-is):** production execution path with
authority/approval/budget/idempotency; observation triples sealed into
`CompleteProofBundle` with real-HTTP runtime provenance; replay gate;
family-generic orchestrator with duck-typed ports and free-string
families; persistence/resume; deterministic multi-step (stage-1 →
stage-2) confirmation including mutating POST probes; benchmark
comparison discipline with declared thresholds and versioned ground
truth; workflow observation extraction and candidate-generation facades
(business_logic + workflow_understanding); gated browser execution and
replay; recon/world-model ingestion.

**Missing for price integrity (the actual gap list):**
1. A price-integrity case registry (v3 ground truth) and target surface
   (displayed vs accepted price, discount/coupon rules, order ownership)
   on the controlled target — none exists.
2. An invariant oracle. `guarded_causal_evaluate` cannot confirm
   "accepted price ≠ displayed price": its CONFIRMED rule keys on
   authorization mismatch/enforcement signals only, and it is sealed.
3. An experiment dispatch for the new family: `_case_of` resolves only
   IDOR/BOLA/AUTH_BYPASS/MUT_IDOR case ids.
4. A family follow-up proposer (FollowUpProposer is ground-truth-tuple
   hardcoded).
5. The EGAIE → `Finding` reporting bridge.
6. Optionally: family contract entry in
   `production/vulnerability_family_contracts.py` (unsealed; currently
   five families, fail-closed lookup :80-86).

---

## 3. Answers to the mission's seven questions

1. **Where should candidate business invariants be represented?**
   As EGAIE `HypothesisRecord`s with a free-string family
   (e.g. `PRICE_INTEGRITY`) plus a structured invariant spec carried in
   the case registry (benchmark fixture file, same discipline as
   `http_ground_truth.py`: fixture definitions separated from detection
   logic). The existing `webpent.business_logic` facades
   (`InvariantChecker`, `StateTransitionAnalyzer`) stay the
   candidate-source layer; their `candidate_only` outputs seed the loop.
   No schema change is needed.

2. **Can EGAIE accept a custom hypothesis type or experiment adapter?**
   Yes for hypotheses (free-string family/signature; dict observations).
   For experiments the orchestrator's `experiment_port` is duck-typed, so
   a new port executes new families cleanly; but the current
   `HTTPExperimentPort` dispatch and `FollowUpProposer` are
   ground-truth-hardcoded, so a price family needs its own dispatch
   branch/case index and proposer (both in our unsealed files).

3. **How can browser workflows be recorded without bypassing the
   boundary?** They cannot be free-form recorded by design. Two gated
   options exist: (a) HTTP-level flows through the existing
   ActionAuthority path (recommended for the price demo: cart/checkout
   APIs); (b) browser flows through `BrowserActionAdapter`'s operation
   allowlist + scope decision + `WorkflowStateMachine` + `ActionReplayEngine`
   (`browser_action` family, ACTIVE + approval for non-read). Recording
   happens at observation level via
   `shared/workflow_understanding.extract_workflow_observations`.

4. **Can real local HTTP request/response observations attach to the
   proof contract?** Already proven in v0.13.0/v0.14.0: `_observation()`
   triples (status, digest, length, headers, structured) feed
   `CompleteProofBundle` with per-observation SHA-256 digests and
   `runtime_provenance={"mode":"controlled_local_http_target",
   "offline":False,"transport":"action_executor"}`. Multi-request
   sequences attach as stage-1/stage-2 bundles (POST → GET demonstrated).

5. **Which persistence and reporting interfaces should be reused?**
   `egaie/persistence.py` (whole-state snapshot, works unchanged for a
   new family) and `reporter/export.py build_report_data` +
   `reporter/bounty_report.py` (consumed via a `Finding`-shaped dict with
   a native ProofBundle — the mapping is the only new piece), with the
   benchmark report dataclasses as the intermediate metrics layer.

6. **Which minimal interfaces are missing?** Five, listed in §2. Plus one
   constraint-driven design piece: because both `causal_guard.py` and
   `replay_verifier.py` are sealed and the replay gate re-runs the sealed
   guard, a non-auth invariant oracle must ship with its own
   `ProofBundlePort`-compatible verify that (i) re-verifies the sealed
   bundle via the builder's `verify_seal()` and (ii) re-runs the new
   oracle on reloaded observations (same reload-digest-compare pattern),
   never modifying sealed files. Auth-expressible violations (cross-owner
   price mutation) can alternatively ride the existing guard unchanged.

7. **Smallest complete end-to-end demonstration?** One controlled-target
   price-integrity surface + v3 case registry (2 positives, 2 negatives,
   one multi-step) + one new port dispatch + invariant oracle port +
   proposer + one red-first test file + benchmark `http-v3` run recorded
   in docs. Estimated: 5 new files (or fewer, some as extensions of our
   own files), zero touches to sealed or protected files, zero changes to
   schemas, orchestrator, ActionAuthority, CausalGuard, bundle builder,
   or replay verifier.

---

## 4. Proposed package/API design (all in unsealed, our own files)

New module `src/webpent/egaie/logic_port.py` (single file, mirrors
`http_port.py`'s structure):

- `build_logic_experiment_port(target, engagement_id, campaign_id,
  authorization, settings) -> LogicExperimentPort` — RuntimeFactory
  ActionAuthority, same G-02 smart_http adapter, manifest
  `("http_read", "http_write")`; dispatch by case index `LOGIC_CASE_INDEX`;
  stage-1 GET for displayed-price observation, POST (form_submit, ACTIVE,
  deterministic idempotency token, `human_approved`) for price-affecting
  mutations; stage-2 follow-up GET, identical to the V2 pattern.
- `InvariantValidationPort` — same `validate(b, c, ctrl) -> dict`
  contract as `CausalValidationPort`. Rule (stated honestly, never
  ground-truth-aware): CONFIRMED only when candidate violates the
  declared invariant predicate (e.g. accepted amount ≠ displayed price
  for the same actor) while the enforced `/control` route upholds it and
  baseline (own-resource) behaves; CLEAN otherwise; INCONCLUSIVE when
  the predicate cannot be evaluated from the observations; BLOCKED on
  incomplete observations (mirroring Gate-1 fail-closed).
- `LogicProofBundlePort` — builds via the sealed
  `build_complete_proof_bundle` (unchanged), and verifies by reload +
  `verify_seal()` + re-running `InvariantValidationPort` + comparing
  verdict/digests (the existing replay pattern, reimplemented for the
  new oracle, calling sealed code only). `runtime_provenance` identical
  and truthful.

Extension of our own files: `benchmark/http_ground_truth.py` gains
`HTTP_GROUND_TRUTH_V3` (`http-v3`, PRICE_INTEGRITY cases, never pooled
with v1/v2); `http_target.py` gains the price surface (displayed price on
GET, accepted price on POST checkout, coupon endpoint, `/control`
enforced siblings, idempotent per-token mutations like V2);
`benchmark/http_runner.py` parameterized already by `cases=` — add the
v3 declared-version entry; new `LogicFollowUpProposer` (same propose()
contract) for the multi-step price case. Reporting bridge: new
`src/webpent/egaie/finding_bridge.py` mapping confirmed hypotheses +
verified bundles → `Finding`-shaped dict with native ProofBundle for
`reporter/export.py`.

`webpent.business_logic` facades remain the candidate-source layer
(wired in a later phase as an alternative seed source); they are not
duplicated and not modified in this mission.

## 5. Minimal dependency plan

No new third-party dependencies. Everything is stdlib + existing
httpx-wrapper transport + sealed builders. New internal imports only:
`logic_port.py` → shared.runtime / action_authority / http (same as
http_port), cqa_v2.proof_bundle_builder, egaie.schemas/persistence;
`finding_bridge.py` → models.proof_bundle, reporter.models. Target
surface extends the existing stdlib `http_target.py`.

## 6. Ordered implementation plan with acceptance criteria

Phase L0 — Red-first tests (one commit): 
`tests/egaie/test_logic_price_integrity.py` with ~9 tests mirroring the
V2 discipline: target routes deterministic (displayed vs accepted price,
cross-actor checkout defect, enforced control denies, effect observable
by follow-up GET); mutation idempotent per token; port executes through
ActionExecutor (AUTHORIZED_ACTIVE + human_approved; SAFE_SMART fails
closed with state unchanged); invariant verdict confirmed with
replay-valid bundles; negative controls clean; resume never double-applies
(`applied_count_for_family("checkout", ...)` == 1);
`run_http_comparison(..., cases=HTTP_GROUND_TRUTH_V3)` report:
version `http-v3`, thresholds_pass True, adaptive > baseline, 0 FP,
replay_valid == confirmed, reproducible, resume_correct. 
Acceptance: tests red for the right reason (ImportError/AttributeError on
new symbols only), suite count 4388 → 4397 monotonic.

Phase L1 — Target surface + registry (one commit): `http_target.py`
price routes + `http_ground_truth.py` v3 (4 cases: cross-actor price
mutation, enforced sibling, multi-step coupon-then-checkout positive and
negative). Acceptance: route tests green; no detection logic in fixture
files; `/control` siblings enforced.

Phase L2 — Port + oracle + proposer (one commit): `logic_port.py`
(dispatch, transport, manifest, idempotency tokens),
`InvariantValidationPort`, `LogicProofBundlePort`,
`LogicFollowUpProposer`, runner v3 version entry. Acceptance: full
logic suite green; orchestrator/selection/schemas/CausalGuard/bundle
builder/replay verifier/ActionAuthority untouched (diff check); seals
still OK.

Phase L3 — Benchmark + docs + bridge (one commit): run
`run_http_comparison` on v3, record verbatim in
`docs/logic_breaker/01_price_integrity_results.md` with honest scope
(deliberately-built target, pre-known paths, one defect family, no live
targets); `finding_bridge.py` + its test mapping one confirmed state to
a `Finding`-shaped dict with native bundle validation; README status
line. Acceptance: bridge test green; docs record the real run; full
battery (seals, gate, monotonic count, ruff, no getattr/broad-except)
passes; ZIP delivered from HEAD.

## 7. Current test and benchmark baselines

Tests: 4388 passed / 0 failed (monotonic from 4379 at v0.13.0; +9
state-change tests in v0.14.0). HTTP suites: `test_http_execution.py`
10 tests (http-v1), `test_http_state_change.py` 9 tests (http-v2).
Benchmarks (recorded, never pooled): http-v1 adaptive 4/4 recall 1.0 vs
baseline 3/4 0.75, 0 FP, replay-valid, 21 vs 18 requests
(docs/egaie/11); http-v2 adaptive 2/2 recall 1.0 vs baseline 1/2 0.5,
0 FP, 18 vs 12 requests, idempotency-proven resume (docs/egaie/12).
Frozen manifest: 13 files OK; construction-authority gate exit 0.

## 8. Risks and unresolved assumptions

1. **Sealed-oracle wall (highest):** the replay gate re-runs the sealed
   `guarded_causal_evaluate`; a non-auth invariant oracle therefore
   needs its own verify path (§3.6) or must express violations as auth
   mismatches. Mitigation: `LogicProofBundlePort` calling sealed code
   only; never editing sealed files. If a future review rules this out,
   the fallback is auth-expressible price defects only (cross-owner
   mutation), which pass today's guard unchanged.
2. **Invariant-oracle subjectivity:** "price accepted ≠ displayed" must
   be a declared predicate evaluated from observation `structured`
   fields, never from ground-truth labels; otherwise the benchmark
   leaks answers. Mitigation: predicate declared per case in the fixture
   file; oracle reads only observations.
3. **RepetitionRegister not persisted:** resume resets repetition
   penalties. Already tolerated in v1/v2 via deterministic idempotency;
   same applies here.
4. **Two coexisting authority systems (ScopeLaw vs ActionAuthority):**
   this capability binds to the ActionExecutor path only; ScopeLaw/
   ToolBoundary stay untouched.
5. **Capability naming trap:** avoid foreign-writer substrings in any
   new capability name (`action_authority.py:104`); `http_write` reuse
   avoids the issue entirely.
6. **Assumption:** the price surface stays on the loopback controlled
   target; no live-target evidence is claimed. Advisory-only discipline
   (no external submissions) unchanged.
7. **Assumption:** `webpent.business_logic` facades remain stable
   consumers later; they are currently unwired and untested, so phase L0
   does not depend on them.

# VIP Roadmap — Detailed Engineering Execution Plan
> For Claude: Execute all tasks autonomously. Governance: vip_qualified=false, P10=CLOSED, local-only synthetic targets.

## Phase A: Engine Completion (P0)

### A1 — Stateful Execution Engine
**File:** `src/webpent/goed_v1/stateful_executor.py`
**Dependencies:** `src/webpent/cqa_v2/proof_bundle_builder.py` (extend for step traces)

**Tasks:**
1. Create `StatefulExecutor` class with:
   - `discover_prerequisites(target, actor_context)` — discovers required tokens, session state, prior resources
   - `acquire_state(prerequisites)` — executes GET requests to obtain state tokens/identifiers
   - `execute_action(action_spec, state)` — executes state-changing action (POST/PUT/PATCH)
   - `observe_state_transition(before_state, after_observation)` — compares before/after state
   - `replay_candidate(action_spec, state)` — replays action for verification
   - `replay_control(action_spec, state)` — replays on control route
   - `check_post_conditions(initial_state, final_state)` — verifies invariants violated/preserved
2. Add `step_trace` field to ProofBundle builder (list of execution steps)
3. Each step records: timestamp, action, request_params, response_status, observed_state_delta, causal_signals
4. Test with business logic pattern: negative-amount transfer (balance should decrease but instead increases)

**Output:** Stateful multi-step vulnerabilities can be executed and verified.

### A2 — Business Logic Invariant Strategies
**File:** `src/webpent/goed_v1/business_logic_strategies.py`
**Dependencies:** `src/webpent/goed_v1/exploration_loop.py` (integrate with invariant miner)

**Tasks:**
1. Define 7 invariant detector classes:
   - `QuantityConservationInvariant` — sum of values should be preserved (e.g., transfer total)
   - `BalanceConservationInvariant` — account balance changes should match transfer amounts
   - `WorkflowOrderingInvariant` — steps must happen in correct order (e.g., approve before finalize)
   - `ApprovalSeparationInvariant` — requester cannot also be approver
   - `OwnershipConsistencyInvariant` — resource owner shouldn't change unexpectedly
   - `StateTransitionValidityInvariant` — only valid state transitions allowed
   - `ReplayResistanceInvariant` — same action twice shouldn't double effect
2. Each detector: `hypothesize(observations)`, `test_prediction(action)`, `validate(result)`
3. Integrate with exploration loop: invariants hypothesized from evidence, never injected
4. Business-logic finding requires causal state evidence (before/after state delta)

**Output:** Business logic vulnerabilities can be hypothesized and tested from observed state.

### A3 — Runtime Discovery Enhancement
**File:** `src/webpent/goed_v1/open_world_mode.py` (modify `discover_from_response`)

**Tasks:**
1. Add HTML link extraction: `<a href>`, `<form action>`, `<script src>`
2. Add Location header following (redirect chains)
3. Add nested JSON entity reference detection: objects containing IDs that look like resources
4. Add OPTIONS probing on discovered paths (detect allowed methods)
5. Add HEAD request probing (lightweight discovery)
6. Measure and report: OPENAPI_DISCOVERY_RATE, RUNTIME_DISCOVERY_RATE, MULTIMODAL_DISCOVERY_RATE

**Output:** Discovery works beyond OpenAPI-only dependence.

### A4 — Adversarial v2 Execution
**Files:** `benchmarks/goed_v1_6_hidden/adversarial_generator.py`, `reports/goed_v1_6/adversarial_results.json`

**Tasks:**
1. Generate 20+ adversarial cases from 12 patterns:
   - same_status_different_semantics, different_status_same_meaning
   - misleading_endpoint_names, misleading_json_fields, decoy_admin_endpoints
   - equivalent_public_private_names, noisy_headers, reordered_fields
   - randomized_identifiers, route_aliases, nested_apis, dynamic_links
2. Run enhanced engine against adversarial targets
3. Measure FP and FN independently
4. Investigate every FP/FN individually with root cause

**Output:** Adversarial robustness measured and documented.

---

## Phase B: Qualification Campaign (Engineering Prep)

### B1 — P10 Authorization Request Document
**File:** `docs/authorization/P10_AUTHORIZATION_REQUEST.md`

**Tasks:**
1. Document current capabilities with evidence
2. Risk assessment: local-only, synthetic, no destructive actions
3. Governance guarantees: fail-closed, smart never overrides causal, memory capped
4. Request formal authorization to open P10

**Output:** Formal authorization request document ready.

### B2 — Approved Synthetic Target v11
**File:** `benchmarks/qualification_v11/approved_synthetic_target_v11.py`

**Tasks:**
1. Fresh FastAPI target, 15 cases × 10 classes minimum
2. Includes: IDOR, BAC, PrivEsc, Tenant Isolation, Business Logic, Workflow Auth, Sensitive Data, Multi-Step Chain, plus 2 new patterns (e.g., Mass Assignment, Race Condition window)
3. Generated AFTER current engine freeze
4. Proper headers, control routes, ground truth isolated
5. All routes emit real HTTP headers via JSONResponse (no HTTPException)

**Output:** Qualification-grade synthetic target ready.

### B3 — Official Isolated Runs (×3)
**File:** `benchmarks/qualification_v11/official_runs/`

**Tasks:**
1. Clean-room execution: no memory warm-up, no prior knowledge
2. Deterministic sealing of all artifacts with SHA-256
3. Run 1, Run 2, Run 3 — each independent
4. Measure: Precision, Recall, F1, Proof completeness, Replay completeness
5. Threshold check: Precision≥0.95, Recall≥0.70, Proof≥0.95

**Output:** 3 official run records, sealed and verifiable.

---

## Phase C: Review Documentation

### C1 — Independent Review Package
**File:** `docs/review/INDEPENDENT_REVIEW_PACKAGE.md`

**Tasks:**
1. Compile all evidence: causal reasoning, generative capability, governance integrity, proof completeness
2. Include: architecture diagrams, threat model, governance invariants, test results

**Output:** Review package ready for external auditors.

---

## Phase D: Final Delivery

### Tasks:
1. Update all acceptance gates
2. Update final truth audit
3. Update executive summary
4. Rebuild `WebPent-GOED-v1.6-Full.zip`
5. Update VIP roadmap with actual execution results

---

## Governance Rules (NEVER break)
- `vip_qualified` = false at all times
- `qualification_state` = CONDITIONAL
- P10 = CLOSED (document request only, don't actually open)
- No external targets
- No real credentials
- No destructive actions
- All changes ADDITIVE
- Historical artifacts preserved

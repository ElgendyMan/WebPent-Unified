# UM-DR-32 Execution Report

**Window:** UM-DR-32 — Workstream B (the four capabilities) + unification
**Report date:** 2026-11-09

---

## 1. What was actually built

Five new production modules (all frozen from birth — see §6), one
production graph node, six state channels, four capability flags, one
validator-route closure, one controlled evaluation lab, and 154 new
tests across nine modules.

> **UM-DR-33 §3.7 correction (2026-11-10):** this report originally said
> "152 new tests". Recomputation from actual pytest node IDs shows the
> nine `test_umdr32_*.py` modules carry **154** unique test IDs
> (7+17+20+13+18+18+22+32+7), and the full UM-DR-32 window added
> **159** (154 + 5 frozen-gate parametrized entries) — exactly what
> `UMDR32_TEST_ACCOUNTING.json` records. The "152" was an arithmetic
> undercount in prose only; the machine-readable accounting was always
> correct. Recorded as an erratum, not silently rewritten.

| Module | Lines | Role |
|---|---|---|
| `production/object_identity.py` | ~670 | the typed identity model + registry + campaign-state ingestion |
| `production/alias_resolution.py` | ~450 | the reversible alias overlay |
| `production/multi_identity.py` | ~500 | principals, matrix, differential questions, validator-input construction |
| `production/composite_workflows.py` | ~840 | observed workflows, bounded sequences, the safety contract, two-route evaluation |
| `production/identity_workflow.py` | ~420 | the unified production node + hypothesis construction |

## 2. Architectural decisions (and their justifications)

1. **One node, four capabilities** (not four nodes): the capabilities
   share a single reasoning pass over the same observations and feed the
   same strategist line; four nodes would multiply supersteps and
   channels for no information gain (§1.4 no architectural inflation).
   Per-capability flags still allow independent ablation arms.
2. **Composed conditional-redirect wiring** (`_research_route_redirects`
   = `_umdr32_routes(_umdr31_routes(routes))`): the identity node runs
   BEFORE research_loop when both are on; each layer is a no-op when
   its flags are off, preserving the byte-comparable flag-off shape of
   every layer beneath (test-enforced).
3. **The anchor is (tenant, resource_type, stable_id) — never the
   path**: enforced in code (§4.2) and tests; `identity_id` is a
   deterministic uuid5 over the anchor, so the same object under
   completely different paths resolves to one identity.
4. **Id-equality alone never merges**: corroborating evidence is a
   distinct evidence-kind set; without it the pair is at most a
   candidate/abstention (the precision-first contract, §1.3).
5. **Two evaluation routes inside the EXISTING validation
   architecture**: same-actor state evidence goes to
   `cqa_v2.guarded_causal_evaluate` (the guard's design domain — its
   same-actor check is exactly right for state differentials);
   cross-actor boundary evidence goes through the REGISTERED
   privilege-differential validator (`run_validator`), which existed
   since UM-DR-31.1. No new confirmation path exists (test-enforced:
   the new modules expose no promotion vocabulary at all).
6. **The validator-route closure** (§6.5): the missing link was the
   capability REGISTRY entry (the strategist's classifier), not the
   validator. Registered `privilege_differential` in
   `agents/validator/registry.py`, added the
   `PRIVILEGE_DIFFERENTIAL` experiment to `EXPERIMENT_REGISTRY`, and
   built the typed triple constructor
   (`build_privilege_differential_input`) that preserves principal
   identity, tenant context and object identity end-to-end with the
   session-isolation invariant (SessionBindingError before any request
   is spent).
7. **Destructive-step safety by contract** (`FixtureSafetyContract`):
   destructive steps require resettable + isolated +
   operator-authorized + method-allowed, and state-mutating sequences
   require resettable isolated fixtures — both tested at the boundary.
8. **Frozen from birth**: the five capability modules are pinned in the
   frozen manifest from their first release (the broad-exception count
   contract requires registered files pinned; freezing all five gives
   every production module the same edit discipline).

## 3. Production integration (the §8 research-to-execution chain)

For each signal class, the ten-step chain with its evidence:

| Step | Evidence |
|---|---|
| 1. produced | `observations_from_campaign_state` over real channels (openapi/workflow/declared) |
| 2. state field | the six declared channels (state.py, contract-tested) |
| 3. consumer | strategist (hypotheses), `stateful_research_hints` (hints), the lab executor (questions/candidates) |
| 4. testable hypothesis | `Hypothesis` records with deterministic uuid5 ids, preconditions, expected behavior, negative controls |
| 5. valid case construction | differential questions REQUIRE a denied negative control; workflow candidates REQUIRE observed transitions + supporting refs |
| 6. budget selection | ordering-only hints (same budget); per-sequence caps; differential dedup by target |
| 7. authorized executor | injected clients only (the StatefulCaseProber/SequenceClient contract); scope checks inside the adapter |
| 8. CausalGuard evaluation | same-actor: `guarded_causal_evaluate` on the real triple; cross-actor: the registered validator route |
| 9. evidence recorded | traces with phases (positive control / experiment / negative-control probe), provenance refs |
| 10. feedback | pool dedup means confirmed/rejected hypotheses are never regenerated; telemetry in `identity_workflow` |

## 4. Validator routing (the closed gap)

Before UM-DR-32: `privilege_differential` hypotheses →
`validator_id_for` → None → strategist records `missing-validator` →
promotion downgraded to DEFER (the documented UM-DR-31.1 limitation).

After: `validator_id_for('privilege_differential') ==
'privilege_differential'` (capability registry) →
`run_validator('PRIVILEGE_DIFFERENTIAL', ...)` dispatches
`validate_privilege_differential` (VALIDATORS, pre-existing) →
CONFIRMED/REFUTED/INCONCLUSIVE with refutation paths → the
EXPERIMENT_REGISTRY entry makes the experiment fabric path executable.
Route tests: `TestPrivilegeDifferentialValidatorRoute` (4 tests,
including the real dispatch on a real triple).

## 5. New test coverage (154 tests, nine modules — see §3.7 erratum above)

- object identity (20): all §9.1 identity scenarios + determinism +
  provenance + bounds + volatile/secret attribute stripping
- alias resolution (13): the §9.1 alias scenarios + reversibility +
  conflict preservation + the F10/F11 fingerprint non-regression
- multi-identity (18): principal model, matrix, questions (+ the
  no-control abstention), the route closure (4), the typed input, the
  session-contamination fail-safe, credential-free projections
- composite workflows (18): observed-only construction, bounds, the
  safety contract, live-fixture execution (violation candidate / false
  hypothesis / denial / budget / failure telemetry / provenance)
- integration (22): wiring on/off, byte-comparability, channel
  contract, LangGraph survival, hypothesis pool dedup + routing, hint
  flow, no-promotion vocabulary, fail-soft faults
- security regressions (32): §10.2-10.6 in full
- evaluation lab (7): the six-arm measurement + determinism
- archive builder (7) + scope admission (17): the engineering remediations

## 6. Frozen-manifest protocol compliance

- 6 existing frozen files re-pinned with the documented rationale
  (version bump, state channels, settings flags, builder wiring,
  validator registry, experiment fabric).
- 5 new modules frozen from birth; the baseline-disagreement gate's
  documented scope extended (`UMDR32_NEW_CAPABILITY_20261109_PATHS`).
- Direct-I/O inventory regenerated deliberately (+7 declared
  dynamic-resolution identities, 0 removed, unapproved pin set
  preserved).
- Broad-exception register extended (25 handlers, full rationale).

## 7. Unimplemented items and why

| Item | Status | Reason |
|---|---|---|
| MCP integration, XBOW comparison, external holdout | NOT IMPLEMENTED | §1.5 explicit non-goals |
| Full 45-node LLM campaign traversal | NOT RUN | requires operator LLM credentials (unavailable); the LangGraph-level wiring is proven with real compiled graphs |
| Cross-campaign identity memory | NOT IMPLEMENTED | per-campaign registry is the bounded scope; cross-campaign state is a separate architectural decision |
| Automatic attribute-signature corroboration | NOT IMPLEMENTED | requires a measured attribute-stability model; the evidence kind exists, the automatic matcher does not (documented limitation) |
| Alias/workflow execution as autonomous graph nodes | DELIBERATELY DEFERRED | execution stays under the authorized executor/harness path (the stateful-discovery precedent); promoting engines into the graph without operator-controlled budgets would violate the bounded-execution contract |

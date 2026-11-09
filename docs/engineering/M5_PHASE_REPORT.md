# M5_PHASE_REPORT.md — M5 (Stateful REST API Testing)

**Phase:** M5 of the CANONICAL_PHASE_REGISTRY (Part 4 §7 — P1).
**Date closed:** 2026-11-06 (UTC).
**Window:** DRIFT_REGISTER UM-DR-18.
**Baseline entering:** post-M3 tree (UM-DR-17); frozen authority manifest untouched; frozen-module gate 661 green.
**Refreeze:** `scripts/refreeze_manifest_m5_stateful_api.py` — exactly 2 declared frozen changes (`config/settings.py`, `agents/api_testing/agent.py`), tests-before-refreeze discipline, post-write self-check passed (neither file predates the pre-unfreeze baseline drift set, so no thaw-set registration was required).

---

## 1. What was delivered

The registry's entering note: "primitives exist (multi_step_auth passive node, api_testing) — engine is greenfield". The engine is the new `stateful_api/` package (outside the frozen gate), wired advisory-only into the frozen `api_testing` node behind a fail-closed flag.

### 1.1 — Contract ingestion (`stateful_api/contracts.py`)

- `ApiOperation` — one REST operation from an OpenAPI schema (rich: body properties, auth requirement) or observed traffic (thin: method + path + query), provenance-preserved per operation.
- `operations_from_state` — derives the operation set from the channels the production graph already populates: `crawled_data["openapi_routes"]` (the frozen schema-ingestion projection) first, then the observed surface via `shared.family_feeds.endpoint_inventory_from_state` (UM-DR-17) for keys the schema did not cover. Deduped by (method, path), bounded at 500.

### 1.2 — Dependency/state model (`contracts.py`)

- `infer_dependencies` — the deterministic producer→consumer heuristic: a creator (POST/PUT/PATCH on a collection path) PRODUCES the identifier its item-path consumers CONSUME (`POST /api/v2/users` produces `user_id` for `GET /api/v2/users/{id}`). Every edge is labelled `inferred:path_shape` — a reproducible planning input, never asserted target truth.

### 1.3 — Bounded sequence generation (`stateful_api/sequences.py`)

- `generate_sequences` — walks the dependency graph from each creator; a sequence is a deterministic chain where each step consumes state a previous step produces. Bounded twice (max_sequences × max_depth) plus a per-plan request budget.
- `SequencePlan` — the replay contract: preconditions (identity + seed state), per-step request specs, expected effects, the randomized-id negative control, and the CLEANUP plan (reverse order; DELETE where the contract has one — a sequence with no reverser says `cleanup_complete: False` honestly). `replay_spec()` is byte-stable (same preconditions, identities, requests — test-pinned determinism).

### 1.4 — BOLA/IDOR differentials (`stateful_api/bola.py`)

- `build_bola_plans` — for every object-consuming operation: identity A creates and accesses its own object (the allowed baseline), identity B attempts the cross-identity access (the differential), and the NEGATIVE CONTROL pins the enforcement baseline (B requests a randomized non-existent id — the 404/403 that proves an access check exists at all; a 2xx there refutes the plan).
- Every plan carries the causal evidence SPEC (precondition/action/effect/baseline/control/repeatability — the M6 vocabulary) and a 3-request budget. Two DISTINCT operator-authorized identities are required — fewer is an honest empty result (the differential IS the test; a single identity cannot differential-test object-level access).
- Identities come only from the engagement's operator-supplied `identity_profiles` (the M2 authorization root) — never invented.

### 1.5 — The advisory projection + wiring

- `sequence_hypotheses` / `bola_hypotheses` — plans become typed `Hypothesis` records: stable UUIDv5 ids (determinism test-pinned), status `unexplored`, provenance `stateful_api_sequence:` / `stateful_api_bola:`, and the M3 research-contract fields (preconditions / expected_behavior / negative_control) — advisory guidance for the hunt, NEVER findings; the deterministic validator owns confirmation.
- Frozen `api_testing/agent.py` (declared): flag-gated block after the existing probes — derives operations, generates sequences + BOLA plans, emits the hypotheses into the `hypotheses` channel (merge_hypotheses upserts by id; empty list is a reducer no-op, so flag-off is byte-identical). Fail-soft: any engine error leaves the node's existing behavior intact.
- Flag: `enable_stateful_api_testing` (fail-closed default False).

## 2. Acceptance vs the registry

| Registry acceptance (Part 4 §7) | Status |
|---|---|
| OpenAPI/observed-traffic contract ingestion | **delivered** (§1.1) |
| dependency/state model | **delivered** (§1.2 — inferred, provenance-labelled) |
| bounded sequence generation | **delivered** (§1.3 — double-bounded + request budgets + cleanup plans) |
| BOLA/IDOR with two authorized identities and negative controls | **delivered** (§1.4 — differential + randomized-id control + causal spec; <2 identities = honest refusal) |
| seeded multi-request states discovered + replayable with same preconditions/identity | **delivered** (§1.3 replay_spec determinism test-pinned; the validator/sandbox chain owns live execution) |
| causal evidence bundle for sequences | **spec delivered** (§1.4 — the bundle spec the deterministic validator fills; this planner never fabricates responses) |
| bounded budgets/cleanup | **delivered** (§1.3/§1.4) |

Deferred with owners: live sequence EXECUTION + evidence-bundle filling → the existing execution_sandbox → validator chain (M2-gated HITL); per-family stateful metrics → M11.

## 3. Gate evidence at closure

- **Tests:** `tests/test_m5_stateful_api.py` — 16 passed (ingestion/provenance, dependency inference, sequences/cleanup/budgets/determinism, BOLA differentials/controls/replay, hypotheses research-contract fields, UUID stability, flag default, node wiring flag-on with neutralized probes, flag-off structural absence).
- **Frozen-module gate:** 661 passed post-refreeze.
- **Test-count gate:** 8,436 ≥ floor 8,115 (`scripts/verify_test_count.py` — OK; re-verified at M5 close).
- **Coverage ratchet:** 4.27% ≥ 4.07% (unchanged scope; M5 tests sit outside the ratchet's scoped suites).
- **Authority manifest:** untouched (13 files).

— End of M5_PHASE_REPORT.md —

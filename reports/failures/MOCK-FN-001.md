# Failure Record — MOCK-FN-001

## Identity

| Field | Value |
|---|---|
| failure_id | `MOCK-FN-001` |
| target_id | `mock_target` |
| run_id | `mock-baseline-001` |
| case_id | `mock.public_observation.v1` |
| observed_result | `blocked` |
| expected_result | `blocked_by_precondition` for the default fixture; a ready fixture is required to exercise the success path |
| failure_layer | Preconditions / Workflow |
| safety_impact | None; the adapter correctly performed no network I/O and no state mutation |

## Reproduction

The official `GenericCaseRunner.execute_case` path returns:

```text
status = blocked
reason = mock_target_not_started_and_precondition_not_ready
proof_bundle_ref = null
observation_refs = []
```

Evidence is stored in `audit/mock_improvement_baseline_v1.json`.

## Root-cause hypothesis

The Mock Target fixture has no explicit ready-state variant. Its default adapter hard-codes the precondition as not ready, and its lifecycle methods stop at `prepare`/`baseline`. Consequently, the fixture can prove fail-closed blocked classification, but it cannot exercise the completed observation, negative-control, verifier, sealing, and replay path required for a full improvement-loop regression.

This is a **target-local fixture limitation**, not a Generic Core discovery or proof defect.

## Root-cause evidence

The adapter exposes `preconditions_ready()` as false for the owned case and returns `blocked` from `prepare()` and `baseline()` with the same not-started reason. The runner preserves this status and does not manufacture a finding or ProofBundle.

## Proposed fix

Add an explicit deterministic ready-state Mock fixture or factory that is opt-in for tests only. The ready variant must return redacted categorical observations, use an independent negative-control branch, and pass any confirmation through the existing verifier and ProofBundle replay path. The default fixture must remain blocked to preserve the current safety regression.

## Classification

`reproducible = true`

`target_specific = true` (fixture only)

`core_change_required = false`

`status = pending_independent_review`

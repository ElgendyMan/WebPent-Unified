# MOCK-FN-001 — Baseline Evaluation

| Field | Value |
|---|---|
| target_id | `mock_target` |
| run_id | `mock-baseline-001` |
| case_id | `mock.public_observation.v1` |
| fixture | default Mock Target |
| execution path | `GenericCaseRunner.execute_case` |
| authorization | explicit loopback fixture authorization |
| network I/O | none |
| state mutation | none |
| result | `blocked` |
| reason | `mock_target_not_started_and_precondition_not_ready` |
| proof_bundle | absent, as required for blocked state |

## Ground truth

The default Mock fixture is intentionally expected to be blocked. It is not a positive vulnerability case. The missing ready-state variant prevents this fixture from exercising the successful observation, independent negative-control, verifier, sealing, and replay path.

## Measured baseline

| Metric | Result |
|---|---|
| discovery quality | blocked classification reproduced |
| confirmation quality | not applicable; no candidate was reached |
| evidence completeness | safe blocked result; no ProofBundle expected |
| false positive | 0 for this blocked case |
| false negative | not scored for the absent ready-state case |

## Root cause

The limitation is target-local to the Mock fixture: its default precondition remains false and no opt-in ready-state factory exists. The Generic Core and central verifier are not identified as the cause.

## Gate decision

`baseline_complete = true`

`improvement_cycle_complete = false`

`next_gate = independent_review_of_MOCK-FN-001_proposal`

No implementation or after-run result is claimed by this report.

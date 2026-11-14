# Improvement Proposal — MOCK-FN-001

## Scope

This proposal addresses the deterministic Mock Target fixture's inability to exercise a successful, redacted lifecycle path. The approved implementation scope is strictly `mock-target-fixture-only`. It does not change the Generic Core, `GenericCaseRunner`, Juice Shop, WebGoat, crAPI, frozen P10 artifacts, or any external target.

## Problem

The default Mock Target intentionally reports `preconditions_ready = false`. That behavior is valuable for blocked-classification regression, but it left no opt-in ready fixture for testing the positive lifecycle path. The baseline was reproducible as `blocked` with no observation references and no ProofBundle.

## Approved implementation

The design approval was `approved_for_implementation` with scope `mock-target-fixture-only`. The implementation adds an explicit `MockTargetAdapter(ready=True)` variant and keeps `MockTargetAdapter()` as the default blocked fixture. The ready variant:

1. exposes only the loopback Mock origin and read-only navigation;
2. produces deterministic metadata-only target-backed observations;
3. uses separate baseline, candidate, and negative-control branches with distinct candidate/control request digests;
4. calls the existing central `verify_replay_evidence` verifier for any confirmation;
5. requires a sealed and replayable ProofBundle before the generic runner returns `confirmed`;
6. retains runtime-only verification state and does not serialize verification or raw evidence in `CaseResult`;
7. stores no raw response bodies, headers, cookies, credentials, or payload artifacts; and
8. returns blocked or unsupported outcomes when the default or an invalid fixture path is used.

A runtime defect found during execution was corrected by using the valid `VulnClass.INFO_DISCLOSURE` enum member instead of an invalid fixture-specific string. This was a target-local correction and did not alter the generic verifier contract.

## Architecture decision

The change belongs in `src/webpent/adapters/mock_target/adapter.py` and its tests, not in `shared/` and not in `GenericWebAdapter`. No target-specific route, selector, or real-target literal was added to Generic Core. The fixture is deterministic and has no network dependency.

## Acceptance evidence

| Criterion | Actual result |
|---|---|
| Default blocked behavior remains unchanged | Pass: `MOCK_TARGET_REGISTRATION` remains `blocked` with reason `mock_target_not_started_and_precondition_not_ready`, with no proof ref. |
| Ready fixture reaches observation path | Pass: `READY_MOCK_TARGET_REGISTRATION` reaches `confirmed` through `GenericCaseRunner`. |
| Candidate/control remain distinct | Pass: central verifier accepted distinct target-backed candidate and negative-control request digests. |
| Confirmation requires central verifier | Pass: runner promotion occurred only from the `VerificationResult` returned by `verify_replay_evidence`. |
| ProofBundle is sealed and replayable | Pass: `verify_seal() = true` and replay with the emitted `replay_context` and three redacted observations = true. |
| No sensitive serialization | Pass: `CaseResult` omits `verification`; serialized result contains no cookie, authorization, or raw response body fields. |
| No target leakage | Pass: final neutrality check passed; implementation is confined to Mock adapter, tests, rerun script, and MOCK-FN-001 reports. |
| Offline quality checks | Pass so far: targeted tests `17 passed`; full suite `1898 passed`; Ruff and compileall passed; direct-I/O inventory regenerated. |

## Review status

`proposal_status = closed_for_mock_target_fixture_only`

`implementation_allowed = true_under_limited_design_approval`

`final_independent_approval = approved_for_limited_mock_fixture_scope`

`improvement_cycle = closed_for_mock-target-fixture-only`

`p10_qualification = NOT_QUALIFIED`

`p9_qualification = NOT_QUALIFIED`

`vip_qualification = NOT_QUALIFIED`

The final independent post-fix review is recorded in `reports/reviews/MOCK-FN-001_final_independent_review.md`. The decision approves only the deterministic, non-networking Mock fixture implementation. It is not a Juice Shop run, does not establish P10 ground-truth metrics, and does not grant P10, P9, or VIP qualification.

## Rollback

Revert the dedicated implementation commit after review. The original default Mock adapter behavior and its blocked regression test remain valid independently.

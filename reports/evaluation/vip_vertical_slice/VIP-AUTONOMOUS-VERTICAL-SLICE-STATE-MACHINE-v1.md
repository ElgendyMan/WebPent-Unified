# VIP Autonomous Vertical Slice v1 — State Machine

## Ordered lifecycle

```text
CREATE_CAMPAIGN
  -> VALIDATE_SCOPE
  -> CHECK_TARGET_READINESS
  -> DISCOVER_CAPABILITIES
  -> SELECT_SAFE_CASES
  -> RUN_BASELINE
  -> EXECUTE_BOUNDED_ACTIONS
  -> COLLECT_REDACTED_OBSERVATIONS
  -> RUN_INDEPENDENT_NEGATIVE_CONTROL
  -> EVALUATE_CENTRAL_ORACLE
  -> CREATE_PROOFBUNDLE
  -> VERIFY_SEAL
  -> REPLAY
  -> EVALUATE_DETECTION_QUALITY
  -> DIAGNOSE_FAILURES
  -> CREATE_IMPROVEMENT_PROPOSAL
  -> CLASSIFY_CHANGE
  -> IMPLEMENT_SAFE_LOCAL_CHANGE
  -> RUN_REGRESSION
  -> RE-TEST
  -> COMPARE_BEFORE_AFTER
  -> GENERATE_REPORT
```

## Transition rules

| Current stage | Required condition | Next stage | Fail-closed result |
|---|---|---|---|
| `CREATE_CAMPAIGN` | Engagement ID exists and a `TargetSpec` is supplied | `VALIDATE_SCOPE` | Report blocked if missing |
| `VALIDATE_SCOPE` | Loopback origin, explicit scope, read-only methods, bounded budget, future expiry, authorization reference, and authority-origin match | `CHECK_TARGET_READINESS` | Stop before handler execution |
| `CHECK_TARGET_READINESS` | Provider returns `ready=true`, `external_contact=false`, `mutation=false` | `DISCOVER_CAPABILITIES` | Stop without case execution |
| `DISCOVER_CAPABILITIES` | Capability provider returns explicit available capability records | `SELECT_SAFE_CASES` | Unavailable capabilities reject individual cases |
| `SELECT_SAFE_CASES` | Case contract validates and capability is available; selection is within budget | `RUN_BASELINE` | Rejected cases remain non-scoring |
| `RUN_BASELINE` | Authorized bounded task returns a redacted baseline observation | `EXECUTE_BOUNDED_ACTIONS` | Executor/authority failure remains blocked or inconclusive |
| `EXECUTE_BOUNDED_ACTIONS` | Candidate task passes central authority | `COLLECT_REDACTED_OBSERVATIONS` | No bypass and no confirmation |
| `COLLECT_REDACTED_OBSERVATIONS` | Projection contains only allowlisted metadata | `RUN_INDEPENDENT_NEGATIVE_CONTROL` | Empty/unsafe projection is not evidence |
| `RUN_INDEPENDENT_NEGATIVE_CONTROL` | Independent control completes and does not match | `EVALUATE_CENTRAL_ORACLE` | No causal confirmation |
| `EVALUATE_CENTRAL_ORACLE` | Baseline, semantic predicate, candidate match, and negative control all pass | `CREATE_PROOFBUNDLE` | Decision is `inconclusive` |
| `CREATE_PROOFBUNDLE` | Common builder receives baseline/candidate/control/oracle evidence | `VERIFY_SEAL` | No manual adapter proof is accepted |
| `VERIFY_SEAL` | `verify_seal() == true` | `REPLAY` | Promotion remains false |
| `REPLAY` | Common replay returns true | `EVALUATE_DETECTION_QUALITY` | Promotion remains false |
| `EVALUATE_DETECTION_QUALITY` | Confirmed proof or a clearly classified non-confirmed outcome exists | `DIAGNOSE_FAILURES` or report flow | Never convert blocked/inconclusive into FN or clean |
| `DIAGNOSE_FAILURES` | Root cause is recorded without inventing evidence | `CREATE_IMPROVEMENT_PROPOSAL` | Preserve the original failure |
| `CREATE_IMPROVEMENT_PROPOSAL` | Proposal contains evidence, options, risk, affected scope, rollback, recommendation | `CLASSIFY_CHANGE` | Gated packet remains pending |
| `CLASSIFY_CHANGE` | Target-local vs generic/non-local classification is explicit | `IMPLEMENT_SAFE_LOCAL_CHANGE` | Generic/non-local path requires Owner Approval |
| `IMPLEMENT_SAFE_LOCAL_CHANGE` | Explicit safe local handler exists and returns a bounded result | `RUN_REGRESSION` | No handler or gated change is blocked |
| `RUN_REGRESSION` | Regression passes under local bounded conditions | `RE-TEST` | Retest is blocked |
| `RE-TEST` | Same target, contract, baseline/control semantics, and bounded method are reused | `COMPARE_BEFORE_AFTER` | No automatic promotion |
| `COMPARE_BEFORE_AFTER` | Before/after statuses, oracle, proof, and promotion flag are recorded | `GENERATE_REPORT` | Report records incomplete comparison |
| `GENERATE_REPORT` | Redacted report hash and governance invariants are present | Terminal | Report is the only output; no qualification |

## Terminal classifications

The orchestrator distinguishes `confirmed`, `probable`, `observation_only`, `blocked`, `unsupported`, and `inconclusive`. A status is not inferred from HTTP 200, route reachability, source presence, or a static metadata observation. The local Juice Shop passive campaign therefore remains non-scoring.

## Owner Approval boundary

The orchestrator may create a decision packet but cannot approve it. Owner Approval is required for policy changes, frozen Ground Truth changes, P10/VIP threshold changes, opening Official P10 runs, credentials, mutation, expanded authorization/scope, external targets, Bug Bounty, or qualification declarations. Silence is not approval. The `safe_local_change_handler` is intentionally limited to an explicitly injected target-local bounded change and does not alter official scoring state.

## Invariants at every terminal state

```text
external_contact = false
credentials_used = false
state_mutation = false
raw_bodies_persisted = false
raw_headers_persisted = false
official_isolated_p10_runs_authorized = false
qualification_claim = null
scoring_promotion = false
```

_End of state-machine record._

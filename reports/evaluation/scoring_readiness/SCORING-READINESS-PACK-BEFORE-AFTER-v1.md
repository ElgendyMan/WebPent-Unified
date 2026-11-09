# Scoring Readiness Pack Before/After v1

## Decision

This is an evidence-packaging and validation improvement. It does not create a new vulnerability finding, promote a ProofBundle, modify frozen ground truth, or open a run gate.

| Dimension | Before this phase | After this phase |
|---|---|---|
| Multi-target evidence | Lifecycle/transport artifact showed all three targets could complete the bounded orchestrator flow | Three explicit Target Packages now separate lifecycle portability from scoring readiness |
| Juice Shop scoring view | Existing baseline and three proof-backed cases existed, but no common machine-readable readiness schema | Three cases are mapped to causal predicates, safe preconditions, negative controls, verifier mappings, and sealed/replayable ProofBundles |
| WebGoat scoring view | Passive lifecycle observation only | Explicit blocked package with zero approved cases/classes and a required-evidence checklist |
| crAPI scoring view | Passive lifecycle observation only; mutable `latest` runtime reference | Explicit blocked package with zero approved cases/classes and immutable-digest blocker |
| Ground truth | Target evidence and mapping were distributed across prior artifacts | A multi-target matrix records admission, proof state, and non-counting rules per row |
| Oracle contracts | Juice Shop contracts existed in target-local code/artifacts | A contract register makes accepted contracts and missing WebGoat/crAPI contracts explicit |
| Quality measurement | Juice Shop baseline existed; official metrics remained withheld | A quality-baseline register links real artifacts and keeps official precision/recall/coverage null until gates are met |
| Validation | No dedicated package schema validator | Generic validator plus six regression tests validates all three packages without target I/O |
| Safety/governance | Existing loopback/GET-only and closed-gate controls | Same controls are repeated and machine-checked in every package; `official_isolated_p10_runs_authorized=false` remains invariant |

## Case-level execution decision

The three Juice Shop cases already had the required bounded baseline, causal contract, safe precondition, independent negative control, central verifier, sealed ProofBundle, seal verification, replay, and regression evidence from the prior local baseline cycle. No new root/health observation was executed because it cannot improve scoring quality.

No additional WebGoat or crAPI case met the admission bar during this packaging phase. Therefore no target-specific implementation, credentials, mutation, lesson completion, or synthetic oracle was introduced for either target. Their zero-case packages are a deliberate fail-closed result, not an FN or a clean result.

## Verification results

The package validator passed for all three packages. The readiness regression suite passed **19 tests**, including package schema validation, three-case Juice Shop contract checks, rejection of observation-only promotion, rejection of an opened Official P10 gate, and rejection of a non-semantic predicate. No target I/O is performed by these checks.

## Remaining before/after limitation

This phase improves scoring-readiness traceability and prevents false quality claims. It does not close the formal P10 gap: the admitted set is still 3 cases across 3 classes, while the threshold is 10 cases across 6 classes and three valid isolated official runs. No official metrics or qualification decision is produced.

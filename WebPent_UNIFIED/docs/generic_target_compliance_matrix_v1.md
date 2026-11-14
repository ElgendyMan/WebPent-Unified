# Generic Target-Neutral Plan — Independent Compliance Matrix v1

## Verification scope

This matrix checks the attached execution plan against the current repository state after the Generic Target migration cycle. Frozen P10 governance artifacts remain independent and unchanged. It distinguishes engineering implementation from live-target evidence and governance qualification. A `PASS` below means the repository contract or offline test is present and verified; it does not mean that P10 has passed.

## Mandatory success criteria

| Criterion | Status | Verification basis | Limitation |
|---|---|---|---|
| Target neutrality | PASS | `scripts/check_generic_target_neutrality.py`; manual forbidden-reference scan across shared/core packages | The guard covers the declared roots; future packages must remain registered with the guard. |
| Adapter isolation | PASS | Juice Shop implementation is under `src/webpent/adapters/juice_shop/` and `src/webpent/profiles/juice_shop/`; legacy benchmark paths are compatibility shims | The shims remain intentionally for backward compatibility and are not generic-core imports. |
| Generic execution portability | PASS (offline) | Versioned optional `CaseLifecycleAdapter` plus `GenericCaseRunner` are resolved through registration and exposed via `RuntimeContext.execute_registered_case`; GenericWebAdapter remains bounded same-origin read-only and fake-transport tests cover HTML/SPA and API-shaped targets plus registry swap | No live runner execution was performed because no authorized local listener was available. |
| Generic proof pipeline | PASS (offline) | Generic lifecycle runner converts only verifier-backed `VerificationResult` objects; proof-reference requirements, sealed/replayable bundles, and redaction are covered by tests | No live target bundle or independent live replay exists. |
| Generic metrics | PARTIAL | Existing metrics/evaluation contracts remain in the shared project and the full suite passes | This implementation did not produce approved live TP/FP/FN, precision, recall, or class-coverage results. |
| Safety and authorization | PASS (fail-closed) | `TargetManifest`, scope/origin validation, `require_live_for_origin`, bootstrap gate, blocked-precondition and unsupported-capability tests | Live execution was not attempted. |
| Extensibility | PASS (offline) | Generic Test Target, Mock Target, and two GenericWebAdapter registrations use shared contracts; non-generic campaign data is supplied only through an explicit `CampaignProfileSpec` | A third-party production adapter has not been onboarded in this verification. |
| Regression protection | PASS | Neutrality scanner, Ruff, compileall, direct-I/O, review-packet, G-02, secret, and full pytest gates pass | CI workflow integration itself was not changed; the guard is executable and reviewable. |

## Phase-by-phase compliance

| Plan phase | Status | Implemented evidence | Open point |
|---|---|---|---|
| 1. Leakage inventory | PASS | `docs/generic_target_architecture_inventory_v1.md` and neutrality scanner | The inventory is a point-in-time report and must be rerun for future packages. |
| 2. Generic contracts | PASS (offline) | Versioned capability/case/result contracts now include the optional `CaseLifecycleAdapter` stage contract, authorization/run context, workflow canonical IDs with legacy aliases, `TargetManifest`, `CampaignProfileSpec`, and proof-reference invariants | Live target behavior is not verified. |
| 3. Juice Shop plugin extraction | PASS | New adapter/profile namespaces with compatibility shims; direct adapter imports use the new profile namespace | The exact illustrative `fixtures.py` and nested plugin `tests/` layout was not required by the existing project conventions. |
| 4. Workflow identifiers | PASS | Canonical workflow IDs and approved-case compatibility test; frozen ground truth unchanged | Legacy names remain only in target-local compatibility mapping where required. |
| 5. Generic ProofBundle | PASS (offline) | Verifier builds from clean projections; sensitive body/DOM/screenshot fields are redacted; generic seal/replay tests pass | Live proof coverage remains unverified. |
| 6. Generic Test Target | PASS (offline) | Generic Test Target, Mock Target, and GenericWebAdapter fake transports cover formal lifecycle resolution, read-only operation, semantic discovery, negative control, seal/replay, verifier-backed promotion, blocked precondition, and unsupported capability | These are deterministic offline fixtures, not live target evidence. |
| 7. Isolation and compatibility | PASS (offline) | `tests/test_generic_target_swap.py`, `tests/test_generic_web_adapter.py`, and `tests/test_generic_case_runner.py` exercise explicit profile resolution, lifecycle resolver compatibility, GenericWebAdapter/Mock registry swap, and origin isolation | No live target swap was possible in the current environment. |
| 8. Juice Shop validation run | BLOCKED / NOT RUN | Preconditions were checked without HTTP or Docker execution; no loopback target listener was present | Requires an authorized local target, reviewed causal contracts, safe preconditions, and governance approval before live runs. |

## CI/CD checklist

| Required check | Status | Evidence |
|---|---|---|
| Core import isolation | PASS | Neutrality guard and target-swap tests |
| Forbidden-string scan | PASS | `check_generic_target_neutrality.py` scans literals/imports and target-specific conditionals in shared/core roots |
| Adapter contract tests | PASS | Registry/manifest and adapter suites in full pytest |
| Workflow consistency | PASS | Canonical workflow compatibility tests |
| Target swap | PASS (offline) | Generic/Mock lifecycle runner and Generic/Juice/Mock registration tests |
| Oracle schema | PASS (offline) | Semantic profile and proof tests |
| Negative control | PASS | Independent-control success and same-request fail-closed tests |
| ProofBundle determinism/seal/replay | PASS (offline) | Generic proof test and verifier suite |
| Redaction | PASS | Redaction regression plus full suite |
| Scope/authorization | PASS (fail-closed) | Manifest and live gate tests |
| Failure classification | PASS (offline) | Runner tests cover blocked preconditions, unsupported capabilities, needs-profile observation, and no promotion without verifier-backed proof |
| Clean environment | PARTIAL | Full test run passes from the current checkout; no separate fresh-clone CI job was executed in this verification |

## Adapter Definition of Done

The Generic Test Target and Mock Target satisfy the offline portions of the adapter DoD: shared registration, manifest/version, capabilities, scope, authorization metadata, origin isolation, blocked/unsupported behavior, redacted observations, proof sealing/replay, contract tests, and target-swap tests. The live-test item is **NOT VERIFIED** because no authorized listener was available. The Juice Shop adapter is likewise not eligible for a live qualification claim until its case-specific causal and negative-control contracts are independently accepted.

## Architecture Review answers

| Review question | Decision |
|---|---|
| Does the change need a Target name? | Target names remain in explicit adapters/profiles/manifests, not in shared runner logic. |
| Does it add a route or selector? | Target-specific values remain outside generic shared packages; the generic semantic rule no longer depends on `/ftp/`. |
| Does it add a Target-specific branch in core? | No such branch was added; registration and capability resolution are used instead. |
| Did a public interface change? | Shared contracts were extended with manifest/live-gate/workflow support; compatibility shims and tests preserve existing imports. |
| Are negative controls present? | Yes for generic proof fixtures; case-specific P10 controls remain incomplete for unscored cases. |
| Is evidence replayable? | Yes for offline generic proof fixtures; live replay evidence is not present. |
| Were frozen governance artifacts changed? | No. The three frozen P10 JSON files have no diff. |
| Was a different Target tested? | Yes, through Generic Test Target and Mock Target offline target-swap tests. |

## Final closure checklist

| Closure item | Status |
|---|---|
| No target leakage inside core | PASS |
| Target-specific logic isolated behind adapters/profiles | PASS |
| Canonical workflow identifiers consistent | PASS |
| Frozen governance artifacts unchanged | PASS |
| Second adapter/mock passes shared contracts | PASS (offline) |
| Generic ProofBundle and replay contract | PASS (offline) |
| CI guardrails prevent recurrence | PASS |
| Live execution authorized, bounded, and safe | NOT EXECUTED; preconditions unavailable |
| Every approved P10 case has accepted causal oracle and negative control | FAIL / OPEN; only the previously reviewed subset has accepted oracle contracts |
| P10 runs separated, sealed, replayable, and independently reviewed | FAIL / OPEN; zero completed live run bundles and metrics |

## Final determination

The **engineering portion of the Generic Target-Neutral plan is implemented and verified offline**. The plan is **not fully closed as a qualification plan** because its live-validation and governance gates were intentionally not bypassed. The repository is therefore ready for the next authorized validation stage, but `P10 = NOT_QUALIFIED` and `P9/VIP = NOT_QUALIFIED` remain the correct states.

> No HTTP 200, route existence, simulated receipt, or offline fixture is being promoted to a live vulnerability result or benchmark metric.

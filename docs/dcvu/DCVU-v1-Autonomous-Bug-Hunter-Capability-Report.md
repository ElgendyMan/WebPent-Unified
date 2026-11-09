# DCVU v1 — Autonomous Bug Hunter Capability Report

**Author:** Manus AI  
**Scope:** Local disposable in-process fixtures only  
**Status:** Engineering validation complete; official qualification not claimed  
**Report artifact:** `reports/evaluation/dcvu_v1_capability_report.json`

## Executive Summary

Detection Capability Validation Upgrade v1 (DCVU v1) adds a controlled benchmark that evaluates whether the existing generic research core can move from hypothesis generation to evidence-backed detection. The benchmark uses three disposable local target fixtures with synthetic identities, roles, resources, tenants, and workflows. It does not contact a network, use credentials, perform login, mutate state, create findings, or open any qualification gate.

The same campaign loop was used across all three fixtures. It discovered six generic authorization surfaces per target, evaluated baseline/candidate/independent negative-control observations, applied a causal decision, and required redacted proof sealing and replay before a positive verdict could be scored. The resulting fixture-backed benchmark produced 13 true positives and 5 true negatives, with zero false positives and zero false negatives across 18 accepted cases.

> These results demonstrate a working offline validation path and generic API portability. They are not field detection quality, do not establish real-world recall, and do not qualify P10, P9, VIP, or bug-bounty execution.

## Validation Design

| Component | DCVU v1 behavior |
|---|---|
| Target model | Three local disposable fixtures: `fixture-a`, `fixture-b`, and `fixture-c`. |
| Discovery | Generic surface inventory only; vulnerability truth is held in a separate registry. |
| Case classes | IDOR/BOLA, privilege escalation, function-level authorization, business logic abuse, tenant isolation, and workflow authorization. |
| Evidence contract | Baseline, unauthorized candidate, and independent authorized negative control. |
| Confirmation | Causal semantic comparison; transport-only observations cannot become positive verdicts. |
| Proof | Redacted observations with deterministic evidence digests and seal/replay verification. |
| Metrics | TP, FP, FN, TN, precision, recall, F1, class coverage, proof completeness. |
| Safety | No network, external scope, real credentials, login, state mutation, finding creation, or qualification effect. |

The campaign deliberately does not pass ground-truth vulnerability flags into discovery. The detector receives generic surface descriptions and produces proposed case IDs; the independent registry is used only for evaluation after the campaign decision. This prevents the benchmark from counting direct truth lookup as autonomous discovery.

## Results by Target

| Target | Attempted | Scored | TP | FP | FN | TN | Precision | Recall | F1 | Class coverage | Proof completeness |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `fixture-a` | 6 | 6 | 6 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| `fixture-b` | 6 | 6 | 4 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| `fixture-c` | 6 | 6 | 3 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| **Aggregate** | **18** | **18** | **13** | **0** | **0** | **5** | **1.00** | **1.00** | **1.00** | **1.00** | **1.00** |

The aggregate result is intentionally interpreted as a bounded fixture result. The clean cases in fixtures B and C demonstrate that the engine can preserve true negatives when a surface is not vulnerable according to the independent registry. They do not measure performance against naturally occurring applications or adversarially changing targets.

## Autonomous Campaign Trace

Each target produced six discovered surfaces and six evaluated case proposals. The campaign emitted no execution events. The same `AutonomousDcvCampaign` and `DetectionQualityValidationEngine` APIs were used for all targets, while target-specific semantics remained inside the disposable fixture profiles.

| Property | Result |
|---|---:|
| Targets exercised | 3 |
| Surfaces discovered | 18 |
| Cases evaluated | 18 |
| Execution events | 0 |
| Credentials used | false |
| State mutation | false |
| External scope | false |
| Qualification effect | false |

## Verification Gates

The DCVU-focused regression suite passed with **20 tests** covering contracts, fixture behavior, ground-truth separation, engine confirmation, campaign determinism, and metric calculation. Ruff and format checks passed on all DCVU source and test files. The JSON report passed structural validation.

The repository-wide release gates from the previous release remain separate from this fixture benchmark. Existing legacy blockers are not reclassified as DCVU detection failures, and no frozen evidence or governance policy was changed to improve the numbers.

## Limitations and Remaining Work

The benchmark is an in-process controlled fixture, not a live application. It therefore does not yet test HTTP parsing, session establishment, authorization state obtained through a real application workflow, framework-specific routing, concurrency, rate limits, or production-like response variability. It also uses deterministic surfaces and deterministic synthetic identities, which makes it suitable for regression and contract validation but insufficient for claiming robust real-world detection.

The next quality increment should introduce additional independently authored fixture implementations with the same contracts and deliberate detector stress cases, including controlled false-positive and false-negative challenges. Any live local application requiring login, token generation, state mutation, or expanded permissions must first be covered by a separate owner-approved decision packet. Official P10 and bug-bounty scope remain closed.

## Governance State

| Gate | State |
|---|---|
| `official_isolated_p10_runs_authorized` | `false` |
| `P10` | `NOT_QUALIFIED` |
| `P9` | `NOT_QUALIFIED` |
| `VIP` | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Official qualification claim | `false` |

## Reproducibility

Run the benchmark from the repository root with:

```text
PYTHONPATH=src:. python3 benchmarks/run_dcvu_v1.py
```

The runner writes `reports/evaluation/dcvu_v1_capability_report.json`. The source implementation is under `src/webpent/dcvu/`, with regression coverage under `tests/test_dcvu_*.py`.

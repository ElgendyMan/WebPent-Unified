# WebPent Smart Autonomous Bug Hunter — Execution Backlog

**Plan source:** `WebPentSmartAutonomousBugHunter.md` v2.0
**Project:** WebPent v60
**Execution posture:** conservative, fail-closed, evidence-first
**Date:** 2026-08-18

## Baseline before implementation

The reproducible baseline in the current working tree is **633 collected and 633 passed**. Earlier delivery notes referenced 654/655 tests, but the current tree does not reproduce those numbers; those claims are therefore not used as the current gate until the missing test files or exact source revision are identified. Historical local logs show earlier intermediate counts of 442, 453, 462, and 463 passed.

The latest live WAPTLab qualification remains **2 candidate rows and 0 confirmed findings**. The live evidence is retained under `docs/live_waptlab_output_final/` and `docs/live_waptlab_results_report.md`.

## Implementation backlog and gates

| Priority | Workstream | Concrete deliverable | Acceptance evidence |
|---|---|---|---|
| P0 | G0 baseline/reproducibility | Baseline manifest, capability report, clean artifact policy, raw quality logs | Reproducible pytest/ruff/compile checks and no credential artifacts |
| P0 | G1 action authority | Typed `ActionPolicy`, central executor contract, fail-closed preflight, audit events | Unit/security tests for scope, method, identity, budget, expiry, idempotency |
| P0 | G2 smart governance | Explicit smart profiles and capability manifest; startup marks unavailable capabilities | Graph/runtime trace proves governance decisions are enforced |
| P0 | G3 coverage-preserving discovery | Surface-family ledger and non-silent tool/parser failure states | Every discovered family is represented as tested, absent, or blocked |
| P0 | G4 identity/workflow | Per-engagement identity vault and replayable owner/foreign workflow | Dual-identity positive/denial differential fixture |
| P0 | G5 executable campaigns | Campaign task contract, bounded executor, next-best-action scoring, terminal states | Injected signal changes task order and every campaign is executed or blocked explicitly |
| P0 | G6 verified learning | Engagement-isolated memory updates and decision trace | Offline replay shows ordering improvement without false-positive increase |
| P0 | G7 proof/validators | Strict validator lifecycle, immutable ProofBundle, replay and negative controls | Mutation tests fail closed when evidence or controls are removed |
| P0 | G8 WAPTLab harness | Ground-truth registry, reset/cleanup, tool/browser/OOB capability reporting | Three independent live runs with explicit per-campaign coverage |
| P1 | G9 reliability | Persistent task/evidence projections, leases, idempotency, metrics | Redelivery/resume/concurrency tests and bounded resource usage |
| P1 | G10 release gates | Release A/B/C/D checklists and signed/exportable manifests | No VIP claim until 15/20 confirmed in three consecutive runs |

## Mandatory safety constraints

1. Do not modify WAPTLab source code.
2. Do not weaken scope, authentication, rate limits, SSRF controls, or evidence gates to increase recall.
3. The LLM may propose or rank; it may not authorize actions, expand scope, or confirm findings.
4. Missing tools, browser, identity, OOB, or validator capability must become typed coverage blockers, never `clean`.
5. Every active action requires policy authorization, a budget, idempotency, cleanup, and a terminal classification.
6. A candidate is not a confirmed vulnerability without a reproducible ProofBundle.

## Execution order

Implementation proceeds one gate at a time. Each code change must add or update regression coverage, run targeted checks, and preserve a rollback point. Live qualification is deferred until the runtime wiring and deterministic fixture gates pass.

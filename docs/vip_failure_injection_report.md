# VIP Offline Failure-Injection Report

**Review date:** 2026-08-20
**Workspace:** `/tmp/webpent_v72_git_recovered`
**Execution mode:** offline artifact/state contracts only
**WAPTLab/Juice Shop:** not started, contacted, or modified

## Purpose

This report exercises the local safety boundaries that can be proven without a target. It does not execute a scanner, open a socket, call AutoPentestX, create a Finding, or promote an offline fixture to `Tool-Confirmed`.

## Harness

The implementation is `benchmarks/failure_matrix.py`, with the bounded CLI `scripts/evaluate_failure_matrix.py`. The CLI writes `docs/vip_failure_matrix_20260820.json` and explicitly reports `live_target_executed: false`, `waptlab_executed: false`, and `autopentestx_executed: false`.

The matrix covers the following local transitions:

| Area | Injected case | Required disposition | Result |
|---|---|---|---|
| Offline validator | Complete evidence and control | `reviewable`, never confirmed | Pass |
| Offline validator | Missing oracle/evidence | `inconclusive` | Pass |
| Offline validator | Blocked cleanup | `blocked` | Pass |
| Offline validator | Incomplete negative control | `inconclusive` | Pass |
| Active research | Scope not explicitly allowed | `blocked` | Pass |
| Active research | Handler exception | `infrastructure_failure` | Pass |
| Active research | Safe injected observation | `negative` | Pass |

## Invariants

The generated artifact proves these local invariants:

1. No network was used.
2. No Finding was created or promoted.
3. Scope denial remains blocked even when a handler exists.
4. Handler exceptions become infrastructure failures rather than positives.
5. Missing evidence cannot become a confirmation.

Artifact SHA256:

`037a94d99015434b97a0247e5c410425853e7f8f003ef5feffbd7f3bb0691215`

## Verification

The dedicated regression suite passed with **10 tests** covering the failure matrix, active research contracts, and offline validator dispositions. Ruff and compileall passed for the new implementation.

## Residual boundary

This is not a live validator or acceptance run. It cannot establish WAPTLab/Juice Shop ground truth, live precision/recall, live reproducibility, browser/OOB behavior, worker/container recovery, or the required number of confirmed vulnerabilities. Those claims remain explicitly unqualified until an authorized target run is performed.

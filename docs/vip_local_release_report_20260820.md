# VIP Local Release and Residual Report

**Date:** 2026-08-20
**Scope:** Local engineering and offline evidence only
**Target policy:** WAPTLab and Juice Shop were not started, contacted, modified, or benchmarked in this pass.

## Release gates

| Gate | Result | Evidence |
|---|---:|---|
| Full pytest | **1007 passed, 0 failed** | Local `.venv/bin/pytest -q` |
| Ruff | **0 errors** | `.venv/bin/ruff check .` |
| Compileall | **PASS** | `python -m compileall -q src tests benchmarks scripts` |
| Unified verifier | **145 PASS, 0 FAIL** | `verify_all.py` |
| Git diff check | **PASS** | `git diff --check` |
| Offline failure matrix | **PASS** | `docs/vip_failure_matrix_20260820.json` |
| Dependency audit | **No reported vulnerabilities** | `docs/vip_pip_audit_20260820.json` |

The dependency audit reported the local project package as not published on PyPI, which is expected for this repository and is not treated as a vulnerability finding. The audit is an environment/dependency check; it does not qualify deployment infrastructure.

## Engineering completed in this pass

The source-to-runtime inventory and plan checklist were refreshed. The local execution-plane contracts now have dedicated regression coverage for scope, active approval, destructive denial, infrastructure failure, and idempotency. ProofBundle coverage now explicitly tests sealing, replay metadata, negative controls, redaction, and immutability. The offline failure matrix and its CLI exercise validator and research-loop dispositions without network access or Finding creation.

The benchmark and failure artifacts are explicitly non-live. They are suitable for local contract verification and later comparison against authorized artifacts, but they do not establish target ground truth, precision, recall, reproducibility, or confirmed vulnerabilities.

The release-artifact audit is now covered by `scripts/verify_release_artifacts.py` and `tests/test_release_artifact_audit.py`. It verifies manifest hashes, rejects forbidden runtime/database/secret-like archive members, and fails closed when an operator-required detached signature is absent. Signature presence is reported as supplied for external verification; the project does not pretend to implement cryptographic verification itself.

## Residual items that cannot be honestly marked complete without a target run

The following remain unqualified because the requested no-WAPTLab constraint prevents collecting the required evidence: WAPTLab/Juice Shop ground truth, live baseline and ablation runs, live proof slices, browser/OOB/API/parser qualification, 15–20 Tool-Confirmed findings, live precision/recall/reproducibility, and Docker/Redis/PostgreSQL/Celery/Chromium production qualification.

The project must not claim VIP qualification or confirmed vulnerabilities from unit tests, offline fixtures, module presence, or historical artifacts alone.

## Integrity

The release artifact and commit hash are recorded after the final commit. The generated dependency audit artifact has SHA256:

`b7252c325b7d02a9e68271ca90eb9928988fa2e813c95a205ecc52d4b7154b74`

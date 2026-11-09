# Full Project VIP Audit Baseline

**Date:** 2026-08-22

## Baseline

The repository is clean at commit `1df340c809dacf7afd123b84c38328056fa66f7e`, and `HEAD` matches `origin/master`. Pytest collection reports 1304 tests. The existing release artifacts are present: direct-I/O inventory, capability report, VIP quality gate, and pasted3 gap matrix.

The full working tree is approximately 5.9G because it contains the virtual environment and runtime state. Excluding `.venv`, `.git`, and Python caches, it is approximately 450M. The dominant non-source footprint is runtime/database state: `memory/global/sessions.db` is approximately 449M, with additional local databases and generated logs. These are not part of the clean ZIP because the archive excludes `.git`, `.venv`, caches, bytecode, and databases. This is a release-hygiene finding, not evidence that source code was deleted.

The tracked suspicious-name scan found only expected examples, audit logs, migration names, secret-vault implementation, and secret-scan tests; no high-confidence secret was identified by the existing tracked-secret gate. Broad exception handlers exist in multiple adapters by design for safe degradation, but each must be checked for fail-closed behavior and evidence preservation rather than blanket approval.

## Initial risks to verify

| Area | Initial observation | Verification requirement |
|---|---|---|
| Release hygiene | Large ignored runtime state and logs exist locally | Ensure clean archive excludes them and production startup does not depend on them |
| VIP evidence | Existing gate has `hard_checks_passed=true` but overall `passed=false` because live qualification is blocked | Keep this distinction; never convert local contract tests into live confirmation |
| Identity state | Identity, cookies, vault references, proof/evidence fields appear across state and agents | Verify checkpoint/report redaction and no raw secret crossing state boundaries |
| Graph autonomy | Many conditional nodes and fallback paths exist | Verify every critical producer has a consumer and failure path is fail-closed |
| G-02 | Existing inventory has 63 records | Regenerate after every source change and verify runtime/precommit contracts |
| Live qualification | WAPTLab and Juice Shop are explicitly excluded from this review | Keep findings local/offline-qualified only |

## Review protocol

The next review phase will inspect graph topology, runtime DI, state/checkpoint serialization, evidence verifiers, LLM/fallback behavior, scope/SSRF guards, reporting, worker resume/cleanup, and CLI/API contracts. Any implementation change must be additive, backward-compatible, fail-closed, and accompanied by focused and integration tests before full regression.

# UMDR42 Closure — Baseline Audit (Phase A0)
Generated 2026-11-20T07:42:12.389530+00:00 by `scripts/umdr42_baseline_audit.py` (programmatic — every fact below is measured from the repository or fetched from origin).

## Baseline identity
- **Published main:** `5a7e511c0efc5cca8bfc013e8d8d9d10142e16da`
- **Parent:** `86e5861ae0f24d40f8f9c1ef9c6ae84fafd026cc`
- **CI run:** `44646708112 (ruff + build-info failed; 8 gates skipped; current-run evidence missing)`
- **Audit HEAD:** `5a7e511c0efc5cca8bfc013e8d8d9d10142e16da`
- **Audit branch:** `security/umdr42-closure`
- **Working tree:** `dirty`

## Commit anatomy (86e5861 → 5a7e511c)
- **Added:** `40`
- **Modified:** `4967`
- **Byte-identical moves (R100):** `39`
- **Deleted (unpaired):** `8`
- **File-mode changes:** `4880`

Deleted paths:
- `WebPent_UNIFIED/REGRESSION.json`
- `WebPent_UNIFIED/UMDR36_2_37_DELIVERABLES/WebPent_Unified_mission-umdr36.2-umdr37.bundle`
- `WebPent_UNIFIED/deliverables/umdr36_1/WebPent_Unified_recovery-umdr36-closure.bundle`
- `WebPent_UNIFIED/docs/baseline/coverage.json`
- `WebPent_UNIFIED/docs/coverage_measured_baseline_0260.json`
- `WebPent_UNIFIED/docs/history/UMDR37_COVERAGE_LAST_RUN.json`
- `WebPent_Unified_umdr38.bundle`
- `deliverables/umdr38/test_evidence/coverage_last_run.json`

## BUILD_INFO provenance (measured)
- **current_release.source_revision:** `a0807294694ce969c3664cbd3b6e7be4d3ed3b04 (resolves locally: False)`
- **manifest_digest declared:** `760dce1150244352416fb35f2868186af13d68d9828d41f68015bf3d875ba8ce`
- **manifest_digest actual (sha256 of frozen_modules.sha256):** `ad62549af0350bd0ba027ae748321f933677422c8500e6047d179d769aedec1b`
- **manifest match:** `False`

## Test accounting (as published)
```json
{
  "passed": 9354,
  "failed": 0,
  "skipped": 9,
  "xfailed": 3,
  "xpassed": 0,
  "deselected": 0,
  "errors": 0,
  "collected": 9365,
  "executed": 9366,
  "sum_of_outcomes": 9366,
  "collected_minus_outcomes": -1,
  "declared_accounting_consistent": true
}
```
9354 passed + 9 failed=0 + 9 skipped + 3 xfailed = 9366 executed, but `collected` says 9365 — one collected test is unaccounted; the closure must reconcile this exactly.

## Ruff (measured now)
- **Findings:** `5689`
- **Frozen baseline:** `None`

## Scope store defects (code-verified)
- **clear_tombstones_latest_active_only:** `True`
- **current_filters_tombstones_before_latest:** `False`
- **worker_attaches_store:** `True`
- **compose_has_scope_env:** `True`

## Defect register
- **P1-SCOPE-REVIVE** (P1): clear() tombstones latest ACTIVE row only; current()/current_version()/redacted() filter tombstones BEFORE choosing latest → revoked v2 resurrects v1
- **P1-SCOPE-API-500** (P1): API scope endpoints do not map ScopeStoreUnavailable to 503 — an unavailable authority surfaces as an opaque 500
- **P1-SCOPE-WORKER-INIT** (P1): Celery worker never attaches the durable store — opt-in env vars are not consumed by worker.py
- **P1-SCOPE-COMPOSE-ENV** (P1): docker-compose.yml api+worker missing WEBPENT_SCOPE_STORE_* env and store path
- **P2-RUFF-28** (P2): 28 ruff regressions vs frozen 8147 baseline
- **P2-BUILDINFO-6** (P2): 6 provenance inconsistencies in BUILD_INFO.json
- **P2-D2-NEEDSHUMAN** (P2): D2 decision table NEEDS-HUMAN vs final verdicts DELETABLE conflict for selected symbols
- **P2-AUDIT-137-VS-108** (P2): audit findings count disagreement 137 vs 108 across copies
- **P2-G02-RENEWALS** (P2 (governance)): 49 expired vs 54 renewed vs 40+3 inventory approvals unreconciled

## External decisions required
- G-02 approval renewal requires the actual repository owner; expiry-date edits without authentic authorization are prohibited (fail-closed retained)
- docker-compose runtime verification requires a Docker daemon (unavailable here)

## Classification
- Facts above: `VERIFIED_LOCAL` (measured) or `VERIFIED_REMOTE` (fetched from origin).
- Docker verification: `BLOCKED_EXTERNAL_DEPENDENCY`.
- G-02 renewals: `BLOCKED_EXTERNAL_AUTHORIZATION` until the owner acts.

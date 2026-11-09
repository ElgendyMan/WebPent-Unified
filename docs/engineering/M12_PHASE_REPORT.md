# M12_PHASE_REPORT.md — M12 (Production Engineering & Operations)

**Phase:** M12 of the CANONICAL_PHASE_REGISTRY (Part 4 §14 — P0/P1).
**Date closed:** 2026-11-06 (UTC).
**Window:** DRIFT_REGISTER UM-DR-23.
**Baseline entering:** post-M11 tree (UM-DR-22); frozen authority manifest untouched; frozen-module gate 661 green.
**Refreeze:** NONE REQUIRED — scripts, workflows and docs only; zero frozen-source changes.

---

## 1. What was delivered

### 1.1 — Verified backup/restore (`scripts/verify_backup_restore.py`)

The registry's "documented, safe deploy + restore" made RESTORE verifiable: the harness backs up every per-engagement workspace store (sessions/databases/ledgers/reports/rag) into a timestamped backup with a sha256 manifest, restores it into a fresh tree, and verifies byte-identity per file + `PRAGMA integrity_check` per sqlite store. Corrupted and missing stores FAIL loudly (test-pinned both ways).

### 1.2 — The weekly ق5 canary enrollment (`.github/workflows/weekly-benchmarks.yml`)

The M11 `run_weekly_benchmarks()` runner enrolled on cron (Mondays 03:00 UTC) + manual dispatch, deterministic/offline posture (mirrors nightly.yml), the dated report artifact uploaded, and a HARD gate: any deception false-positive fails the canary. This closes the registry's "weekly ... runs + canary scheduler + ق5 self-benchmark wired" — the scheduler enrollment was the missing half after M11 built the runner.

### 1.3 — The release discipline (`docs/engineering/RELEASE_PROCESS.md`)

* The **14-gate chain** documented with its CI enforcement (state-contract law, orchestrator authority, isolation denylist, vault import authority, test-count floor, build-info honesty, frozen-module manifest, ruff ratchet, dependency CVE gate, secret scan, bandit, coverage ratchet, full regression with evidence, authority manifest).
* **Artifacts per release**: SBOM (CycloneDX, CI-generated — mandatory), BUILD_INFO, the qualification rollup, the deception benchmark report, release notes.
* **The release-notes contract**: what changed (window ids + flags with fail-closed defaults), KNOWN LIMITATIONS (the deferred items with owning phases), the MEASURED qualification labels (never aspirations), migration notes, rollback.
* **The rollback runbook**: stop intake → verified backup (§1.1) → restore → pin the previous release (content-addressed manifests) → re-run the 14 gates.
* **Reproducible builds**: `uv sync --locked`, the frozen-modules + authority manifests as content-addressed pins, reproducible test counts.

### 1.4 — What already existed (verified, not rebuilt)

The 2026-10-29 residual-closure window had already promoted ruff/pip-audit to blocking CI gates and wired the CycloneDX SBOM step + `make coverage-ratchet` into ci.yml; Alembic migrations run inside `init_db()` with fail-closed stamping; deployment hardening (non-root gosu, loopback defaults, fail-closed keys, SSRF pinning) shipped with M2. This window VERIFIED those seams (the CI-chain contract test pins every step by name) and added the missing pieces (§1.1–§1.3).

## 2. Acceptance vs the registry

| Registry acceptance (Part 4 §14) | Status |
|---|---|
| documented, safe deploy + restore | **delivered** (§1.1, §1.3 — verified restore + the runbook) |
| all CI gates green | **verified** (§1.4 — the chain exists and is enforced; the in-sandbox reproductions: frozen 661, test-count 8,505 ≥ 8,115, ratchet 4.27% ≥ 4.07%) |
| SBOM per release | **delivered** (CI step, mandatory artifact per §1.3) |
| coverage ratchet wired into CI | **verified** (ci.yml "make coverage-ratchet"; the M1-C floor is up-only) |
| dependency audit/lockfile/vuln-scan | **verified** (CVE gate + allowlist, `uv sync --locked`) |
| versioned migrations + fresh-install/upgrade | **existing** (Alembic in init_db, fail-closed stamping) — full upgrade-path lab tests deferred to the operator-deployment window |
| weekly Juice Suite runs + canary scheduler | **delivered** (§1.2 — the ق5 enrollment; live Juice-Shop targets remain operator infrastructure per M11's caveat) |
| release notes / known limitations / rollback / reproducible builds | **delivered** (§1.3) |

Deferred with owners: live deployment rehearsal (docker-compose prod-up/backup-restore on a real host) → operator infrastructure; the 12 known CVEs in pinned langgraph-adjacent versions → the 0.34.2 major-bump window already recorded in ci.yml's header.

## 3. Gate evidence at closure

- **Tests:** `tests/test_m12_release_engineering.py` — 7 passed (clean/corrupt/missing backup-restore verification; the weekly workflow contract; the release-doc contracts; the CI gate chain by name; the nightly canary still enrolled).
- **Frozen-module gate:** 661 passed.
- **Test-count gate:** 8,505 ≥ floor 8,115.
- **Authority manifest:** untouched (13 files).

— End of M12_PHASE_REPORT.md —

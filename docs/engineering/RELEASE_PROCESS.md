# RELEASE_PROCESS.md — M12 (Part 4 §14): release discipline

**Scope:** the per-release gates, the artifacts every release carries, the
known-limitations contract, and the rollback runbook. The gates
themselves are CI-enforced (`.github/workflows/ci.yml`); this document
is the operator-facing discipline that ties them together.

---

## 1. The release gate chain (all must be green)

| # | Gate | Enforcement |
|---|------|-------------|
| 1 | Static state-contract law | `scripts/check_state_contract.py` (CI) |
| 2 | Orchestrator construction authority (R1) | `scripts/check_orchestrator_construction_authority.py` (CI) |
| 3 | Isolation denylist (S-1) | `scripts/check_isolation_denylist.py` (CI) |
| 4 | Vault import authority (M4) | `scripts/check_vault_import_authority.py` (CI) |
| 5 | Test-count floor | `scripts/verify_test_count.py --floor-file scripts/test_count_floor.json` (CI + `make test-count`) |
| 6 | Build-info honesty (P2-205) | `scripts/check_build_info_honesty.py` (CI) |
| 7 | Frozen-module manifest | `pytest tests/test_frozen_module_gate.py` — 661 green; any frozen change requires a declared refreeze script + drift-register entry (DR-009 protocol) |
| 8 | Ruff ratchet | `scripts/check_ruff_ratchet.py` (CI, blocking since the 2026-10-29 residual closure) |
| 9 | Dependency CVE gate | `scripts/check_deps_gate.py` against `pip_audit_allowlist.txt` (CI, blocking) |
| 10 | Secret scan | `scripts/check_secrets.py` (CI) |
| 11 | Bandit SAST (high) | `bandit -lll` (CI) |
| 12 | Coverage ratchet (M1-C) | `make coverage-ratchet` — floor in `scripts/coverage_floor.json`, up-only (`--allow-lower` is the documented escape hatch) |
| 13 | Full regression with evidence | `scripts/run_tests_with_evidence.py` (CI) |
| 14 | Authority manifest | `docs/integration/WEBPENT_AUTHORITY_MANIFEST.json` — 13 files, byte-verified by the frozen gate |

## 2. Artifacts every release carries

1. **SBOM (CycloneDX)** — generated and uploaded by CI ("Generate SBOM" step). No release ships without its SBOM.
2. **BUILD_INFO.json** — suite counts, checked for honesty by gate 6.
3. **The qualification rollup** — the latest `reports/qualification/weekly_*.json` (the M11 runner: per-family metrics with sample sizes, the label ladder, the honest deterministic-engine label).
4. **The deception benchmark report** — `reports/deception/benchmark_v1.json` (zero false positives required).
5. **Release notes** — see §3.

## 3. Release notes contract (per release)

Every release's notes MUST carry:

* **What changed** — the phase windows closed (DRIFT_REGISTER entry ids) and the flags added (every new capability flag with its fail-closed default).
* **Known limitations** — the honest list: the deferred items with their owning phases (e.g. live-corpus benchmarking requires operator-deployed targets; the LLM hypothesis path stays behind the Charter §4.1 gate; M4/M8 remain closed by their optionality gates).
* **The declared qualification levels** — per the M11 label ladder, sourced from the qualification rollup. A component is described by its MEASURED label, never its aspiration.
* **Migration notes** — Alembic heads moved, fresh-install vs upgrade paths.
* **Rollback** — see §4.

## 4. Rollback runbook

1. **Stop intake** — stop the API/worker processes (no new engagements start).
2. **Preserve evidence** — `python scripts/verify_backup_restore.py --workspace <workspace>` produces a verified backup (sha256 manifest + sqlite integrity checks) of every engagement store BEFORE anything is touched.
3. **Restore** — the same script's `restore()` path (or the backup directory's manifest) copies stores back; verify with the integrity pass.
4. **Pin the previous release** — the frozen-module manifest and the authority manifest are content-addressed: the previous release's manifests restore byte-identically and the frozen gate verifies them.
5. **Re-run the gate chain** on the rolled-back tree — all 14 gates green before intake reopens.

## 5. Reproducible builds

* Dependencies: `uv sync --locked` (the lockfile is the version truth; the CVE gate audits it).
* Module integrity: the frozen_modules.sha256 manifest (659 hashes) and the authority manifest (13 files) — the frozen gate verifies both on every run; a rebuilt tree that drifted fails gate 7.
* The frozen-module manifest pins 659 module hashes; the authority manifest pins the 13-file authority surface — a rebuilt tree is verified against both.
* Tests: `verify_test_count.py` collects against the floor file — the count is reproducible, not hand-typed.

## 6. Deployment posture (carried from M2/M12 hardening)

Non-root execution (gosu drop, M2), loopback-only defaults for every
listener (OAST responder, OOB collector), fail-closed secret keys
(celery_payload_key / jwt_secret_key / audit_secret_key refuse
well-known defaults), SSRF-pinned transports, and the per-engagement
workspace isolation (fail-closed switching). New flags ship default-
off; the flag list in the release notes is the operator's enablement
surface.

— End of RELEASE_PROCESS.md —

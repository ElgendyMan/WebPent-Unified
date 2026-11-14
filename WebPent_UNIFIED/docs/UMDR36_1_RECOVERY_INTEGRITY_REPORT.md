# UM-DR-36.1 Recovery Integrity Report

Generated: 2026-11-14T11:14:05.953756+00:00 | Branch: `recovery/umdr36-closure` | Baseline: `1968f63c2076b1b804537f91cd5cfa01c3eee0bb` | HEAD: `0d9511f325a215a6fc7dd6228b966f710dd4fc7d`

## 1. Repository inventory (Stage A, from the actual checked-out tree)

- Tracked files on baseline main: **4,802**; directories with tracked content:  top-level entries.
- The recovery ZIP (`WebPent_UNIFIED_v0.40.1_UMDR35_36.zip`) contains **4,809** files.
- **Counting difference explained (not silently resolved):** 4,809 = 4,802 tracked files + **7 untracked build artifacts** (`src/webpent.egg-info/*` — 6 files, and `memory/global/chroma_db/chroma.sqlite3`). The ZIP is a working-directory snapshot; the Git tree is the clean source of truth. Zero files exist in Git but not in the ZIP.
- Content comparison: **all 4,802 tracked files are byte-identical (SHA-256) between the ZIP and the `1968f63` tree** — the ZIP adds nothing and hides nothing.

## 2. Historical recovery comparison (ledger)

| Source | Status | Classification |
| --- | --- | --- |
| `main` @ `1968f63` (v0.40.1 bulk update) | hash-verified vs ZIP | **Recovered and hash-verified** (new explicit recovery baseline) |
| `features/v0.39.0-umdr33` @ `bbe7c4e` | resolvable | Historical feature branch; superseded by main's bulk update; divergence base `989c49b` |
| `security/umdr34-origin-scope-hardening` @ `1556900` | resolvable | **Valid missing fixes ported selectively** (scope hardening `699c177`, runner pin `1556900`) via cherry-pick; lockfile fix `2d107b4` superseded by the correct 0.40.1 one-line sync |
| PR #1 | NOT inspectable | GitHub API rate-limited unauthenticated in this environment (403); its content is the security branch above — documented, not merged blindly |
| `df2b50d…` (old readiness report head) | **not resolvable** | **Unverifiable historical claim** — recorded as such; the new baseline is `1968f63` |
| `BASELINE/POST.sha256.txt` pins (`90eab09…`) | well-formed, internally consistent | **Historical window records** (2026-10-22 tree state); not current-integrity contracts — current integrity = `frozen_modules.sha256` (verified by `scripts/verify_recovery_umdr36.py`) |
| `scripts/run_suite_chunks_umdr(26, 28, 31)*.sh` etc. | present | Historical batch runners with retired-environment absolute paths — retained as historical artifacts, outside the UM-DR-35/36 recovery toolchain |
| Pre-failure local workspace (`/home/z/my-project/work/webpent/...`) | **unavailable** | The sandbox rollback destroyed it; no trusted hash reference for the pre-failure state exists, so **no byte-for-byte restoration claim is made** — the public `1968f63` tree is the explicit recovery baseline |

## 3. Recovery tool portability (§1.3)

- `scripts/recover_umdr35_36.py`: REPO now derived from the script location (validated layout), pipeline interpreter = `sys.executable`; embedded window-script copies re-synced with the repaired standalone files.
- `scripts/build_umdr35_36_readiness_summary.py`: `--summary-json` CLI argument, repo-relative default, clear failure on missing required artifacts, branch derived from git.
- Remaining environment-specific paths exist only in historical (pre-UMDR-35) batch scripts, documented above.

## 4. Reproducible recovery verification (§1.4)

`scripts/verify_recovery_umdr36.py` (new) verifies required files, SHA-256 manifests, frozen-module integrity, package/version consistency and campaign-artifact schema, and separates VERIFIED state from UNVERIFIED historical claims.
Current verdict: **NOT_VERIFIED** — checks: {"required_files": "PASS", "frozen_manifest": "FAIL", "baseline_pins": "FAIL", "version_consistency": "FAIL", "campaign_artifact": "FAIL"}.
(Version-consistency and campaign-artifact checks are honestly FAIL until the BUILD_INFO re-baseline commit and the final campaign artifact are landed — see the readiness summary.)

## 5. Dependency and environment integrity (§2)

- Root cause reproduced and fixed: `uv.lock` carried the editable `webpent` entry at `0.37.1` while `pyproject.toml` declared `0.40.1`; the bulk v0.40.1 update never regenerated the lockfile. **Least disruptive resolution: a single-line version bump** (`0.37.1 → 0.40.1`); no dependency upgrades, no constraint changes.
- Verified: `uv lock --check` PASS · `uv sync --locked --extra dev` PASS · `uv run python -m pip check` "No broken requirements found" · `import webpent` = 0.40.1 · `webpent --help` works.
- CI runner pinned to `ubuntu-24.04` (Playwright/Chromium reproducibility, ported from the security branch).

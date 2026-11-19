# UM-DR-36.2 Build Provenance Report

Generated 2026-11-16T05:24:44.894368+00:00.

- SSOT: pyproject.toml + CHANGELOG at 0.40.1; `__init__`, `uv.lock`,
  BUILD_INFO (top-level and contract) aligned — the stale 0.40.0 /
  0.38.0 entries that failed `version_consistency` since 36.1 are
  closed.
- BUILD_INFO `suite_count` refreshed from the current v3 evidence run.
- Historical claims (UM-DR-32/33-era suite counts, unresolvable local
  heads) stay recorded as UNVERIFIED — never converted to PASS.
- Frozen manifest: the UM-DR-37 change set (http_discovery,
  access_control, unified_hunt) is declared in the DR-009 ritual with
  per-file rationale; the baseline-diff gate documents the thaw set.
- Recovery verifier: **VERIFIED** — required_files, frozen_manifest,
  baseline_pins, version_consistency, campaign_artifact all PASS.

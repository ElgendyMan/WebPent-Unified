# UM-DR-38 — Version Integrity Report

Generated: 2026-11-16T08:09:15.575264+00:00.

* Canonical package version (pyproject SSOT): **0.40.1**
* BUILD_INFO package_version: **0.40.1**
* BUILD_INFO version_identity_contract.current_release.package_version: **0.40.1**
* CHANGELOG current entry: ## [0.40.1] — UM-DR-36.2/37 (2026-11-15)
* suite_count: **9250** = provenance.test_accounting.executed, derived from the CURRENT full-suite evidence by the re-baseline script (never a hand-typed count)

## Historical/current separation (the §10 reconciliation)

* The stale `suite_evidence_provenance` (9178/9160/7 @ 51dfb44) and the stale top-level `current_release` block (0.39.0) are GONE as current claims; the current release block is the UM-DR-38 closure at 0.40.1 with its evidence provenance bound to the release commit.
* `version_identity_contract.release_history` records every release as STRICTLY older historical entries with resolvable source revisions or honest null markers.
* Historical narrative blocks (umdr32/umdr34/umdr35_36) are preserved as history — the honesty gate distinguishes verified facts from unverifiable historical claims instead of deleting them.

## Honesty gate at the release commit (re-executed)

```
build_info_honesty: PASS — version identity, provenance revisions, manifest digest, test accounting and stability discipline all verified; historical narrative preserved
```
exit code: **0**

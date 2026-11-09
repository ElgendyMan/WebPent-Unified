# archive/ — P2-404 hygiene archival (2026-11-01)

Historical self-reports, legacy snapshot families, and delivery-adjacent
artifacts were moved out of the tree root into this directory. Nothing here is
imported by the product, exercised by the test suite, or consulted by any CI
gate (verified by the reference-safety survey
`audit/logs/phase2/p404_reference_safety.json` before any move). The archived
bytes are preserved unchanged — this is a relocation, not a deletion.

## Old → new mapping

| Old location (root) | New location |
|---|---|
| 65 root self-report files (*.md / *.txt / *.json) — EVIDENCE_REPORT_*, FABRIC_*, VALIDATOR_*, TEAM1_*/TEAM2_*, UNFREEZE_*, *_sha256 manifests, REGRESSION.json, CHANGED_FILES.txt, DRIFT_REGISTER.md, WORKLOG.md, REMEDIATION_REPORT.md, ACCEPTANCE_RESULT.txt, invoice_route_static.json, … | `archive/self_reports_20261101/` |
| `goed_v1_8/` `goed_v1_8_1/` `goed_v1_8_2/` `goed_v1_8_3/` `goed_v1_8_4/` | `archive/goed_v1_8*` (same names, under archive/) |
| `docs/generalization_evidence/` | `archive/generalization_evidence/` |
| `release/` | `archive/release/` |
| `deliverables/` | `archive/deliverables/` |
| `demo_refactor.py`, `build_sprint_a_zip.py` | `archive/demos/` |

## Kept at the root (R11 whitelist + functional tooling)

`README.md`, `SECURITY.md`, `DEPLOYMENT_CHECKLIST.md`, `QUICKSTART_CAMPAIGNS.md`,
`BUILD_INFO.json`, `credentials_template.json` — plus `verify_all.py`
(wired into the Makefile `verify` target) and `viewer.py` (lesson-store CLI,
referenced by the reflection agent's operator docs).

## Resolving historical references

Historical documents under `docs/` (release manifests, worklogs, integration
reports) and comments inside frozen source/test files cite the old root paths.
Those citations describe the past and were intentionally left untouched; a
cited filename resolves by looking in `archive/self_reports_20261101/` (or the
matching subdirectory above). Live build tooling that enumerated the moved
paths (`scripts/build_delivery_v*.py`, `scripts/team2_phase1_env.py`,
`scripts/build_release_manifest.py`) was updated to the archive paths in the
same commit. The historical freeze-window authorization lists inside
`scripts/gate_frozen_delta*.py` (WORKLOG.md, deliverables/) are left verbatim —
they authorize past-window deltas and are not runtime file reads.

## .gitignore fix shipped with this archival

The recurring "27 files lost on workspace transfer" incidents (root cause
identified 2026-11-01) came from `.gitignore` generated-artifact patterns
(`*.sha256`, `*.sha256.txt`, `REGRESSION.json`, `CHANGED_FILES.txt`,
`requirements-audit-*.txt`, `operator_credentials*.json`, `*_audit.txt`)
swallowing files the delivery SHIPS. Anchored `!` negations now pin those
paths, so git-aware transfers keep them.

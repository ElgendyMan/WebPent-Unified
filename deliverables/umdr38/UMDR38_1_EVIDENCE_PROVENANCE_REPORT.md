# UM-DR-38.1 — Evidence Provenance Report (Phase 2)

Generated: 2026-11-17T04:58:58.434367+00:00 — from the CURRENT machine records only. The superseded UM-DR-38 evidence (bound to the lost commit `e31cad5`) is preserved as history and NEVER reused as current-release proof.

## One source of truth — separated revisions

| Revision | Value | Resolvable from this branch |
|---|---|---|
| provenance.source_revision | `9802cd22f2b7` | YES |
| provenance.tested_revision | `9802cd22f2b7` | YES |
| provenance.evidence_revision | `9802cd22f2b7` | YES |
| provenance.recovery_baseline | `1968f63c2076` | YES |

These are SEPARATE fields (the git_head single-field claim from the UM-DR-32 era remains documented as a provenance limitation inside BUILD_INFO). Artifact revision = the deliverable manifests' source_commit; publication revision = the commit GitHub carries after the PR merges (NOT_YET_PUBLISHED — no push credentials in the build environment).

## The current full-suite evidence

* source_commit: `9802cd22f2b7c11ed5350eaa33a965573d4b339b`
* tree_clean at test start: **True**
* python: 3.12.16 | uv: uv 0.13.8 (x86_64-unknown-linux-gnu)
* lockfile sha256: `6d714ff5ed5212b8e751d19fc50917aa52fec042583f4d69d9d6b2a75c4ef650`
* test scope digest: `55304f036becaf0c79ad3e14da5fa851bb842b61919d3f9d61ddac7d254722af`
* collected 9288 | executed 9289 | passed 9277 | failed 0 | errors 0 | skipped 9 | xfailed 3
* v3 invariants: True | cross-check agree: True | interrupted: False
* coverage: 77.09% (floor 72)
* exit code: 0

## The test-commit vs metadata-commit relationship

The evidence was produced at the SOURCE commit recorded above with a clean tree. Commits after it carry ONLY: the BUILD_INFO re-baseline (touching BUILD_INFO.json alone) and the generated deliverables. The re-baseline tool enforces this invariant — any later change to `src/`, `tests/`, `pyproject.toml`, `uv.lock` or the workflows invalidates the evidence and the re-baseline refuses. The evidence checker enforces the same contract: an ancestor evidence commit validates exactly when every path changed since is metadata.

## BUILD_INFO re-baseline (derived, never typed)

* package_version: 0.40.1
* suite_count: 9288 = the v3 well-formed EXECUTED count (accounting_v3.started_items — the v2 executed conflates collection-phase reports; the UM-DR-24 release gate requires suite_count <= collected)
* publication.published: False (honest: remote publication blocked)

# UM-DR-38.1 — Repository Structure Report (Phase 1)

Generated: 2026-11-17T04:58:58.420541+00:00 — proven from the GIT TREE at **98184af16754** (`git ls-tree`), not from file listings.

## Repository root now contains

```
.github
README.md
WebPent_UNIFIED
WebPent_Unified_umdr38.bundle
deliverables
dist
```

| Path | In the git tree |
|---|---|---|
| `README.md` | YES |
| `.github/workflows/ci.yml` | YES |
| `.github/workflows/nightly.yml` | YES |
| `.github/workflows/weekly-benchmarks.yml` | YES |
| `WebPent_UNIFIED/pyproject.toml` | YES |
| `WebPent_UNIFIED/README.md` | YES |
| `WebPent_UNIFIED/BUILD_INFO.json` | YES |
| `deliverables/umdr38/UMDR38_ACCEPTANCE_MATRIX.json` | YES |
| `deliverables/umdr37/evidence/EVIDENCE_MANIFEST.json` | YES |
| `WebPent_Unified_umdr38.bundle` | YES |

## The nested locations are GONE

* `WebPent_UNIFIED/.github/`: removed (the canonical workflows moved to the root; tests/test_umdr38_1_repository_structure.py forbids the nested shadow and pins the root paths with NO fallback)
* `WebPent_UNIFIED/deliverables/umdr38|umdr37`: moved to the root `deliverables/` — the project's own historical deliverables stay inside the project.

## The root README

A REAL repository entrypoint (what WebPent is, that the code lives in `WebPent_UNIFIED/`, clean-clone install, test and evidence commands, the MANDATORY authorization requirements, the security policy, the CI gates, where the reports and evidence live). The project README at `WebPent_UNIFIED/README.md` is untouched.

## Workflow corrections carried over

* every job executes from the project root via `defaults.run.working-directory: WebPent_UNIFIED`;
* artifact-upload paths are re-rooted independently (marketplace actions ignore `working-directory`): `WebPent_UNIFIED/.webpent-evidence/`, `WebPent_UNIFIED/docs/sbom.cdx.json`;
* `workflow_dispatch` on top of push/PR; nightly/weekly schedules preserved; every security gate carried over — none removed.

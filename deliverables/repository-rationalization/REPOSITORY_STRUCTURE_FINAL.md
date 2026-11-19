# Repository Structure — final state after UM-DR Phase B

## The working structure (unchanged canonical contracts)

```
WebPent-Unified/
├── README.md
├── .github/workflows/ci.yml
├── WebPent_Unified_umdr38.bundle          (unique history — preserved)
├── deliverables/
│   ├── umdr37/ umdr38/ umdr39/            (canonical release evidence)
│   ├── umdr39.1/                          (provenance reconciliation)
│   ├── repository-rationalization/        (phase-B package)
│   └── umdr40/                            (research-evolution package)
└── WebPent_UNIFIED/                        (canonical application root)
    ├── src/ tests/ scripts/ config/ verification/ docs/
    ├── docs/archive/2026-10-28-root-artifacts/   (dated archive — completed)
    ├── archive/self_reports_20261101/            (dated archive)
    ├── memory/global/chroma_db                  (runtime mount point, untracked)
    └── pyproject.toml uv.lock BUILD_INFO.json CHANGELOG.md README.md …
```

## What changed in this phase

* 11 root-level historical files removed (byte-identical copies in
  the dated archives); 2 root artifacts + 1 artifacts directory
  moved into the archive (zero loss) — commit 458a973.
* Mission lifecycle register added (docs/engineering/
  MISSION_LIFECYCLE.md + machine-readable JSON): 7 COMPLETED /
  3 ACTIVE / 2 DEFERRED / 1 BLOCKED_EXTERNAL_DEPENDENCY.
* Inventory scripts added under scripts/ (reproducible measurement).

## Documented follow-ups (explicitly NOT executed)

The root still carries other historical report families (FABRIC_*,
ADDITIONS_*, EXECUTION_REPORT, …): no verified archive copies and
no reference analysis were performed for them in this window —
recorded as the first candidates for a follow-up pass with the same
per-file evidence discipline.

# Cleanup Decisions (UM-DR Phase B)

Generated 2026-11-18 from the measured inventory
(`REPOSITORY_INVENTORY.json`). Every decision carries its evidence.

## D1 — Git bundles: PRESERVE (all three)

| Bundle | Size | Verification | Decision |
|---|---|---|---|
| `WebPent_Unified_umdr38.bundle` | 29.8 MB | verify OK; head `8f43e88…` unreachable from the clone (unique history) | **Preserve** |
| `UMDR36_2_37_DELIVERABLES/…umdr36.2-umdr37.bundle` | 14.7 MB | verify OK; head `073c64b…` unreachable | **Preserve** |
| `deliverables/umdr36_1/…recovery-umdr36-closure.bundle` | 0.4 MB | verify OK; head `0d9511f…` unreachable | **Preserve** |

Every bundle carries at least one head commit unreachable from the
published repository (unique history). Mission rule: do not delete a
bundle containing unique history; no external archive destination
was authorized → retained in-tree (digests recorded in the
inventory).

## D2 — Root historical artifacts duplicated in dated archives: REMOVED root copies (commit 458a973)

11 root files under `WebPent_UNIFIED/` were byte-identical (sha256)
to copies already preserved in `docs/archive/2026-10-28-root-artifacts/`
and/or `archive/self_reports_20261101/` (largest: the 1.88 MB
TEAM1_AVI runtime JSON, three identical copies; a previous cleanup
archived them but left the root copies). The two root artifacts
WITHOUT an archive copy (the source-hash file and the DEEP_RECON
directory) were moved into the dated archive first — zero
information loss, mapped in FILE_MIGRATION_MAP.md. Live-code import
search over src/, scripts/, tests/ found no runtime consumer of any
removed file.

## D3 — Large coverage/evidence JSON: PRESERVE both baselines, no merge

`docs/coverage_measured_baseline_0260.json` (5.6 MB, the coverage
ratchet baseline) and `deliverables/umdr38/test_evidence/
coverage_last_run.json` (canonical release evidence) serve different
contracts; the `docs/history/UMDR37_COVERAGE_LAST_RUN.json` snapshot
is distinct historical content — all preserved.

## D4 — The 119 small duplicate sets (0.81 MB): DOCUMENTED, no bulk removal

Intentional archival copies; bulk removal saves under 1 MB and risks
breaking evidence paths. Recorded with digests for a future,
separately-reviewed pass.

## D5 — Empty `memory/global/chroma_db`: untracked runtime mount point — no action.

## D6 — Orphaned-code audit: DEFERRED to UM-DR-40 (RC-10 assessment) — no module removed.

## What was NOT done, and why

* No history rewrite, no filter-repo/BFG (pack 44.8 MiB; tracked
  payload ~136 MB — working-tree cleanup is the honest scope).
* No gate or floor lowered; the full suite re-ran green after the
  cleanup commit.

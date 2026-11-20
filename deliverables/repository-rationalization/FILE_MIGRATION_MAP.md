# File Migration Map (UM-DR Phase B cleanup — commit 458a973)

## Removed root files — canonical copy already in a dated archive

| Removed root path | Preserved canonical copy (byte-identical) |
|---|---|
| `AUTONOMOUS_BUG_HUNTER_MASTER_PLAN.md` | `docs/archive/2026-10-28-root-artifacts/` |
| `DEPLOYMENT_CHECKLIST.md` | `docs/archive/2026-10-28-root-artifacts/` |
| `LEGACY_CONFIRMATION_PATHS.md` | both archives |
| `TEAM1_AVI_V1_1_REAL_TARGET_QUALIFICATION_REPORT.md` | both archives |
| `TEAM1_AVI_V1_2_100_DECISION_RUNTIME.json` | both archives |
| `TEAM1_AVI_V1_2_ENVIRONMENT.md` | both archives |
| `TEAM1_AVI_V1_2_RELEASE_CLOSURE.json` | both archives |
| `TEAM1_AVI_V1_2_RELEASE_CLOSURE.md` | both archives |
| `TEAM1_AVI_V1_2_TRUST_HARDENING.json` | both archives |
| `TEAM1_AVI_V1_2_TRUST_HARDENING.md` | both archives |
| `TEAM1_AVI_V1_PRODUCTION_RELEASE_REPORT.md` | both archives |

(all under `WebPent_UNIFIED/`; "both archives" =
`docs/archive/2026-10-28-root-artifacts/` + `archive/self_reports_20261101/`)

## Moved root files — archived in this cleanup, then removed from root

| Old root path | New archived path |
|---|---|
| `TEAM1_AVI_V1_2_SOURCE_HASH.sha256.txt` | `docs/archive/2026-10-28-root-artifacts/…` |
| `TEAM1_DEEP_RECON_ARTIFACTS/` (4 files, 20 KB) | `docs/archive/2026-10-28-root-artifacts/TEAM1_DEEP_RECON_ARTIFACTS/` |

## Reference handling

Live-code import search over `src/`, `scripts/`, `tests/` found no
runtime consumer of any removed file. The remaining references are
inside historical records; per the evidence-preservation rule those
texts are left as written — this map is the resolution record.

#!/usr/bin/env python3
"""Archive the remaining point-in-time root reports — plan item ب.5
(WEBPENT_FIX_PLAN_20261029.md, 2026-11-01 window).

The 2026-10-29 root-closure pass (scripts/root_closure_move_20261029.py)
already took the root from 152 files to ~46; this pass moves the last
historical report files (merge/unfreeze/red-team/remediation logs) into
``docs/archive/2026-11-01-plan-exec-root-reports/`` so the root keeps only
ACTIVE files (config, gates, README/CHANGELOG/DRIFT_REGISTER/worklog and the
frozen-manifest artifacts the gate test reads).

Every move fails closed: the file must exist at the root and must not
already exist in the archive. Pointers in README/comments are updated in
the same window (see the CHANGELOG entry).
"""
from __future__ import annotations

import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ARCHIVE = REPO / "docs" / "archive" / "2026-11-01-plan-exec-root-reports"

# Historical point-in-time reports (provenance logs, no runtime reader).
REPORTS = [
    "ADDITIONS_AND_FIXES_20261022.md",
    "CHANGED_FROM_BASELINE.txt",
    "MERGE_20261026.md",
    "MERGE_REPORT.md",
    "REMEDIATION_REPORT.md",
    "REVIEW_REFREEZE_REPORT.md",
    "ULTIMATE_PLAN_EXECUTION_20261027.md",
    "UNFREEZE_APPLIED_REPORT_20261005.md",
    "UNFREEZE_TRACK2_PARALLEL_RECON_20261019.md",
    "UNFREEZE_TRACK3_RABBIT_HOLE_DRAFTING_20261020.md",
]

# Deliberate root keeps (active files) — asserted to remain untouched.
MUST_STAY = [
    "README.md",
    "CHANGELOG.md",
    "DRIFT_REGISTER.md",
    "worklog.md",
    "frozen_modules.sha256",
    "frozen_modules.sha256.baseline_pre_unfreeze",
    "frozen_modules.sha256.orig",
]


def main() -> int:
    ARCHIVE.mkdir(parents=True, exist_ok=True)
    for name in MUST_STAY:
        if not (REPO / name).is_file():
            print(f"ABORT: deliberate keep missing from root: {name}")
            return 1
    moved = 0
    for name in REPORTS:
        src = REPO / name
        dst = ARCHIVE / name
        if not src.is_file() and dst.is_file():
            print(f"  {name} (already archived)")
            continue
        if not src.is_file():
            print(f"ABORT: expected report missing: {name}")
            return 1
        if dst.exists():
            print(f"ABORT: archive collision for {name}")
            return 1
        shutil.move(str(src), str(dst))
        moved += 1
        print(f"  {name} -> docs/archive/2026-11-01-plan-exec-root-reports/")
    root_files = sum(1 for p in REPO.iterdir() if p.is_file())
    print(f"moved {moved} report(s); root files now: {root_files}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build the 0.34.0 red-team R2 COMPLETE delivery ZIP (2026-11-02).

Same convention as the 0.26-0.33 windows: full-tree mirror, excluding
.git, __pycache__, .venv, egg-info, .pyc, *.sqlite3, webpent.db (+WAL/SHM)
and the delivery ZIPs themselves. Fail-closed: refuses to ship without
the window's evidence artifacts (now including the round-2 addendum that
closes the §8 list with families/forge).
"""
from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("/home/z/my-project/download/webpent_ULTIMATE_0.34.0_r2_complete_20261102.zip")

EXCLUDE_DIRS = {".git", "__pycache__", ".venv", ".pytest_cache", ".ruff_cache", "download"}
EXCLUDE_SUFFIXES = (".pyc", ".sqlite3", ".zip")
EXCLUDE_FILE_PARTS = ("egg-info",)
EXCLUDE_FILES = {"webpent.db", "webpent.db-wal", "webpent.db-shm"}

REQUIRED = [
    "docs/RED_TEAM_ROUND2_20261102.md",
    "docs/PRODUCTION_HARDENING_PLAN_0330.md",
    "docs/FULL_SUITE_EVIDENCE_0340_REDTEAM_R2.md",
    "reports/canary/CANARY_7X_20261101_0.34.0.json",
    "reports/canary/CANARY_7X_20261101_0.34.0.md",
    "scripts/refreeze_manifest_0340_redteam_r2.py",
    "scripts/regen_direct_io_inventory_0340_redteam_r2.py",
    "scripts/r2_families_forge_repros.py",
    "scripts/quality/DELIVERY_GIT_HEAD_0340.txt",
    "tests/test_redteam_r2_c1.py",
    "tests/test_redteam_r2_c2.py",
    "requirements.constraints.txt",
    "CHANGELOG.md",
    "uv.lock",
]


def excluded(p: Path, rel: str) -> bool:
    if p.is_dir():
        return False
    parts = p.parts
    if any(part in EXCLUDE_DIRS for part in parts):
        return True
    if any(part in EXCLUDE_FILE_PARTS for part in parts):
        return True
    if rel in EXCLUDE_FILES:
        return True
    return rel.endswith(EXCLUDE_SUFFIXES)


def main() -> int:
    for req in REQUIRED:
        if not (ROOT / req).is_file():
            print(f"ABORT: required deliverable missing: {req}")
            return 2
    git_head = (ROOT / "scripts" / "quality" / "DELIVERY_GIT_HEAD_0340.txt").read_text().strip()
    live = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    if live and live != git_head:
        print(f"ABORT: git head moved: manifest={git_head} live={live}")
        return 3
    count = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(ROOT.rglob("*")):
            if p.is_dir():
                continue
            rel = p.relative_to(ROOT).as_posix()
            if excluded(p, rel):
                continue
            zf.write(p, arcname=f"webpent/{rel}")
            count += 1
        zf.writestr(
            "webpent/DELIVERY_INFO_0340_R2_COMPLETE.txt",
            "webpent 0.34.0 red-team R2 COMPLETE delivery (2026-11-02)\n"
            f"git_head_live: {git_head}\n"
            "window: docs/RED_TEAM_ROUND2_20261102.md — fix window C1 10/10 + C2 18/18 + "
            "C3 16/17 (45/45 base findings; lesson-wiring half deferred, documented) + "
            "§8 addendum closing the §8 list with families/forge (25 findings: "
            "1 Critical / 6 High / 10 Medium / 8 Low; all 7 Critical+High proven by "
            "direct execution — scripts/r2_families_forge_repros.py); 0.35.0 window "
            "proposed (CA/CB/CC) with hard ordering: no family-spine wiring before CA\n"
            "suite: 6844 collected = 6837 passed / 0 failed / 4 skipped / 3 xfailed\n"
            "post-addendum re-verification: freeze gate 661 passed; families+forge "
            "suites 327 passed / 2 skipped; repro script 7/7 PROVEN\n"
            "canary: 7x STABLE with collection gate (0 silent collection errors)\n"
            "manifest: 659 entries re-frozen (REDTEAM_R2_20261102_THAW_PATHS=1)\n"
            "direct-I/O: 814 -> 816 records (declared deltas only)\n"
            "ruff ratchet: 6212 == 6212 (re-baselined, zero new src findings)\n",
        )
    print(f"OK: {OUT} ({count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

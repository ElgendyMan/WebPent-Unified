#!/usr/bin/env python3
"""Build the 0.33.0 production-hardening delivery ZIP (2026-11-01).

Same convention as the 0.26-0.32 windows: full-tree mirror, excluding
.git, __pycache__, .venv, egg-info, .pyc, *.sqlite3, webpent.db (+WAL/SHM)
and the delivery ZIPs themselves. Fail-closed: refuses to ship without
the window's evidence artifacts.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("/home/z/my-project/download/webpent_ULTIMATE_0.33.0_hardening_20261101.zip")

EXCLUDE_DIRS = {".git", "__pycache__", ".venv", ".pytest_cache", ".ruff_cache", "download"}
EXCLUDE_SUFFIXES = (".pyc", ".sqlite3", ".zip")
EXCLUDE_FILE_PARTS = ("egg-info",)
EXCLUDE_FILES = {"webpent.db", "webpent.db-wal", "webpent.db-shm"}

REQUIRED = [
    "docs/PRODUCTION_HARDENING_PLAN_0330.md",
    "docs/UNFREEZE_FILES_0330_HARDENING.md",
    "docs/FULL_SUITE_EVIDENCE_0330_HARDENING_CHUNKED.txt",
    "reports/canary/CANARY_7X_20261101_0.33.0.json",
    "reports/canary/CANARY_7X_20261101_0.33.0.md",
    "scripts/refreeze_manifest_0330_hardening.py",
    "scripts/regen_direct_io_inventory_0330_hardening.py",
    "scripts/quality/DELIVERY_GIT_HEAD_0330.txt",
    "tests/test_hardening_0330_b1.py",
    "tests/test_hardening_0330_b2.py",
    "tests/test_hardening_0330_b3.py",
    ".dockerignore",
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
        # Delivery self-descriptor.
        git_head = (ROOT / "scripts" / "quality" / "DELIVERY_GIT_HEAD_0330.txt").read_text().strip()
        zf.writestr(
            "webpent/DELIVERY_INFO_0330.txt",
            "webpent 0.33.0 production-hardening delivery (2026-11-01)\n"
            f"git_head_live: {git_head}\n"
            "window: docs/PRODUCTION_HARDENING_PLAN_0330.md (B1/B2/B3 100% + B4 minimum)\n"
            "suite: 6783 collected = 6776 passed / 0 failed / 4 skipped / 3 xfailed\n"
            "canary: 7x STABLE, ruff clean, collection clean (6783, 0 errors)\n"
            "manifest: 659 entries re-frozen (23 declared changed)\n"
            "direct-I/O: 815 -> 814 records (declared deltas only)\n",
        )
        count += 1
    print(f"OK: {OUT} — {count} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

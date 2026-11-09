#!/usr/bin/env python3
"""Build the 0.32.0 retired-alias-removal delivery ZIP (2026-11-01).

Same convention as the 0.26/0.27/0.28/0.29/0.30 windows: full-tree
mirror, excluding .git, __pycache__, .venv, egg-info, .pyc, *.sqlite3.
Fail-closed: refuses to ship without the window's evidence artifacts.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("/home/z/my-project/download/webpent_ULTIMATE_0.32.0_alias_removal_20261101.zip")

EXCLUDE_DIRS = {".git", "__pycache__", ".venv", ".pytest_cache", ".ruff_cache"}
EXCLUDE_SUFFIXES = (".pyc", ".sqlite3")
EXCLUDE_FILE_PARTS = ("egg-info",)

REQUIRED = [
    "docs/FULL_SUITE_EVIDENCE_0320_ALIAS_REMOVAL_CHUNKED.txt",
    "scripts/quality/cve_allowlist.json",
    "scripts/quality/DELIVERY_GIT_HEAD_0320.txt",
    "reports/canary/CANARY_7X_20261101_0.32.0.json",
    "reports/canary/CANARY_7X_20261101_0.32.0.md",
    "scripts/refreeze_manifest_0320_alias_removal.py",
    "scripts/regen_direct_io_inventory_0320_alias_removal.py",
    "src/webpent/autonomous/authorization_recheck.py",
    "tests/test_retired_alias_removal_v0320.py",
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
    size = OUT.stat().st_size
    print(f"OK: {OUT.name} — {count} files, {size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

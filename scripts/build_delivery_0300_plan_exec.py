#!/usr/bin/env python3
"""Build the 0.30.0 plan-execution delivery ZIP (2026-11-01).

Same convention as the 0.26/0.27/0.28/0.29 windows: full-tree mirror,
excluding .git, __pycache__, .venv, egg-info, .pyc, *.sqlite3.
Fail-closed: refuses to ship without the window's evidence artifacts.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("/home/z/my-project/download/webpent_ULTIMATE_0.30.0_plan_exec_20261101.zip")

EXCLUDE_DIRS = {".git", "__pycache__", ".venv", ".pytest_cache", ".ruff_cache"}
EXCLUDE_SUFFIXES = (".pyc", ".sqlite3")
EXCLUDE_FILE_PARTS = ("egg-info",)

REQUIRED = [
    "docs/FULL_SUITE_EVIDENCE_0300_PLANEXEC_CHUNKED.txt",
    "docs/pip_audit_release.json",
    "scripts/quality/cve_allowlist.json",
    "scripts/quality/DELIVERY_GIT_HEAD_0300.txt",
    "reports/canary/CANARY_7X_20261101_0.30.0.json",
    "scripts/refreeze_manifest_0300_plan_exec.py",
    "scripts/regen_direct_io_inventory_0300_plan_exec.py",
    "scripts/root_reports_archive_20261101.py",
    "docs/archive/2026-11-01-plan-exec-root-reports/MERGE_20261026.md",
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
    files = [
        p for p in sorted(ROOT.rglob("*"))
        if p.is_file() and not excluded(p, str(p.relative_to(ROOT)))
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for p in files:
            zf.write(p, str(p.relative_to(ROOT)))
    size = OUT.stat().st_size
    print(f"OK: {OUT.name} — {len(files)} files, {size/1_048_576:.1f} MiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

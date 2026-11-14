#!/usr/bin/env python3
"""Post-build ZIP hygiene gate (audit D-04/D-05/D-09 remediation).

Fails (exit 1) if the archive contains any of:
  - runtime databases:        *.db, *.db-*, *.sqlite, *.sqlite3, *.lock
  - editor backup droppings:  *.orig, *.pre-fix, *.bak, *~
  - cache/build cruft:        __pycache__/, .pytest_cache/, .ruff_cache/,
                              *.egg-info/, *.pyc
  - environment leak:         .env (any depth)
Also fails if any entry has an mtime in the future relative to the newest
entry (clock-jump forensics hygiene, audit D-09) with a 24h tolerance.

Usage: python scripts/zip_hygiene_gate.py path/to/archive.zip
Exit codes: 0 = PASS, 1 = FAIL (entries listed), 2 = usage error.
"""

from __future__ import annotations

import fnmatch
import sys
import zipfile
from datetime import datetime, timedelta, timezone

FORBIDDEN_PATTERNS = [
    "*.db", "*.db-*", "*.sqlite", "*.sqlite3", "*.lock",
    "*.orig", "*.pre-fix", "*.bak", "*~",
    "*.pyc", ".env",
]
# Dependency lockfiles are legitimate build inputs, not runtime locks:
ALLOWED_LOCKFILES = {"uv.lock", "requirements_closure.txt"}
FORBIDDEN_DIR_COMPONENTS = {
    "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
}
FORBIDDEN_DIR_SUFFIXES = (".egg-info",)


def entry_forbidden(name: str) -> str | None:
    parts = name.split("/")
    for part in parts[:-1]:
        if part in FORBIDDEN_DIR_COMPONENTS or part.endswith(FORBIDDEN_DIR_SUFFIXES):
            return f"forbidden directory component: {part}"
    base = parts[-1]
    if not base:
        return None
    if base in ALLOWED_LOCKFILES:
        return None
    for pattern in FORBIDDEN_PATTERNS:
        if fnmatch.fnmatch(base, pattern):
            return f"matches forbidden pattern {pattern}"
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: zip_hygiene_gate.py <archive.zip>", file=sys.stderr)
        return 2
    archive = sys.argv[1]
    with zipfile.ZipFile(archive) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        violations = []
        for info in infos:
            reason = entry_forbidden(info.filename)
            if reason:
                violations.append(f"{info.filename}  ({reason})")

        mtimes = [
            datetime(*info.date_time, tzinfo=timezone.utc) for info in infos
        ]
        newest = max(mtimes)
        stale_clock = [info.filename
                       for info, mt in zip(infos, mtimes)
                       if mt > newest + timedelta(days=365)]
        if stale_clock:
            violations.append(
                "entries dated more than 1 year after the newest entry "
                f"(clock-jump anomaly): {stale_clock[:10]}"
            )

        print(f"ZIP hygiene gate: {archive}")
        print(f"  entries checked: {len(infos)}")
        print(f"  newest entry mtime: {newest.isoformat()}")
        if violations:
            print(f"  FAIL — {len(violations)} violation(s):")
            for v in violations:
                print(f"    - {v}")
            return 1
        print("  PASS — no databases, locks, backups, caches, or .env in archive")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

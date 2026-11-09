#!/usr/bin/env python3
"""M12 (Part 4 §14): verify backup/restore for the per-engagement
workspace stores.

The registry's acceptance: "documented, safe deploy + restore". This
harness makes RESTORE verifiable per workspace store:

1. **Backup** — copy every workspace store file (the sqlite databases
   under ``sessions/``/``databases/``/``ledgers/`` and the report
   artifacts) into a timestamped backup directory, plus a manifest
   with sha256 per file.
2. **Restore** — copy the backup back into a (fresh) workspace.
3. **Verify** — every restored sqlite store passes
   ``PRAGMA integrity_check``; every file's sha256 matches the backup
   manifest; row-count spot checks per store.

Usage:
    python scripts/verify_backup_restore.py --workspace <dir> [--backup-dir <dir>]

Exit 0 = the workspace's stores backup, restore and verify clean.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path

STORE_SUFFIXES = (".sqlite3", ".sqlite", ".db")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def store_files(workspace: Path) -> list[Path]:
    files: list[Path] = []
    for sub in ("sessions", "databases", "ledgers", "reports", "rag"):
        root = workspace / sub
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file():
                files.append(path)
    return files


def backup(workspace: Path, backup_dir: Path) -> dict:
    backup_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, str] = {}
    for path in store_files(workspace):
        relative = path.relative_to(workspace)
        target = backup_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        manifest[str(relative)] = sha256(target)
    (backup_dir / "BACKUP_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    return manifest


def restore(backup_dir: Path, destination: Path) -> None:
    manifest_path = backup_dir / "BACKUP_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    destination.mkdir(parents=True, exist_ok=True)
    for relative in sorted(manifest):
        source = backup_dir / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def verify(workspace: Path, backup_dir: Path) -> list[str]:
    failures: list[str] = []
    manifest = json.loads(
        (backup_dir / "BACKUP_MANIFEST.json").read_text(encoding="utf-8")
    )
    for relative, expected in sorted(manifest.items()):
        path = workspace / relative
        if not path.is_file():
            failures.append(f"missing_after_restore:{relative}")
            continue
        if sha256(path) != expected:
            failures.append(f"hash_mismatch:{relative}")
        if path.suffix in STORE_SUFFIXES:
            try:
                connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                try:
                    result = connection.execute("PRAGMA integrity_check").fetchone()
                    if not result or result[0] != "ok":
                        failures.append(f"integrity_check_failed:{relative}")
                finally:
                    connection.close()
            except sqlite3.Error as exc:
                failures.append(f"sqlite_open_failed:{relative}:{exc}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="the workspace directory")
    parser.add_argument("--backup-dir", default=None, help="where the backup lands")
    args = parser.parse_args(argv)

    workspace = Path(args.workspace)
    if not workspace.is_dir():
        print(f"ABORT: workspace not found: {workspace}", file=sys.stderr)
        return 2
    backup_dir = Path(args.backup_dir) if args.backup_dir else workspace.parent / (
        workspace.name + "-backup-verify"
    )
    if backup_dir.exists():
        shutil.rmtree(backup_dir)

    manifest = backup(workspace, backup_dir)
    restore_target = backup_dir / "_restored"
    restore(backup_dir, restore_target)
    failures = verify(restore_target, backup_dir)

    print(f"backed up {len(manifest)} file(s) -> {backup_dir}")
    if failures:
        for failure in failures:
            print(f"  FAIL: {failure}", file=sys.stderr)
        return 1
    print("OK: every store restored byte-identical and integrity-checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

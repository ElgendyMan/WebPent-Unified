#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the ROOTLESS DEPLOYMENT window
(v0.28.0) per the DR-009 protocol:

  * same path set + same order — every existing entry's hash is
    recomputed from the current tree (fail-closed on a missing file);
  * NO scope completion: the window touches NO new src/ file. The only
    frozen-file change is the declared version bump of
    ``src/webpent/__init__.py`` (0.27.0 -> 0.28.0, the SSOT rule the
    release-packaging gate enforces). The path is already a documented
    member of MERGE_20261026_THAW_PATHS (Track 0.4 identity lineage), so
    no new thaw group is required in the gate test;
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_0280_rootless.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

# 0.28.0 adds no new src files — the list is empty by design; kept as an
# explicit declaration so the next window can diff its scope at a glance.
WINDOW_SCOPE_COMPLETION: list[str] = []

# The single frozen file whose bytes changed in this window (the declared
# version bump). Informational — the script re-hashes the whole manifest.
WINDOW_CHANGED_FILES = [
    "src/webpent/__init__.py",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            print(f"ABORT: unparsable manifest line: {line!r}", file=sys.stderr)
            return 1
        digest, relpath = parts[0], parts[1].strip()
        entries.append((digest, relpath))
        seen.add(relpath)

    for relpath in WINDOW_CHANGED_FILES:
        if relpath not in seen:
            print(f"ABORT: declared changed file is not pinned: {relpath}", file=sys.stderr)
            return 1

    for relpath in WINDOW_SCOPE_COMPLETION:
        if relpath in seen:
            continue
        entries.append(("NEW", relpath))
        seen.add(relpath)

    out_lines: list[str] = []
    for digest, relpath in entries:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"ABORT: pinned path missing from tree: {relpath}", file=sys.stderr)
            return 1
        actual = sha256(absolute)
        marker = " (re-pinned new)" if digest == "NEW" else (
            " (changed)" if actual != digest.lower() else ""
        )
        if marker:
            print(f"  {relpath}{marker}")
        out_lines.append(f"{actual}  {relpath}")

    # Self-check before write.
    for line in out_lines:
        digest, relpath = line.split(None, 1)
        if sha256(REPO / relpath.strip()) != digest:
            print(f"ABORT: self-check failed for {relpath}", file=sys.stderr)
            return 1

    tmp = MANIFEST.with_suffix(".sha256.tmp")
    tmp.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    tmp.replace(MANIFEST)
    print(f"manifest re-frozen: {len(out_lines)} entries "
          f"(+{len(WINDOW_SCOPE_COMPLETION)} scope completion)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the PLAN-EXECUTION window (v0.30.0)
per the DR-009 protocol:

  * the window's declared frozen-tree changes are the provenance-comment
    path updates (plan item ب.5 — historical reports moved to
    docs/archive/2026-11-01-plan-exec-root-reports/) in
    ``src/webpent/autonomous/__init__.py`` and
    ``src/webpent/agents/validator/agent.py``, the deprecation-banner
    edits in ``src/webpent/cli/commands.py`` (plan item ج.2 — scheduled
    removal window declared on the retired aliases), and the declared
    version bump of the SSOT identity file ``src/webpent/__init__.py``
    (0.29.0 -> 0.30.0);
  * NO removals and NO scope completion: the window deletes no src file
    and adds no new src file;
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_0300_plan_exec.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

# Declared deletions of this window — none (kept as an explicit
# declaration so the next window can diff its scope at a glance).
WINDOW_REMOVED_FILES: list[str] = []

# No new src files in this window — empty by design.
WINDOW_SCOPE_COMPLETION: list[str] = []

# Comment/banner edits + the declared version bump of the SSOT identity
# file. Run this script AFTER the version bump — it re-hashes from the
# current tree. NOTE: src/webpent/autonomous/__init__.py is NOT manifest-
# pinned (like most package __init__ files) — its provenance-comment edit
# is declared in the CHANGELOG instead.
WINDOW_CHANGED_FILES = [
    "src/webpent/__init__.py",
    "src/webpent/cli/commands.py",
    "src/webpent/agents/validator/agent.py",
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

    for relpath in WINDOW_REMOVED_FILES:
        if relpath not in seen:
            print(
                f"ABORT: declared removed file is not pinned: {relpath}",
                file=sys.stderr,
            )
            return 1
        if (REPO / relpath).exists():
            print(
                "ABORT: declared removed file still exists in the tree: "
                f"{relpath}",
                file=sys.stderr,
            )
            return 1
        entries = [(d, p) for d, p in entries if p != relpath]
        seen.discard(relpath)
        print(f"  {relpath} (removed)")

    for relpath in WINDOW_CHANGED_FILES:
        if relpath not in seen:
            print(
                f"ABORT: declared changed file is not pinned: {relpath}",
                file=sys.stderr,
            )
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
            print(
                f"ABORT: pinned path missing from tree: {relpath}",
                file=sys.stderr,
            )
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
    print(
        f"manifest re-frozen: {len(out_lines)} entries "
        f"(-{len(WINDOW_REMOVED_FILES)} declared removal, "
        f"+{len(WINDOW_SCOPE_COMPLETION)} scope completion, "
        f"{len(WINDOW_CHANGED_FILES)} declared changed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

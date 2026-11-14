#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the G-1 REMOVAL window (v0.29.0)
per the DR-009 protocol:

  * the window's declared frozen-tree change is the DELETION of the retired
    ``src/webpent/brain/lessons.py`` module (docs/PRODUCTION_FIX_PLAN_0270.md
    item G-1; retirement decision in docs/learning_source_of_truth.md —
    "deletion is a separate, announced change");
  * a manifest pin pointing at a deleted file can never pass
    ``scripts/verify_frozen_manifest.py`` (it fails closed on any
    ``missing:<path>``), so this script removes the declared entries and
    re-hashes everything that remains (fail-closed on any other missing
    file — the gate must never be silenced by an unrelated deletion);
  * NO scope completion: the window adds no new src/ file;
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_0290_g1_lessons_removal.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

# Declared deletions of this window — each MUST currently be pinned; the
# entry is dropped and the file must indeed be absent from the tree.
WINDOW_REMOVED_FILES = [
    "src/webpent/brain/lessons.py",
]

# No new src files in this window — empty by design, kept as an explicit
# declaration so the next window can diff its scope at a glance.
WINDOW_SCOPE_COMPLETION: list[str] = []
# Deletion only, plus the declared version bump of the SSOT identity file
# (0.28.0 -> 0.29.0). Run this script AFTER the version bump — it re-hashes
# from the current tree.
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
        print(f"  {relpath} (removed — G-1 declared deletion)")

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
        f"+{len(WINDOW_SCOPE_COMPLETION)} scope completion)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

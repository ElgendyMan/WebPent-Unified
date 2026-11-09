#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the FEATURE PROPOSALS window
ق5-ق11 (2026-11-04) per the DR-009 protocol:

  * the window declares EXACTLY ONE frozen-tree change:
      - src/webpent/config/settings.py — declares the missing
        ``enable_platform_export`` flag (UM-DR-09). The platform export
        renderer (reporter/platform_export.py, PROPOSALS_ULTIMATE_V3 §6)
        was merged reading a flag that Settings never declared; every
        gate read raised AttributeError (UM-DR-06 residual, 14 red
        tests). The field is declared additively, default False
        (fail-closed), with the standard AliasChoices env aliases.
  * NO manifest-path removals;
  * NO scope completions (all ق5-ق11 deliverables are NEW files the
    manifest has never pinned: src/webpent/shared/cve_advisory.py,
    src/webpent/jsintel/*, src/webpent/auth/identity_orchestrator.py,
    src/webpent/reporter/bounty_pipeline.py, src/webpent/dojo/
    self_benchmark.py, src/webpent/portfolio/*, src/webpent/legacy_*
    — new files are outside the frozen gate by construction);
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_0350_proposal_window.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

# Run AFTER the edit — hashes re-read from the current tree.
WINDOW_CHANGED_FILES = [
    "src/webpent/config/settings.py",  # UM-DR-09: enable_platform_export
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
            print(f"ABORT: declared removed file is not pinned: {relpath}", file=sys.stderr)
            return 1
        if (REPO / relpath).exists():
            print(f"ABORT: declared removed file still exists in the tree: {relpath}", file=sys.stderr)
            return 1
        entries = [(d, p) for d, p in entries if p != relpath]
        seen.discard(relpath)
        print(f"  {relpath} (removed)")

    for relpath in WINDOW_CHANGED_FILES:
        if relpath not in seen:
            print(f"ABORT: declared changed file is not pinned: {relpath}", file=sys.stderr)
            return 1

    for relpath in WINDOW_SCOPE_COMPLETION:
        if relpath in seen:
            continue
        if not (REPO / relpath).is_file():
            print(f"ABORT: scope-completion file missing from tree: {relpath}", file=sys.stderr)
            return 1
        entries.append(("NEW", relpath))
        seen.add(relpath)

    out_lines: list[str] = []
    changed_count = 0
    for digest, relpath in entries:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"ABORT: pinned path missing from tree: {relpath}", file=sys.stderr)
            return 1
        current = sha256(absolute)
        if current != digest:
            if relpath not in WINDOW_CHANGED_FILES:
                print(
                    f"ABORT: UNDECLARED drift on pinned file {relpath} "
                    "(this window's protocol covers only the files listed "
                    "in WINDOW_CHANGED_FILES)",
                    file=sys.stderr,
                )
                return 1
            changed_count += 1
            out_lines.append(f"{current}  {relpath}")
            print(f"  re-pinned {relpath}")
        else:
            out_lines.append(f"{digest}  {relpath}")

    unexpected = changed_count != len(WINDOW_CHANGED_FILES)
    if unexpected:
        print(
            f"ABORT: expected to re-pin exactly {len(WINDOW_CHANGED_FILES)} "
            f"file(s), re-pinned {changed_count}",
            file=sys.stderr,
        )
        return 1

    MANIFEST.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    total = len(out_lines)
    print(f"OK: manifest re-frozen — {total} entries, {changed_count} re-pinned this window")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

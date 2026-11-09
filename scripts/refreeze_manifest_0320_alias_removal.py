#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the RETIRED-ALIAS REMOVAL window
(v0.32.0) per the DR-009 protocol:

  * the window's declared frozen-tree changes are the removal of the
    three retired CLI aliases (scan/hunt-auto/hunt-plan) and the
    scan-only helpers from ``src/webpent/cli/commands.py``, the
    re-export cleanup in ``src/webpent/cli/__init__.py``, the
    wording/docstring updates in ``src/webpent/cli/unified_hunt.py`` /
    ``src/webpent/state/unified_state.py`` /
    ``src/webpent/adapters/legacy_state_bridge.py`` /
    ``src/webpent/autonomous/hunt_state.py``, and the declared version
    bump of the SSOT identity file ``src/webpent/__init__.py``
    (0.30.0 -> 0.32.0 — the declared removal window name);
  * ONE scope completion: ``src/webpent/autonomous/authorization_recheck.py``
    (the v80 Task 3 mid-hunt recheck moved from the removed ``hunt-auto``
    CLI closure to the ``webpent.autonomous`` library API, verbatim
    semantics);
  * NO manifest-path removals (only in-file symbol removals);
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_0320_alias_removal.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

# Declared deletions of this window — none at the FILE level (the window
# removed in-file symbols from commands.py, not manifest paths).
WINDOW_REMOVED_FILES: list[str] = []

# The mid-hunt recheck module: new src file pinned by this re-freeze.
WINDOW_SCOPE_COMPLETION = [
    "src/webpent/autonomous/authorization_recheck.py",
]

# Run AFTER the version bump — hashes re-read from the current tree.
# (src/webpent/autonomous/hunt_state.py is NOT manifest-pinned — its
# docstring wording edit is declared in the CHANGELOG instead, same
# posture as the package __init__ files.)
WINDOW_CHANGED_FILES = [
    "src/webpent/__init__.py",
    "src/webpent/cli/__init__.py",
    "src/webpent/cli/commands.py",
    "src/webpent/cli/unified_hunt.py",
    "src/webpent/state/unified_state.py",
    "src/webpent/adapters/legacy_state_bridge.py",
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
        if not (REPO / relpath).is_file():
            print(
                f"ABORT: scope-completion file missing from tree: {relpath}",
                file=sys.stderr,
            )
            return 1
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

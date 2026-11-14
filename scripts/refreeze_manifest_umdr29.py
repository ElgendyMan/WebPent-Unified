#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-29 dead-code window
(2026-11-07) per the DR-009 protocol.

Documented scope of this refreeze (see archive/umdr29_dead_code/README.md):

  * REMOVED — 22 entries of the seven frozen-but-dead packages moved to
    archive/umdr29_dead_code/ (contracts, copilot, experience,
    persistence, profiles, security_models, validation). Verified dead by
    the UM-DR-29 import-graph reachability audit: zero runtime importers,
    zero test importers, zero script/config references. 661 -> 639 entries;
    the >= 630 floor documented in tests/test_frozen_module_gate.py holds.
    webpent/validation/ was a frozen dead duplicate of the live
    webpent/validators/; webpent/contracts/ was a dead re-export facade.

  * RE-PINNED — six package __init__.py docstring corrections (stale
    "Core engine: webpent.goed_v1, ..." lines replaced with the real
    engine roots after goed_v1 completed its archive move): workers,
    state, graph, api, agents, shared. Byte content changed for exactly
    these six frozen files; hashes re-pinned here.

Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr29.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR29_ARCHIVED_PACKAGES = (
    "src/webpent/contracts/",
    "src/webpent/copilot/",
    "src/webpent/experience/",
    "src/webpent/persistence/",
    "src/webpent/profiles/",
    "src/webpent/security_models/",
    "src/webpent/validation/",
)

UMDR29_REPINNED_FILES = (
    "src/webpent/workers/__init__.py",
    "src/webpent/state/__init__.py",
    "src/webpent/graph/__init__.py",
    "src/webpent/api/__init__.py",
    "src/webpent/agents/__init__.py",
    "src/webpent/shared/__init__.py",
    "src/webpent/__init__.py",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str]] = []
    removed = 0
    repinned = 0
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, relpath = line.partition(" ")
        relpath = relpath.strip()
        if any(relpath.startswith(pkg) for pkg in UMDR29_ARCHIVED_PACKAGES):
            removed += 1
            continue
        absolute = REPO / relpath
        if not absolute.exists():
            print(f"FAIL-CLOSED: manifest entry missing from tree: {relpath}", file=sys.stderr)
            return 1
        current = sha256(absolute)
        if current != digest:
            if relpath in UMDR29_REPINNED_FILES:
                repinned += 1
                digest = current  # documented re-pin
            else:
                print(
                    f"FAIL-CLOSED: undeclared drift on frozen file {relpath} "
                    "(only the six UMDR29 docstring files may change)",
                    file=sys.stderr,
                )
                return 1
        if relpath in seen:
            print(f"FAIL-CLOSED: duplicate entry {relpath}", file=sys.stderr)
            return 1
        seen.add(relpath)
        entries.append((digest, relpath))

    if removed != 22:
        print(
            f"FAIL-CLOSED: expected to remove exactly 22 archived entries, removed {removed}",
            file=sys.stderr,
        )
        return 1
    if repinned != 7:
        print(
            f"FAIL-CLOSED: expected exactly 7 re-pinned files (6 docstring "
            "corrections + the 0.35.0 version bump in src/webpent/__init__.py), "
            f"got {repinned}",
            file=sys.stderr,
        )
        return 1
    if len(entries) < 630:
        print(
            f"FAIL-CLOSED: manifest floor violated ({len(entries)} < 630)",
            file=sys.stderr,
        )
        return 1

    # self-check: re-hash every kept entry from disk before write
    for digest, relpath in entries:
        if sha256(REPO / relpath) != digest:
            print(f"FAIL-CLOSED: self-check mismatch for {relpath}", file=sys.stderr)
            return 1

    MANIFEST.write_text(
        "\n".join(f"{digest}  {relpath}" for digest, relpath in entries) + "\n",
        encoding="utf-8",
    )
    print(f"OK: {len(entries) + removed} -> {len(entries)} entries "
          f"({removed} archived removed, {repinned} re-pinned "
          "[6 docstrings + version bump])")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

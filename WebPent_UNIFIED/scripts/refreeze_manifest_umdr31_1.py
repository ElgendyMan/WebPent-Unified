#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-31.1 intelligence &
engineering uplift window (2026-11-08) per the DR-009 protocol.

Documented scope of this refreeze (see DRIFT_REGISTER.md, UM-DR-31.1):

  * RE-PINNED — exactly three frozen files, each verified by its new
    regression tests BEFORE this re-pin:

      1. src/webpent/__init__.py — the 0.37.0 -> 0.37.1 version bump
         (byte change = the __version__ line only, the UM-DR-29/30/31
         precedent).
      2. src/webpent/coverage/gap_detector.py — the R6/F20
         documentation of the fail-closed "unknown_status" contract
         (the _OPEN set is unchanged in MEMBERSHIP; only the
         deliberate-exclusion comment was added — no behavioral delta).
      3. src/webpent/shared/coverage_ledger.py — the R6/F20 fail-closed
         projection: producer aliases ("not_observed"/"tested") map to
         "not_scanned"; ANY other unrecognized raw status projects to
         the explicit, observable NON-gap "unknown_status" instead of
         silently becoming an actionable research opportunity.

Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr31_1.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR31_1_REPINNED_FILES = (
    "src/webpent/__init__.py",
    "src/webpent/coverage/gap_detector.py",
    "src/webpent/shared/coverage_ledger.py",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = [
        line.strip()
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    entries: list[tuple[str, str]] = []
    repinned = 0
    for line in lines:
        digest, _, relpath = line.partition("  ")
        relpath = relpath.strip()
        if relpath in UMDR31_1_REPINNED_FILES:
            new_digest = sha256(REPO / relpath)
            if new_digest != digest:
                repinned += 1
            entries.append((new_digest, relpath))
        else:
            entries.append((digest, relpath))
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
    print(f"OK: {len(entries)} entries unchanged in count, {repinned} re-pinned "
          "(the UM-DR-31.1 uplift window: version bump + F20 fail-closed contract)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

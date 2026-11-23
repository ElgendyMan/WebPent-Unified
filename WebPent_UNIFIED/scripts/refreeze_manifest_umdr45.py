#!/usr/bin/env python3
"""UM-DR-45 declared window re-freeze (directive §16 discipline).

Re-pins the files thawed for the UM-DR-45 window
(UMDR45_20261123_THAW_PATHS — the K3/K4 startup-gate window) and pins
the NEW trust-chain file of this window
(tests/test_umdr45_k4_auth_startup_gate.py is a test, not pinned;
scripts/generate_sbom.py carries the R1 SBOM adjudicator), restoring
byte-identity enforcement for the whole window, exactly like
scripts/refreeze_manifest_umdr43c.py did for the UMDR-43C window.

Run from the repo root (WebPent_UNIFIED/) AFTER the window's regression
proof is green. Idempotent: running it twice produces the same manifest.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "frozen_modules.sha256"

# The UM-DR-45 window delta: the thawed K3/K4 files re-pinned + the new
# R1 SBOM adjudicator pinned for the first time.
REFREEZE_PATHS = (
    "src/webpent/api/auth.py",
    "src/webpent/shared/preflight.py",
    "src/webpent/jsintel/api_surface_shadow.py",
    # R2 (CI run #40): the declared-target contract repair in the raw
    # h2 dial — thawed mid-window, re-pinned here at window close.
    "src/webpent/shared/h2_race.py",
    "scripts/generate_sbom.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not MANIFEST.exists():
        print("refreeze_umdr45: FAIL — frozen manifest missing")
        return 1
    entries: dict[str, str] = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, relpath = line.partition("  ")
        entries[relpath] = digest

    changes: list[str] = []
    for relpath in REFREEZE_PATHS:
        absolute = REPO / relpath
        if not absolute.exists():
            print(f"refreeze_umdr45: FAIL — {relpath} missing")
            return 1
        digest = _sha256(absolute)
        if entries.get(relpath) != digest:
            action = "pinned (new)" if relpath not in entries else "re-pinned"
            entries[relpath] = digest
            changes.append(f"{action}: {relpath}")

    if not changes:
        print("refreeze_umdr45: manifest already current — nothing to do")
        return 0

    MANIFEST.write_text(
        "".join(f"{digest}  {relpath}\n" for relpath, digest in sorted(entries.items())),
        encoding="utf-8",
    )
    for line in changes:
        print(f"refreeze_umdr45: {line}")
    print(f"refreeze_umdr45: manifest rewritten — {len(changes)} change(s), {len(entries)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())

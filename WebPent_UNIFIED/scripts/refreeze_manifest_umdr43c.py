#!/usr/bin/env python3
"""UM-DR-43C declared window re-freeze (directive §16 discipline).

Re-pins ``src/webpent/state/reducers.py`` (the ONE file thawed for the
hypothesis-lifecycle contract, UMDR43C_20261121_THAW_PATHS) and adds
the NEW trust-chain file ``src/webpent/production/hypothesis_identity.py``
to the frozen manifest — restoring byte-identity enforcement for the
whole window, exactly like scripts/refreeze_manifest_umdr42_closure.py
did for the UMDR42 scope window.

Run from the repo root (WebPent_UNIFIED/) AFTER the window's
regression proof (tests/test_umdr43c_lifecycle.py and the full suite)
is green. Idempotent: running it twice produces the same manifest.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "frozen_modules.sha256"

# The UMDR-43C window delta: one thawed file re-pinned + one new file
# pinned for the first time.
REFREEZE_PATHS = (
    "src/webpent/state/reducers.py",
    "src/webpent/production/hypothesis_identity.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not MANIFEST.exists():
        print("refreeze_umdr43c: FAIL — frozen manifest missing")
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
            print(f"refreeze_umdr43c: FAIL — {relpath} missing")
            return 1
        digest = _sha256(absolute)
        if entries.get(relpath) != digest:
            action = "pinned (new)" if relpath not in entries else "re-pinned"
            entries[relpath] = digest
            changes.append(f"{action}: {relpath}")

    if not changes:
        print("refreeze_umdr43c: already frozen (no changes)")
        return 0

    lines = [f"{digest}  {relpath}" for relpath, digest in entries.items()]
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")
    for change in changes:
        print(f"refreeze_umdr43c: {change}")
    print(f"refreeze_umdr43c: manifest updated ({len(entries)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

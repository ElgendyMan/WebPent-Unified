#!/usr/bin/env python3
"""UM-DR-40b window close — re-freeze the thawed file (strategist).

Follows the declared-refreeze convention (refreeze_manifest_umdr31/
umdr40/… precedents): the thawed file's changes were verified by the
window's regression tests BEFORE the re-pin
(tests/test_umdr40_rc6_rc7_decision_ledger.py), the manifest update
lists exactly the re-pinned files, and the result is re-hashed from
disk before write (self-verifying).

UM-DR-40b (2026-11-18) — the window's only frozen-file change:

  src/webpent/agents/strategist/agent.py —
    1. RC-7: record_coverage carries the ranked runner-up slice
       (alternatives_considered: bounded top-5 with scores) from
       production/decision_ledger.ranked_alternatives;
    2. RC-6: the decision batch records its MEASURED information
       gain (before/after pool difference via
       decision_ledger.information_gain_snapshot; RC-5's
       deterministic generation-time ids make the difference stable)
       as a "prioritization" decision entry
       (rule_fired=umdr40_rc6_measured_information_gain).

The 39 register's RC-6 constraint — "adapted INTO the strategist,
not a parallel orchestrator" — is exactly what this thaw enables.

Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr40b.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR40B_REPINNED_FILES = (
    "src/webpent/agents/strategist/agent.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not MANIFEST.exists():
        print(f"[refreeze-umdr40b] manifest missing: {MANIFEST}")
        return 1
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    pinned = {
        parts[1]: parts[0]
        for parts in (line.split(maxsplit=1)
                      for line in lines if line.strip())
    }
    changes: list[tuple[str, str, str]] = []
    for relpath in UMDR40B_REPINNED_FILES:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"[refreeze-umdr40b] MISSING file: {relpath}")
            return 1
        new_hash = _sha256(absolute)
        old_hash = pinned.get(relpath)
        if old_hash == new_hash:
            print(f"[refreeze-umdr40b] UNCHANGED (already pinned): "
                  f"{relpath}")
            continue
        pinned[relpath] = new_hash
        changes.append((relpath, old_hash or "-", new_hash))
    if not changes:
        print("[refreeze-umdr40b] nothing to re-pin — manifest "
              "already current for this window's files")
        return 0
    out_lines = [
        f"{pinned[line.split(maxsplit=1)[1]]}  "
        f"{line.split(maxsplit=1)[1]}"
        if line.split(maxsplit=1)[1] in {
            rel for rel, _, _ in changes}
        else line
        for line in lines if line.strip()
    ]
    MANIFEST.write_text(chr(10).join(out_lines) + "\n",
                        encoding="utf-8")
    verify = {
        parts[1]: parts[0]
        for parts in (line.split(maxsplit=1)
                      for line in
                      MANIFEST.read_text(encoding="utf-8")
                      .splitlines() if line.strip())
    }
    for relpath, old_hash, new_hash in changes:
        on_disk = _sha256(REPO / relpath)
        assert verify[relpath] == on_disk == new_hash, relpath
        print(f"[refreeze-umdr40b] re-pinned {relpath}: "
              f"{old_hash[:12]} -> {new_hash[:12]} (verified)")
    print(f"[refreeze-umdr40b] manifest updated: {MANIFEST} "
          f"({len(changes)} file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())

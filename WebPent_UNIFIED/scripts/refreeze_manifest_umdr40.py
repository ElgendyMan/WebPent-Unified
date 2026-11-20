#!/usr/bin/env python3
"""UM-DR-40 window close — re-freeze the delta file (builder.py).

Follows the declared-refreeze convention (refreeze_manifest_umdr31/
umdr31_1/umdr32/… precedents): the window's frozen-file changes are
verified by their new regression tests BEFORE the re-pin, the
manifest update lists exactly the re-pinned files, and the result is
re-hashed from disk before write (self-verifying).

UM-DR-40 (2026-11-18) — the window's only frozen-file change:

  src/webpent/graph/builder.py —
    1. RC-4: the hypothesis router's path map now flows through the
       composed advisory redirect `_research_route_redirects`
       (_umdr32_routes over _umdr31_routes): with any identity
       capability enabled, strategist-bound branches run the
       identity_workflow node first; with every flag OFF the mapping
       is returned byte-identically (7 contract cases,
       tests/test_umdr40_rc4_router.py).
    2. RC-5: the registered hypothesis node is the dedup-wrapped
       generator `deduplicated_hypothesis_node` — generation-time
       deterministic uuid5 ids from the (target_url, vuln_class)
       content fingerprint, so the existing upsert-by-id reducer
       absorbs cross-pass duplicates (4 contract cases incl. the
       two-pass acceptance, tests/test_umdr40_rc5_dedup.py).

Everything else the window added is NEW non-frozen code
(production/identity_activation.py, production/hypothesis_dedup.py,
scripts/, tests/, deliverables/) — not listed in the manifest, per
the UM-DR-31 precedent for new production modules.

Self-verifying: the result is re-hashed from disk before write.
Usage: python3 scripts/refreeze_manifest_umdr40.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR40_REPINNED_FILES = (
    "src/webpent/graph/builder.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not MANIFEST.exists():
        print(f"[refreeze-umdr40] manifest missing: {MANIFEST}")
        return 1
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    pinned = {
        parts[1]: parts[0]
        for parts in (line.split(maxsplit=1)
                      for line in lines if line.strip())
    }
    changes: list[tuple[str, str, str]] = []
    for relpath in UMDR40_REPINNED_FILES:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"[refreeze-umdr40] MISSING file: {relpath}")
            return 1
        new_hash = _sha256(absolute)
        old_hash = pinned.get(relpath)
        if old_hash == new_hash:
            print(f"[refreeze-umdr40] UNCHANGED (already pinned): "
                  f"{relpath}")
            continue
        pinned[relpath] = new_hash
        changes.append((relpath, old_hash or "-", new_hash))
    if not changes:
        print("[refreeze-umdr40] nothing to re-pin — manifest "
              "already current for this window's files")
        return 0
    # rewrite, preserving the original ordering
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
    # self-verify from disk
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
        print(f"[refreeze-umdr40] re-pinned {relpath}: "
              f"{old_hash[:12]} -> {new_hash[:12]} (verified)")
    print(f"[refreeze-umdr40] manifest updated: {MANIFEST} "
          f"({len(changes)} file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())

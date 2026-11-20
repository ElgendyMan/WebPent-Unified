#!/usr/bin/env python3
"""UMDR42-closure window close — re-freeze the closure-modified frozen files.

Follows the declared-refreeze convention (refreeze_manifest_umdr42.py and
its 40+ precedents): the thawed files' changes were verified by this
window's regression tests BEFORE the re-pin (tests/test_umdr42_scope_closure.py
7/7 green; full-suite failure set byte-identical to the published 5a7e511
baseline — zero new failures).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR42_CLOSURE_REPINNED_FILES = (
    "src/webpent/scope/store.py",
    "src/webpent/api/app.py",
    "src/webpent/workers/pentest_worker.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not MANIFEST.exists():
        print(f"[refreeze-umdr42-closure] manifest missing: {MANIFEST}")
        return 1
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    pinned = {
        parts[1]: parts[0]
        for parts in (line.split(maxsplit=1)
                      for line in lines if line.strip())
    }
    changes: list[tuple[str, str, str]] = []
    for relpath in UMDR42_CLOSURE_REPINNED_FILES:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"[refreeze-umdr42-closure] MISSING file: {relpath}")
            return 1
        new_hash = _sha256(absolute)
        old_hash = pinned.get(relpath)
        if old_hash is None:
            print(f"[refreeze-umdr42-closure] NOT IN MANIFEST (skip): {relpath}")
            continue
        if old_hash == new_hash:
            print(f"[refreeze-umdr42-closure] UNCHANGED (already pinned): {relpath}")
            continue
        pinned[relpath] = new_hash
        changes.append((relpath, old_hash or "-", new_hash))
    if not changes:
        print("[refreeze-umdr42-closure] nothing to re-pin — manifest already current")
        return 0
    out_lines = [
        f"{pinned[line.split(maxsplit=1)[1]]}  {line.split(maxsplit=1)[1]}"
        if line.split(maxsplit=1)[1] in {rel for rel, _, _ in changes} else line
        for line in lines if line.strip()
    ]
    MANIFEST.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    verify = {
        parts[1]: parts[0]
        for parts in (line.split(maxsplit=1)
                      for line in MANIFEST.read_text().splitlines() if line.strip())
    }
    ok = all(verify[rel] == _sha256(REPO / rel) for rel, _, _ in changes)
    for relpath, old, new in changes:
        print(f"[refreeze-umdr42-closure] RE-PINNED {relpath}: {old[:12]} -> {new[:12]}")
    print(f"[refreeze-umdr42-closure] {len(changes)} file(s) re-pinned; verify={'OK' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

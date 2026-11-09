#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the M3 window 2 tenant_isolation
qualification seam (2026-11-06) per the DR-009 protocol. DRIFT_REGISTER
entry: UM-DR-17 (seam part; runs after the ف3.2 part re-pinned settings.py).

The window declares EXACTLY these frozen-tree changes (each verified by
new regression tests run BEFORE this refreeze —
tests/test_m3_family_qualification_seam.py, 11 tests green):

  - src/webpent/config/settings.py
    (M3 UM-DR-17: the ``enable_family_execution_spine`` flag — fail-closed
    default False; second declared change to this file within the M3
    window 2, after enable_js_ast_reversing)

  - src/webpent/graph/builder.py
    (M3 UM-DR-17: ``_family_execution_enabled()`` fail-closed helper +
    the flag-gated ``wire_family_execution(graph)`` call before compile —
    the causal family execution spine (six passive analyzers incl.
    tenant_isolation, deterministic validators, ProofBundle sealing,
    promotion) gains its first production-builder caller; additive-only
    edges: the direct sandbox→validator edge survives)

  - src/webpent/families/execution_node.py
    (M3 UM-DR-17: family_execution_node derives endpoint_inventory /
    multi_tenant / auth_flows from the REAL PentestState channels via the
    new non-frozen ``shared/family_feeds.py`` adapter when the direct
    channels are absent — closing the M0 ب6-pattern "passive wrappers
    waiting for data nobody provides"; derivation observable via
    ``family_feeds_derived`` in the output)

  * NO manifest-path removals; NO scope completions (shared/family_feeds.py
    and the test file are new files OUTSIDE the frozen gate by
    construction);
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_m3_family_seam.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

# Run AFTER the edits — hashes re-read from the current tree.
WINDOW_CHANGED_FILES = [
    "src/webpent/config/settings.py",
    "src/webpent/graph/builder.py",
    "src/webpent/families/execution_node.py",
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
        new_digest = sha256(absolute)
        if new_digest != digest:
            if relpath not in WINDOW_CHANGED_FILES and relpath not in WINDOW_SCOPE_COMPLETION:
                print(
                    f"ABORT: undeclared change detected in pinned file: {relpath}",
                    file=sys.stderr,
                )
                return 1
            changed_count += 1
            print(f"  re-pinned: {relpath}")
        out_lines.append(f"{new_digest}  {relpath}")

    # Self-check: exactly the declared window drifted.
    if changed_count != len(WINDOW_CHANGED_FILES):
        print(
            f"ABORT: expected exactly {len(WINDOW_CHANGED_FILES)} re-pinned "
            f"entries, found {changed_count}",
            file=sys.stderr,
        )
        return 1
    if len(out_lines) != len(entries):
        print("ABORT: output line count mismatch", file=sys.stderr)
        return 1

    MANIFEST.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    # Post-write self-check: re-read and verify every entry byte-identical.
    verification_failures: list[str] = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, relpath = line.split(None, 1)
        absolute = REPO / relpath.strip()
        if not absolute.is_file() or sha256(absolute) != digest:
            verification_failures.append(relpath.strip())
    if verification_failures:
        print(
            f"ABORT: post-write self-check failed for: {verification_failures}",
            file=sys.stderr,
        )
        return 1

    print(f"OK: manifest re-frozen with exactly {changed_count} declared changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the M3 window 2 OAST + campaign
resume production wiring (2026-11-06) per the DR-009 protocol.
DRIFT_REGISTER entry: UM-DR-17 (OAST/campaign-resume part).

The window declares EXACTLY these frozen-tree changes (each verified by
new regression tests run BEFORE this refreeze —
tests/test_m3_oast_campaign_resume_wiring.py, 15 tests green):

  - src/webpent/graph/builder.py
    (M3 UM-DR-17: ``_oast_enabled()`` fail-closed helper + the
    flag-gated ``wire_oast_correlation(graph)`` call before compile —
    the OAST correlation node (graph/oast_nodes.py, non-frozen) gains
    its production wiring: post_exploitation→oast_correlation→
    rabbit_hole additive-only, the direct edge stays; second declared
    change to this file within M3 window 2)

  - src/webpent/workers/pentest_worker.py
    (M3 UM-DR-17: campaign-resume wiring — the soft-timeout and
    recursion-limit handlers write the flag-gated interrupt marker via
    production/campaign_lifecycle.py (non-frozen; soft_time_limit is
    resumable, recursion_limit is forensic-only by the package's
    reason vocabulary); the terminal exit clears the marker so a stale
    crash mark can never auto-resume a finished engagement; second
    declared change to this file within M3 window 2)

  * NO manifest-path removals; NO scope completions (graph/oast_nodes.py,
    production/campaign_lifecycle.py and the test file are new files
    OUTSIDE the frozen gate by construction);
  * enable_oast / enable_campaign_resume were already declared in M1-C
    (UM-DR-12) — settings.py is NOT part of this window;
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_m3_oast_resume.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

WINDOW_CHANGED_FILES = [
    "src/webpent/graph/builder.py",
    "src/webpent/workers/pentest_worker.py",
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

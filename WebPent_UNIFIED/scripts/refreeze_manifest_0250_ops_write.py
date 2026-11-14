#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the OPS WRITE + WORKER CLAIMS
window (v0.25.0) per the DR-009 protocol:

  * same path set + same order — every existing entry's hash is
    recomputed from the current tree (fail-closed on a missing file);
  * the window's TWO new src files (campaign_worker_claims.py,
    ops_state.py) are appended as the documented scope completion;
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_0250_ops_write.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

# The 0.25.0 scope completion (must match
# OPS_WRITE_20261028_SCOPE_COMPLETION_PATHS in the gate test).
WINDOW_SCOPE_COMPLETION = [
    "src/webpent/production/campaign_worker_claims.py",
    "src/webpent/production/ops_state.py",
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

    for relpath in WINDOW_SCOPE_COMPLETION:
        if relpath in seen:
            continue
        entries.append(("NEW", relpath))
        seen.add(relpath)

    out_lines: list[str] = []
    for digest, relpath in entries:
        absolute = REPO / relpath
        if not absolute.is_file():
            print(f"ABORT: pinned path missing from tree: {relpath}", file=sys.stderr)
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
    print(f"manifest re-frozen: {len(out_lines)} entries "
          f"(+{len(WINDOW_SCOPE_COMPLETION)} scope completion)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

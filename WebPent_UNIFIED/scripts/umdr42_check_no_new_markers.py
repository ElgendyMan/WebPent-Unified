#!/usr/bin/env python3
"""UMDR42 D3 — no-new-markers ratchet.

Fails (exit 1) if any TODO/FIXME/XXX/HACK comment marker exists in
src/ beyond the classified allowlist in docs/backlog/TODO_REGISTER.md.
Run from the repo root (WebPent_UNIFIED). Wired into CI as part of the
UMDR42 audit-ratchet job.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

ALLOWLIST = {
    # (file, line) pairs of the two classified non-marker occurrences
    ("src/webpent/brain/curiosity.py", 97),
    ("src/webpent/shared/canonical_json.py", 12),
}

MARKER = re.compile(r"#.*\b(TODO|FIXME|XXX|HACK)\b")


def main() -> int:
    offenders: list[tuple[str, int, str]] = []
    for py in SRC.rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        rel = str(py.relative_to(ROOT))
        try:
            for i, line in enumerate(
                    py.read_text(encoding="utf-8",
                                 errors="replace").splitlines(), 1):
                if MARKER.search(line) and (rel, i) not in ALLOWLIST:
                    offenders.append((rel, i, line.strip()[:80]))
        except OSError:
            continue
    if offenders:
        print(f"FAIL: {len(offenders)} new TODO/FIXME/XXX/HACK marker(s):")
        for rel, i, text in offenders:
            print(f"  {rel}:{i}: {text}")
        print("Resolve or classify them in docs/backlog/TODO_REGISTER.md.")
        return 1
    print("OK: zero unclassified TODO/FIXME/XXX/HACK markers in src/")
    return 0


if __name__ == "__main__":
    sys.exit(main())

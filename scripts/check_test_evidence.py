#!/usr/bin/env python3
"""Fail closed when a test run has no complete machine-generated evidence."""
from __future__ import annotations

from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / "docs" / "FULL_SUITE_EVIDENCE.txt"
REQUIRED_MARKERS = (
    "# Test Run Evidence",
    "# --- PYTEST OUTPUT ---",
    "# --- SUMMARY ---",
    "# Total:",
    "# New failures vs baseline:",
    "# Exit code:",
)


def main() -> int:
    if not EVIDENCE.is_file():
        print(f"FAIL: missing {EVIDENCE}")
        return 1
    text = EVIDENCE.read_text(encoding="utf-8")
    missing = [marker for marker in REQUIRED_MARKERS if marker not in text]
    if missing:
        print("FAIL: missing evidence markers: " + ", ".join(missing))
        return 1
    print(f"OK: complete test evidence present ({EVIDENCE})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

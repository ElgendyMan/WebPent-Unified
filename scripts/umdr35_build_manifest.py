#!/usr/bin/env python3
"""UM-DR-35.8 — regenerable frozen-file manifest digest.

BUILD_INFO.json's ``manifest_digest_v9`` is the SHA-256 over the canonical
frozen-file manifest: the sorted (relative_path, sha256) pairs of the
identity-bearing frozen files. The digest is REGENERABLE by running this
script — it is never a manufactured constant.

Frozen set (identity-bearing, deliberately minimal and stable):
  * pyproject.toml        — package version + dependency pins
  * uv.lock               — dependency lock identity
  * scripts/test_count_floor.json — preserved test-count floor
  * BASELINE.sha256.txt   — frozen module baseline

Usage:
  python scripts/umdr35_build_manifest.py            # print digest
  python scripts/umdr35_build_manifest.py --check X  # verify digest X
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FROZEN_FILES = (
    "pyproject.toml",
    "uv.lock",
    "scripts/test_count_floor.json",
    "BASELINE.sha256.txt",
)


def canonical_manifest() -> str:
    lines = []
    for rel in sorted(FROZEN_FILES):
        path = ROOT / rel
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{rel}  {digest}")
    return "\n".join(lines) + "\n"


def manifest_digest_v9() -> str:
    return hashlib.sha256(canonical_manifest().encode("utf-8")).hexdigest()


def main() -> int:
    if len(sys.argv) > 2 and sys.argv[1] == "--check":
        expected = sys.argv[2].strip().lower()
        actual = manifest_digest_v9()
        if expected == actual:
            print(f"manifest_digest_v9 VERIFIED: {actual}")
            return 0
        print(f"manifest_digest_v9 MISMATCH: expected={expected} actual={actual}")
        return 1
    print(manifest_digest_v9())
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""DEPRECATED shim — UM-DR-32 §3.1 portability remediation.

The UM-DR-31.1 builder computed its project prefix as
``str(REPO.relative_to(GIT_ROOT)) + "/"`` which produces ``"./"`` when
the project root IS the Git root; ``git ls-tree`` never returns
``./``-prefixed paths, so the payload filter matched nothing and the
builder aborted (or, in any variant without the abort check, would
have emitted an empty archive).

The canonical corrected implementation is
``scripts/build_release_archive.py`` (root layout + nested monorepo
layout, explicit documented exclusion policy, deterministic output,
full post-build verification). This shim keeps the historical entry
point working and simply delegates.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_release_archive import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())

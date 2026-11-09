"""Release packaging gates (v78, Task 4): version sync + install smoke."""

from __future__ import annotations

import re
from pathlib import Path

import webpent

WORK = Path(__file__).resolve().parents[1]


def test_version_sources_agree() -> None:
    pyproject = (WORK / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert match is not None, "pyproject.toml has no version line"
    assert match.group(1) == webpent.__version__
    # RESIDUAL CLOSURE 2026-10-29: the hard-coded "0.14.0" pin was a
    # fossil — every window since 0.15.0 had to either bump it (and
    # didn't) or watch this gate fail. The CONTRACT is the agreement of
    # the sources, not a pinned literal; the release window asserts its
    # own version in the changelog-head check below.
    # G-1 REMOVAL window (0.29.0, 2026-10-31): the 0.28.0 window had
    # reintroduced a fossil pin ("== 0.28.0") in this gate — removed
    # again per the same SSOT doctrine: a pinned literal makes every
    # future window edit this gate for no protective gain (the dynamic
    # pyproject<->__init__ agreement above plus the changelog-head check
    # below already catch a stale identity).


def test_changelog_leads_with_current_version() -> None:
    changelog = (WORK / "CHANGELOG.md").read_text(encoding="utf-8")
    first_heading = next(
        line for line in changelog.splitlines() if line.startswith("## ")
    )
    assert webpent.__version__ in first_heading
    # The changelog head must carry its own release date (kept dynamic —
    # the fossil date pin had the same staleness problem as the version).
    assert re.search(r"\d{4}-\d{2}-\d{2}", first_heading)


def test_console_script_declared() -> None:
    pyproject = (WORK / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r"webpent\s*=\s*\"webpent", pyproject), (
        "console script entry missing"
    )

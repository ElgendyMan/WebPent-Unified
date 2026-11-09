#!/usr/bin/env python3
"""RETIRED-ALIAS REMOVAL window (v0.32.0) — one-shot surgical edit of
``src/webpent/cli/commands.py``.

Removes the three retired CLI commands declared for removal in the
0.30.0 CHANGELOG (item ج.2, scheduled removal window v0.32.0):

  * ``scan``       (lines 528-1188 — the legacy full-engagement command),
  * ``hunt-plan``  (lines 1515-1627 — the retired planner alias),
  * ``hunt-auto``  (lines 1717-1940 — the retired bounded-hunter alias),
  * ``_parse_report_formats`` (lines 422-436 — helper whose only caller
    was the removed ``scan`` command; its direct unit-test assertions in
    tests/test_operations_ux_upgrade.py are trimmed in the same window),

and rewrites the module docstring's usage examples to point at the
unified ``hunt`` command. Fail-closed: every deletion range is anchored
by exact expected content before anything is written.
"""
from __future__ import annotations

from pathlib import Path

TARGET = Path(__file__).resolve().parents[1] / "src/webpent/cli/commands.py"

# (start_line_1based, end_line_inclusive, anchor_substring_that_must_appear)
DELETIONS = [
    (422, 436, "def _parse_report_formats("),
    (528, 1188, "def scan("),
    (1515, 1627, 'def hunt_plan('),
    (1717, 1940, "def hunt_auto("),
]

DOCSTRING_OLD = """Usage:
    webpent scan --url https://target.com
    webpent scan --url https://target.com --creds admin:password
    webpent scan --url https://target.com --creds admin:password --auto-approve
    webpent scan --url https://target.com --cookies "PHPSESSID=abc123; security=low"
    webpent scan --url https://target.com --portswigger
    webpent preflight
"""
DOCSTRING_NEW = """Usage (the unified entry point — the retired scan/hunt-auto/hunt-plan
aliases were removed in the v0.32.0 window, declared 2026-11-01):
    webpent hunt --url https://target.com --mode standard --authorization <ref>
    webpent hunt --url https://target.com --mode quick --authorization <ref>
    webpent hunt --url https://target.com --mode deep --authorization <ref>
    webpent preflight
"""


def main() -> int:
    lines = TARGET.read_text(encoding="utf-8").splitlines(keepends=True)
    text = "".join(lines)

    # Fail-closed anchors: every range must contain its marker, and the
    # line BEFORE each start must be blank (command boundary hygiene).
    for start, end, marker in DELETIONS:
        chunk = "".join(lines[start - 1 : end])
        if marker not in chunk:
            print(f"ABORT: anchor {marker!r} not in lines {start}-{end}")
            return 1
    for start, _end, _m in DELETIONS:
        if lines[start - 2].strip():
            print(f"ABORT: line before {start} is not blank: {lines[start-2]!r}")
            return 1
    if DOCSTRING_OLD not in text:
        print("ABORT: docstring usage block not found verbatim")
        return 1

    # Sanity: the kept neighbors must be present.
    for must_keep in (
        "def preflight(",
        "def hunt(",
        'def graph_command(',
        "def _chain_honesty_verdict(",
        "def _enforce_chain_honesty(",
        "def _load_hunter_principals(",
    ):
        if must_keep not in text:
            print(f"ABORT: expected keeper {must_keep!r} missing before edit")
            return 1

    lines = text.splitlines(keepends=True)

    # Delete in reverse order so earlier ranges stay valid. The docstring
    # replacement happens AFTER the deletions (it changes line numbering).
    for start, end, marker in sorted(DELETIONS, reverse=True):
        chunk = "".join(lines[start - 1 : end])
        if marker not in chunk:
            print(f"ABORT (pre-delete): anchor {marker!r} lost at {start}-{end}")
            return 1
        del lines[start - 1 : end]

    out = "".join(lines)
    if DOCSTRING_OLD not in out:
        print("ABORT (post-delete): docstring usage block not found verbatim")
        return 1
    out = out.replace(DOCSTRING_OLD, DOCSTRING_NEW)
    # Collapse blank-line runs longer than the 2-blank pycodestyle ceiling
    # created by the deletion seams. The pre-edit file was ruff-clean, so
    # no legitimate 3+ blank run existed before this window.
    import re as _re

    out = _re.sub(r"\n{4,}", "\n\n\n", out)
    # Post-conditions: removed symbols are gone, kept ones survive.
    for gone in ("def scan(", "def hunt_plan(", "def hunt_auto(", "_parse_report_formats"):
        if gone in out:
            print(f"ABORT (post-check): {gone!r} still present")
            return 1
    for keep in ("def preflight(", "def hunt(", "def _chain_honesty_verdict(", "def _enforce_chain_honesty("):
        if keep not in out:
            print(f"ABORT (post-check): keeper {keep!r} lost")
            return 1

    TARGET.write_text(out, encoding="utf-8")
    print(
        "OK: commands.py edited — 3 retired commands + 1 scan-only helper "
        f"removed ({len(text.splitlines())} -> {len(lines)} lines)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

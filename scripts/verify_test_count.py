#!/usr/bin/env python3
"""Fail if the repository loses the minimum preserved test count.

Sprint I-1b, item 1.2: the old design hand-typed a `--minimum 498`
literal into ci.yml, which the repo's own logs show disagreeing with six
OTHER hand-counted figures scattered across docs/summaries (seven total,
never matching) -- every one a human manually recounting at a different
time, from a different vantage point (raw `def test_*` functions vs.
actual collected test items, which diverge as soon as any
`@pytest.mark.parametrize` is used, since one function expands into N
collected items).

Fix: the authoritative count is now pytest's OWN `--collect-only` count
-- the real number of test items that will actually run, not a proxy for
it -- collected fresh, in-job, every run. The floor itself lives in a
single checked-in file (`scripts/test_count_floor.json`), never as an
inline CLI literal, and is only ever changed by explicitly re-running
this script with `--update` (a deliberate, reviewable diff), never by
hand-editing a number.

The old AST-based per-file walk is kept as supplementary diagnostic
output only (useful to see which files hold how many raw test
functions) -- it is no longer the number the floor gates on.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_FLOOR_FILE = Path(__file__).parent / "test_count_floor.json"

_COLLECTED_RE = re.compile(r"(\d+)\s+tests?\s+collected", re.IGNORECASE)
_COLLECTED_WITH_ERRORS_RE = re.compile(
    r"(\d+)\s+tests?\s+collected.*?(\d+)\s+errors?", re.IGNORECASE)


def count_test_functions(root: Path) -> tuple[int, dict[str, int]]:
    """Supplementary diagnostic only -- see module docstring for why this
    is no longer the gating number."""
    total = 0
    per_file: dict[str, int] = {}
    for path in sorted(root.rglob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except OSError as exc:
            raise SystemExit(f"cannot read test file {path}: {exc}") from exc
        count = sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            for node in ast.walk(tree)
        )
        if count:
            relative = str(path.relative_to(root.parent))
            per_file[relative] = count
            total += count
    return total, per_file


def real_collected_count(tests_dir: Path) -> int:
    """The authoritative count: actually ask pytest how many test items
    it collects, exactly as it will run them (parametrize expansion,
    skips-still-collected, etc. all accounted for correctly, unlike a
    raw AST function walk)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", str(tests_dir)],
        capture_output=True, text=True,
    )
    output = proc.stdout + proc.stderr
    match = _COLLECTED_WITH_ERRORS_RE.search(output)
    if match:
        raise SystemExit(
            f"pytest --collect-only reported {match.group(2)} collection error(s) "
            f"alongside {match.group(1)} collected tests -- fix collection errors "
            "before trusting this count:\n" + output[-2000:]
        )
    match = _COLLECTED_RE.search(output)
    if not match:
        raise SystemExit(
            "could not parse a 'N tests collected' line from pytest --collect-only "
            "output -- pytest's own summary format may have changed:\n" + output[-2000:]
        )
    return int(match.group(1))


def load_floor(floor_file: Path) -> int:
    if not floor_file.exists():
        raise SystemExit(
            f"floor file {floor_file} does not exist -- run with --update once to "
            "create it from today's real collected count."
        )
    return json.loads(floor_file.read_text(encoding="utf-8"))["minimum"]


def write_floor(floor_file: Path, minimum: int) -> None:
    floor_file.write_text(
        json.dumps({"minimum": minimum}, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", type=Path, default=Path("tests"))
    parser.add_argument(
        "--floor-file", type=Path, default=DEFAULT_FLOOR_FILE,
        help="Checked-in file holding the current floor (never hand-edit this number).",
    )
    parser.add_argument(
        "--update", action="store_true",
        help="Regenerate the floor file from today's real collected count and exit "
             "(run this deliberately after intentionally adding tests; produces a "
             "reviewable diff instead of a hand-typed number).",
    )
    args = parser.parse_args()

    current = real_collected_count(args.tests)
    _, per_file = count_test_functions(args.tests)

    if args.update:
        write_floor(args.floor_file, current)
        print(f"Floor file {args.floor_file} updated to {current} (from real pytest collection).")
        return 0

    minimum = load_floor(args.floor_file)
    payload = {
        "pytest_collected_count": current,
        "ast_raw_function_count": sum(per_file.values()),
        "minimum": minimum,
        "files": per_file,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    if current < minimum:
        print(f"ERROR: pytest-collected test count {current} is below floor {minimum}")
        return 1
    print(f"OK: pytest-collected test count {current} >= floor {minimum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

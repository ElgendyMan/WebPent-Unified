#!/usr/bin/env python3
"""Coverage ratchet (Phase-4 ops item, 2026-11-04).

The honest-coverage contract, in three sentences: the floor lives in a
single checked-in file (``scripts/coverage_floor.json``); the ONLY way
to change it is re-running this script with ``--update`` after a real
measured run (a deliberate, reviewable diff — the same protocol as
``scripts/verify_test_count.py`` and the ruff ratchet); the floor can
move UP freely but a DOWNWARD update is refused unless ``--allow-lower``
is passed explicitly (a documented, visible decision — never a silent
relaxation).

Usage:
    # measure + enforce (CI / nightly canary):
    python scripts/coverage_ratchet.py --scope "tests/shared tests/dojo"

    # pin or raise the floor after a real run:
    python scripts/coverage_ratchet.py --scope "..." --update

The floor file records the scope it was measured on; a floor measured
on one scope is NEVER compared against a different scope (the script
refuses with a scope mismatch instead of reporting a fake regression).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FLOOR_PATH = REPO / "scripts" / "coverage_floor.json"

__all__ = ["main"]


def _load_floor() -> dict | None:
    if not FLOOR_PATH.exists():
        return None
    try:
        data = json.loads(FLOOR_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ABORT: coverage_floor.json unreadable: {exc}", file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(data, dict) or "minimum" not in data or "scope" not in data:
        print("ABORT: coverage_floor.json shape invalid", file=sys.stderr)
        raise SystemExit(2)
    return data


def _run_coverage(scope: str) -> float:
    """Run pytest --cov on the scope; return the TOTAL coverage percent."""
    cmd = [
        sys.executable, "-m", "pytest",
        *scope.split(),
        "--cov=webpent",
        "--cov-report=json:/tmp/webpent_coverage.json",
        "-q",
        "--no-header",
        "-x",  # a red suite is not a coverage measurement
        "-p", "no:cacheprovider",
    ]
    print(f"  running: {' '.join(cmd[:6])} ... ({scope})")
    result = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    report_path = Path("/tmp/webpent_coverage.json")
    if not report_path.exists():
        print(result.stdout[-3000:], file=sys.stderr)
        print(result.stderr[-2000:], file=sys.stderr)
        print("ABORT: coverage report not produced (suite failed before reporting)", file=sys.stderr)
        raise SystemExit(3)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    total = report.get("totals", {}).get("percent_covered")
    if total is None:
        print("ABORT: coverage report has no total", file=sys.stderr)
        raise SystemExit(3)
    return round(float(total), 2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scope", required=True,
        help="pytest args selecting the measured suites, e.g. 'tests/shared tests/dojo'",
    )
    parser.add_argument(
        "--update", action="store_true",
        help="write the measured value as the new floor (up freely; down needs --allow-lower)",
    )
    parser.add_argument(
        "--allow-lower", action="store_true",
        help="explicit, documented permission to lower the floor",
    )
    args = parser.parse_args()

    floor = _load_floor()
    measured = _run_coverage(args.scope)
    print(f"  measured coverage: {measured}% (scope: {args.scope})")

    if args.update:
        if floor is not None and floor["scope"] != args.scope and not args.allow_lower:
            print(
                f"ABORT: floor exists for a DIFFERENT scope ({floor['scope']!r}); "
                "a floor is only comparable within its scope. Re-run with "
                "--allow-lower if the scope change is a documented decision.",
                file=sys.stderr,
            )
            return 2
        if floor is not None and measured < float(floor["minimum"]) and not args.allow_lower:
            print(
                f"ABORT: refusing to LOWER the floor {floor['minimum']} -> {measured}. "
                "The ratchet only moves up. Pass --allow-lower to record a "
                "documented downward decision.",
                file=sys.stderr,
            )
            return 2
        FLOOR_PATH.write_text(
            json.dumps(
                {"minimum": measured, "scope": args.scope, "updated_by": "scripts/coverage_ratchet.py"},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        direction = "pinned" if floor is None else (
            "raised" if measured > float(floor["minimum"]) else "re-recorded"
        )
        print(f"OK: floor {direction} at {measured}% for scope {args.scope!r}")
        return 0

    if floor is None:
        print(
            "SKIP: no coverage_floor.json yet — run once with --update after a "
            "real measured run to pin the floor."
        )
        return 0
    if floor["scope"] != args.scope:
        print(
            f"SKIP: floor is pinned for scope {floor['scope']!r}, this run used "
            f"{args.scope!r} — not comparable (scope mismatch is never a regression)."
        )
        return 0
    minimum = float(floor["minimum"])
    if measured + 1e-9 < minimum:
        print(
            f"FAIL: coverage {measured}% < floor {minimum}% — coverage regressed. "
            "Fix the loss, or run with --update --allow-lower for a documented "
            "downward decision.",
            file=sys.stderr,
        )
        return 1
    if measured > minimum:
        print(
            f"NOTE: coverage {measured}% > floor {minimum}% — run with --update "
            "to ratchet the floor up."
        )
    print(f"OK: coverage {measured}% >= floor {minimum}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

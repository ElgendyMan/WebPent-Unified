#!/usr/bin/env python3
"""Run the full suite and write machine-generated evidence.

The script intentionally owns the evidence file: reports must reference the
file produced by this command rather than handwritten test counts.

RESIDUAL CLOSURE WINDOW 2026-10-29 (unified roadmap Track 1, التغطية):
the run now ALSO measures coverage over ``src/webpent`` and enforces the
frozen floor from ``scripts/quality/coverage_baseline.json`` (a measured
baseline + ratchet: the floor may only move DOWN on purpose, never by
accident). One run produces evidence AND coverage — CI does not pay for
a second suite execution. Coverage data is written to
``docs/coverage_last_run.json`` so the floor can be re-baselined from a
real, reproducible artifact instead of a hand-typed number.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs" / "FULL_SUITE_EVIDENCE.txt"
BASELINE = ROOT / "docs" / "FULL_SUITE_BASELINE.json"
COVERAGE_JSON = ROOT / "docs" / "coverage_last_run.json"
COVERAGE_FLOOR_FILE = ROOT / "scripts" / "quality" / "coverage_baseline.json"
SUMMARY_RE = re.compile(r"(?P<count>\d+)\s+(?P<kind>passed|failed|skipped|error|errors?)\b")


def _summary(output: str) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    for match in SUMMARY_RE.finditer(output):
        kind = match.group("kind")
        kind = "errors" if kind.startswith("error") else kind
        counts[kind] = max(counts[kind], int(match.group("count")))
    return counts


def _floor_percent() -> int | None:
    if not COVERAGE_FLOOR_FILE.exists():
        return None
    try:
        data = json.loads(COVERAGE_FLOOR_FILE.read_text(encoding="utf-8"))
        return int(data["total_percent"])
    except (OSError, ValueError, KeyError):
        return None


def main() -> int:
    floor = _floor_percent()
    command = [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"]
    if floor is not None:
        command += [
            "--cov=src/webpent",
            f"--cov-report=json:{COVERAGE_JSON}",
            f"--cov-fail-under={floor}",
        ]
    started = datetime.now(timezone.utc)
    completed = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    output = completed.stdout
    counts = _summary(output)
    baseline = json.loads(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else {"failed": 0, "errors": 0}
    new_failures = max(0, counts["failed"] + counts["errors"] - int(baseline.get("failed", 0)) - int(baseline.get("errors", 0)))
    coverage_line = "coverage floor: not configured (scripts/quality/coverage_baseline.json missing)"
    if floor is not None and COVERAGE_JSON.exists():
        try:
            total = json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))["totals"]["percent_covered"]
            coverage_line = f"# Coverage: {total:.2f}% (floor {floor}% — {'OK' if total >= floor else 'BELOW FLOOR'})"
        except (OSError, ValueError, KeyError):
            coverage_line = f"# Coverage: floor {floor}% — report unavailable"
    evidence = [
        "# Test Run Evidence",
        f"# Date: {started.isoformat()}",
        f"# Command: {' '.join(command)}",
        f"# Python: {platform.python_version()} | Platform: {platform.platform()}",
        coverage_line,
        "# --- PYTEST OUTPUT ---",
        output.rstrip(),
        "# --- SUMMARY ---",
        f"# Total: {sum(counts.values())} | Passed: {counts['passed']} | Failed: {counts['failed']} | Skipped: {counts['skipped']} | Errors: {counts['errors']}",
        f"# New failures vs baseline: {new_failures}",
        f"# Exit code: {completed.returncode}",
    ]
    EVIDENCE.write_text("\n".join(evidence) + "\n", encoding="utf-8")
    for line in evidence[-5:][:4]:
        print(line)
    if completed.returncode != 0 or new_failures > 0:
        return completed.returncode or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

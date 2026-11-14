#!/usr/bin/env python3
"""Run the full suite and write machine-generated, provenance-bound evidence.

The script intentionally owns the evidence files: reports must reference
the files produced by this command rather than handwritten test counts.

UM-DR-36.1 §4 (stale-evidence elimination) — the evidence contract:

* BOTH a human-readable transcript (docs/FULL_SUITE_EVIDENCE.txt) and a
  machine-readable record (docs/FULL_SUITE_EVIDENCE.json) are written.
* The JSON record carries full run provenance: source commit SHA, git
  tree clean/dirty state, GitHub workflow run id/attempt (when running
  under Actions), UTC start/completion timestamps, Python and uv
  versions, the dependency lockfile SHA-256, the exact test command,
  the test-inventory scope digest, coverage result + floor, and the
  complete outcome accounting (collected, executed, passed, failed,
  skipped, xfailed, xpassed, errors, deselected, exit code).
* Accounting is parsed from pytest's own final session summary (never
  progress-line counts) and verified mathematically:
  executed == passed+failed+errors+skipped+xfailed+xpassed and
  collected == executed+deselected. An unparseable or inconsistent
  accounting fails the run (fail-closed) — the evidence never claims a
  green state the transcript does not support.
* Any pre-existing evidence file is DELETED before the run starts, so a
  failed or interrupted run can never leave an older green evidence
  file behind for a checker to accept.

Coverage (RESIDUAL CLOSURE WINDOW 2026-10-29, Track 1): when
scripts/quality/coverage_baseline.json exists the run measures coverage
over src/webpent and enforces its floor; one run produces evidence AND
coverage. Coverage data lands in docs/coverage_last_run.json.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_TXT = ROOT / "docs" / "FULL_SUITE_EVIDENCE.txt"
EVIDENCE_JSON = ROOT / "docs" / "FULL_SUITE_EVIDENCE.json"
COVERAGE_JSON = ROOT / "docs" / "coverage_last_run.json"
COVERAGE_FLOOR_FILE = ROOT / "scripts" / "quality" / "coverage_baseline.json"
EVIDENCE_SCHEMA = "full-suite-evidence/v2"
RUNNER_NAME = "run_tests_with_evidence.py"

OUTCOME_KINDS = ("passed", "failed", "skipped", "xfailed", "xpassed",
                 "deselected", "errors")
_SUMMARY_LINE_RE = re.compile(r"^=+\s*(?P<body>.*?)\s*=+$")
_OUTCOME_RE = re.compile(r"(?P<count>\d+)\s+(?P<kind>passed|failed|skipped|xfailed|xpassed|deselected|errors?)\b")
# pytest prints "collecting ... collected 6713 items" in the run header
# and "9056 tests collected" under --collect-only -q; accept both.
_COLLECTED_RE = re.compile(
    r"(?:collected\s+(?P<header>\d+)\s+items?|(?P<collect_only>\d+)\s+tests?\s+collected)")


def _collected_count(output: str) -> int | None:
    for m in _COLLECTED_RE.finditer(output):
        value = m.group("header") or m.group("collect_only")
        if value:
            return int(value)
    return None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(args: list[str]) -> str:
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                       text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def _scope_digest() -> str:
    """SHA-256 over the sorted (path, file-hash) inventory of tests/."""
    h = hashlib.sha256()
    for path in sorted((ROOT / "tests").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(_sha256_file(path).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def _floor_percent() -> int | None:
    if not COVERAGE_FLOOR_FILE.exists():
        return None
    try:
        return int(json.loads(COVERAGE_FLOOR_FILE.read_text(
            encoding="utf-8"))["total_percent"])
    except (OSError, ValueError, KeyError):
        return None


def parse_accounting(output: str) -> dict[str, int | None]:
    """Parse pytest's own final summary line + collection line.

    Returns a dict with collected/executed/passed/failed/skipped/xfailed/
    xpassed/errors/deselected (None where pytest did not report a kind)
    plus 'accounting_consistent' (1/0) and 'summary_found' (1/0).
    """
    counts: dict[str, int | None] = {k: None for k in OUTCOME_KINDS}
    collected = _collected_count(output)
    summary_found = False
    for line in reversed(output.splitlines()):
        stripped = line.strip()
        m = _SUMMARY_LINE_RE.match(stripped)
        if not m:
            continue
        body = m.group("body")
        found = _OUTCOME_RE.findall(body)
        if not found:
            continue
        summary_found = True
        for count, kind in found:
            key = "errors" if kind.startswith("error") else kind
            counts[key] = int(count)
        break
    if not summary_found:
        return {**counts, "collected": collected, "executed": None,
                "accounting_consistent": 0, "summary_found": 0}
    for key in OUTCOME_KINDS:
        if counts[key] is None:
            counts[key] = 0
    executed = (counts["passed"] + counts["failed"] + counts["errors"]
                + counts["skipped"] + counts["xfailed"] + counts["xpassed"])
    consistent = 1
    if collected is not None and collected != executed + counts["deselected"]:
        consistent = 0
    return {**counts, "collected": collected, "executed": executed,
            "accounting_consistent": consistent, "summary_found": 1}


def _uv_version() -> str:
    uv = shutil.which("uv")
    if not uv:
        return "unavailable"
    r = subprocess.run([uv, "--version"], capture_output=True, text=True,
                       check=False)
    return r.stdout.strip() or "unknown"


def main() -> int:
    floor = _floor_percent()
    command = [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"]
    if floor is not None:
        command += [
            "--cov=src/webpent",
            f"--cov-report=json:{COVERAGE_JSON}",
            f"--cov-fail-under={floor}",
        ]

    # UM-DR-36.1 §4: stale evidence cannot survive this run. Delete any
    # pre-existing evidence (from an earlier workflow or local run) BEFORE
    # starting; if this run then fails or is interrupted, no old green
    # evidence file remains for a checker to accept.
    for stale in (EVIDENCE_TXT, EVIDENCE_JSON):
        if stale.exists():
            stale.unlink()

    started = datetime.now(timezone.utc)
    commit = _git(["rev-parse", "HEAD"])
    dirty = bool(_git(["status", "--porcelain"]))
    github_run = os.environ.get("GITHUB_RUN_ID")
    github_attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
    lockfile_sha = (_sha256_file(ROOT / "uv.lock")
                    if (ROOT / "uv.lock").is_file() else None)

    completed = subprocess.run(command, cwd=ROOT, text=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, check=False)
    output = completed.stdout
    finished = datetime.now(timezone.utc)
    accounting = parse_accounting(output)

    coverage_result = "not_configured"
    coverage_percent = None
    if floor is not None:
        coverage_result = f"floor {floor}% — report unavailable"
        if COVERAGE_JSON.exists():
            try:
                total = json.loads(COVERAGE_JSON.read_text(
                    encoding="utf-8"))["totals"]["percent_covered"]
                coverage_percent = round(total, 2)
                coverage_result = (
                    f"{total:.2f}% (floor {floor}% — "
                    f"{'OK' if total >= floor else 'BELOW FLOOR'})")
            except (OSError, ValueError, KeyError):
                pass

    record = {
        "schema": EVIDENCE_SCHEMA,
        "runner": RUNNER_NAME,
        "source_commit": commit or "unknown",
        "tree_clean": not dirty,
        "github": ({"run_id": github_run, "run_attempt": github_attempt}
                   if github_run else None),
        "started_at_utc": started.isoformat(),
        "completed_at_utc": finished.isoformat(),
        "python_version": platform.python_version(),
        "uv_version": _uv_version(),
        "lockfile_sha256": lockfile_sha,
        "command": command,
        "test_scope_digest": _scope_digest(),
        "accounting": accounting,
        "coverage": {"floor_percent": floor, "result": coverage_result,
                     "percent_covered": coverage_percent},
        "exit_code": completed.returncode,
    }
    EVIDENCE_JSON.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_JSON.write_text(json.dumps(record, indent=2) + "\n",
                             encoding="utf-8")

    a = accounting
    evidence_txt = [
        "# Test Run Evidence",
        f"# Schema: {EVIDENCE_SCHEMA} (machine record: {EVIDENCE_JSON.name})",
        f"# Date: {started.isoformat()} -> {finished.isoformat()}",
        f"# Source commit: {record['source_commit']} "
        f"(tree {'clean' if record['tree_clean'] else 'DIRTY'})",
        f"# Workflow: {record['github'] or 'local run (no GitHub Actions context)'}",
        f"# Command: {' '.join(command)}",
        f"# Python: {platform.python_version()} | uv: {record['uv_version']} "
        f"| lockfile sha256: {lockfile_sha}",
        f"# Test scope digest: {record['test_scope_digest']}",
        f"# Coverage: {coverage_result}",
        "# --- PYTEST OUTPUT ---",
        output.rstrip(),
        "# --- SUMMARY ---",
        "# Collected: {collected} | Executed: {executed}".format(**a),
        "# Total: {executed} | Passed: {passed} | Failed: {failed} | "
        "Skipped: {skipped} | Xfailed: {xfailed} | Xpassed: {xpassed} | "
        "Errors: {errors} | Deselected: {deselected}".format(**a),
        f"# Accounting consistent: {bool(a['accounting_consistent'])}",
        f"# Exit code: {completed.returncode}",
    ]
    EVIDENCE_TXT.write_text("\n".join(evidence_txt) + "\n", encoding="utf-8")

    print(f"collected={a['collected']} executed={a['executed']} "
          f"passed={a['passed']} failed={a['failed']} "
          f"skipped={a['skipped']} xfailed={a['xfailed']} "
          f"xpassed={a['xpassed']} errors={a['errors']} "
          f"deselected={a['deselected']}")
    print(f"accounting_consistent={bool(a['accounting_consistent'])} "
          f"exit_code={completed.returncode}")
    print(f"evidence: {EVIDENCE_JSON}")

    # Fail-closed: a non-zero pytest exit, or an accounting we could not
    # parse/verify, is never a green evidence state.
    if completed.returncode != 0:
        return completed.returncode
    if not a["accounting_consistent"]:
        print("FAIL: test accounting could not be verified from the pytest "
              "session summary", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

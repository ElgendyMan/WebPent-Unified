#!/usr/bin/env python3
"""Run the full suite and write machine-generated, provenance-bound evidence.

The script intentionally owns the evidence files: reports must reference
the files produced by this command rather than handwritten test counts.

UM-DR-38 §6.2 (evidence output contract) — evidence is a BUILD ARTIFACT:

* Evidence is written to the ignored `.webpent-evidence/` directory
  (configurable via the WEBPENT_EVIDENCE_DIR environment variable),
  NEVER to tracked source files: a test run must not modify the source
  revision it is testing. `tree_clean` therefore describes the checkout
  at TEST-START time (captured before pytest runs); the historical
  records under docs/history/ are never touched.
* BOTH a human-readable transcript (FULL_SUITE_EVIDENCE.txt) and a
  machine-readable record (FULL_SUITE_EVIDENCE.json) are written
  ATOMICALLY (tmp file + os.replace), so an interrupted write can never
  leave a truncated or partial record at the evidence path.
* The JSON record carries full run provenance: source commit SHA, git
  tree clean/dirty state at test start (plus a bounded status sample),
  GitHub workflow run id/attempt (when running under Actions), UTC
  start/completion timestamps, Python and uv versions, the dependency
  lockfile SHA-256, the exact test command, the test-inventory scope
  digest, coverage result + floor, and the complete outcome accounting
  (collected, executed, passed, failed, skipped, xfailed, xpassed,
  errors, deselected, exit code).
* Accounting is parsed from pytest's own final session summary (never
  progress-line counts) and cross-checked against the hook-level v3
  model (UM-DR-36.2 §3.6): the v3 invariants are authoritative and the
  legacy terminal equation is only well-formed with zero
  collection-phase reports; an unparseable or UNEXPLAINED accounting
  fails the run (fail-closed) — the evidence never claims a green
  state the transcript does not support.
* Any pre-existing evidence in the evidence directory is DELETED before
  the run starts, so a failed or interrupted run can never leave an
  older green evidence file behind for a checker to accept.

Coverage (RESIDUAL CLOSURE WINDOW 2026-10-29, Track 1): when
scripts/quality/coverage_baseline.json exists the run measures coverage
over src/webpent and enforces its floor; one run produces evidence AND
coverage. Coverage data lands in the evidence directory.
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
EVIDENCE_DIR = Path(os.environ.get("WEBPENT_EVIDENCE_DIR")
                    or (ROOT / ".webpent-evidence"))
EVIDENCE_TXT = EVIDENCE_DIR / "FULL_SUITE_EVIDENCE.txt"
EVIDENCE_JSON = EVIDENCE_DIR / "FULL_SUITE_EVIDENCE.json"
COVERAGE_JSON = EVIDENCE_DIR / "coverage_last_run.json"
COVERAGE_FLOOR_FILE = ROOT / "scripts" / "quality" / "coverage_baseline.json"
EVIDENCE_SCHEMA = "full-suite-evidence/v3"
RUNNER_NAME = "run_tests_with_evidence.py"
ACCOUNTING_PLUGIN = "pytest_accounting_plugin"

OUTCOME_KINDS = ("passed", "failed", "skipped", "xfailed", "xpassed",
                 "deselected", "errors")
_SUMMARY_LINE_RE = re.compile(r"^=+\s*(?P<body>.*?)\s*=+$")
_OUTCOME_RE = re.compile(
    r"(?P<count>\d+)\s+(?P<kind>passed|failed|skipped|xfailed|xpassed"
    r"|deselected|errors?)\b")
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


def _atomic_write(path: Path, text: str) -> None:
    """UM-DR-38 §6.2: evidence writes are atomic (tmp + os.replace), so
    an interrupted write can never leave a truncated record at the
    evidence path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


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
    counts: dict[str, int | None] = dict.fromkeys(OUTCOME_KINDS)
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


def evidence_gate_ok(
    terminal_accounting: dict,
    accounting_v3: dict | None,
    cross_check: dict | None,
) -> tuple[bool, str]:
    """The fail-closed evidence gate (UM-DR-36.2 §3.6, contract level).

    The hook-level v3 accounting is the AUTHORITATIVE model. The legacy
    v2 terminal equation (collected == executed + deselected, where
    "executed" conflates item outcomes with collection-phase reports)
    is only well-formed when NO collection-phase reports exist; when
    collection errors/skips are present the v2 equation is EXPECTED to
    disagree, and the v3 invariants + terminal cross-check decide.

    Never bypassed: a v2 disagreement WITHOUT collection-phase reports
    still fails, and a missing / invariant-violating / disagreeing v3
    always fails.
    """
    if accounting_v3 is None:
        return False, ("hook-level accounting (pytest_accounting_plugin) "
                       "is missing — the v3 evidence contract requires it")
    if not accounting_v3.get("invariants_all_true"):
        return False, "v3 accounting invariants violated"
    if not (cross_check or {}).get("all_agree"):
        return False, ("hook-level accounting disagrees with the terminal "
                       f"summary: {(cross_check or {}).get('disagreements')}")
    collection_phase_reports = (
        int(accounting_v3.get("collection_errors") or 0)
        + int(accounting_v3.get("collection_skips") or 0)
    )
    if not terminal_accounting.get("accounting_consistent") \
            and not collection_phase_reports:
        return False, ("the v2 terminal equation disagrees while the v3 "
                       "model records NO collection-phase reports — "
                       "unexplained accounting inconsistency")
    return True, ("" if terminal_accounting.get("accounting_consistent")
                  else f"v2 equation explained by {collection_phase_reports} "
                       f"collection-phase report(s); v3 invariants hold")


def main() -> int:
    floor = _floor_percent()
    command = [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short",
               "-p", ACCOUNTING_PLUGIN]
    if floor is not None:
        command += [
            "--cov=src/webpent",
            f"--cov-report=json:{COVERAGE_JSON}",
            f"--cov-fail-under={floor}",
        ]

    # UM-DR-36.2 §3.4 (hook-level accounting): the plugin counts every
    # report by phase, separating collection errors/skips (non-item
    # reports) from setup/teardown errors — the categories the terminal
    # summary collapses (the recorded 9141-collected vs 9142-executed
    # anomaly was exactly this conflation).
    import tempfile
    accounting_file = Path(tempfile.mkdtemp(prefix="umdr-accounting-")) \
        / "accounting.json"
    run_env = dict(os.environ)
    run_env["UMDR_ACCOUNTING_OUT"] = str(accounting_file)
    scripts_dir = str(ROOT / "scripts")
    run_env["PYTHONPATH"] = (scripts_dir + os.pathsep
                             + run_env.get("PYTHONPATH", ""))

    # UM-DR-36.1 §4: stale evidence cannot survive this run. Delete any
    # pre-existing evidence (from an earlier workflow or local run) BEFORE
    # starting; if this run then fails or is interrupted, no old green
    # evidence file remains for a checker to accept.
    for stale in (EVIDENCE_TXT, EVIDENCE_JSON):
        if stale.exists():
            stale.unlink()

    started = datetime.now(timezone.utc)
    commit = _git(["rev-parse", "HEAD"])
    if not commit:
        print("FAIL: not a git checkout — the v3 evidence contract "
              "requires the exact source commit under test",
              file=sys.stderr)
        return 1
    # UM-DR-38 §6.2: tree state at TEST START. Captured BEFORE pytest
    # runs; the evidence directory is git-ignored, so a clean checkout
    # stays clean and `tree_clean` describes the source revision being
    # tested — never run-generated output.
    status_porcelain = _git(["status", "--porcelain"])
    dirty = bool(status_porcelain)
    tree_status_sample = status_porcelain.splitlines()[:50]
    github_run = os.environ.get("GITHUB_RUN_ID")
    github_attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
    lockfile_sha = (_sha256_file(ROOT / "uv.lock")
                    if (ROOT / "uv.lock").is_file() else None)

    completed = subprocess.run(command, cwd=ROOT, text=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, check=False,
                               env=run_env)
    output = completed.stdout
    finished = datetime.now(timezone.utc)
    accounting = parse_accounting(output)

    # ---- v3: merge the hook-level accounting + cross-check -------------
    accounting_v3 = None
    cross_check: dict[str, object] = {"plugin_available": False}
    if accounting_file.is_file():
        try:
            accounting_v3 = json.loads(
                accounting_file.read_text(encoding="utf-8"))
        except ValueError:
            accounting_v3 = None
    if accounting_v3 is not None:
        cross_check["plugin_available"] = True
        terminal = {
            "errors": accounting.get("errors"),
            "skipped": accounting.get("skipped"),
            "passed": accounting.get("passed"),
            "failed": accounting.get("failed"),
            "xfailed": accounting.get("xfailed"),
            "xpassed": accounting.get("xpassed"),
            "collected": accounting.get("collected"),
        }
        checks = {
            "collected": (
                accounting_v3["collected_items"] == terminal["collected"]),
            "errors": (
                accounting_v3["errors_total"] == terminal["errors"]),
            "skipped": (
                accounting_v3["outcomes"]["skipped"]
                + accounting_v3["collection_skips"]
                == terminal["skipped"]),
            "passed": (
                accounting_v3["outcomes"]["passed"] == terminal["passed"]),
            "failed": (
                accounting_v3["outcomes"]["failed"] == terminal["failed"]),
            "xfailed": (
                accounting_v3["outcomes"]["xfailed"] == terminal["xfailed"]),
            "xpassed": (
                accounting_v3["outcomes"]["xpassed"] == terminal["xpassed"]),
        }
        # None terminal values (unparsed) do not fail the cross-check;
        # a parsed number that DISAGREES with the hooks always does.
        disagreements = {
            k: v for k, v in checks.items() if terminal[k] is not None
            and not v
        }
        cross_check["disagreements"] = disagreements
        cross_check["all_agree"] = not disagreements
        cross_check["plugin_invariants_all_true"] = accounting_v3.get(
            "invariants_all_true", False)
    else:
        cross_check["all_agree"] = False
        cross_check["plugin_invariants_all_true"] = False

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
        "tree_status_sample_at_test_start": tree_status_sample,
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
        "accounting_v3": accounting_v3,
        "accounting_cross_check": cross_check,
        "coverage": {"floor_percent": floor, "result": coverage_result,
                     "percent_covered": coverage_percent},
        "exit_code": completed.returncode,
    }
    EVIDENCE_JSON.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(EVIDENCE_JSON,
                  json.dumps(record, indent=2) + "\n")

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
    if accounting_v3 is not None:
        o = accounting_v3["outcomes"]
        evidence_txt += [
            "# --- V3 HOOK-LEVEL ACCOUNTING "
            "(scripts/pytest_accounting_plugin.py) ---",
            f"# Collected items: {accounting_v3['collected_items']} | "
            f"started: {accounting_v3['started_items']} | "
            f"not_started: {accounting_v3['not_started']}",
            f"# Item outcomes: passed {o['passed']} | failed {o['failed']} | "
            f"skipped {o['skipped']} | xfailed {o['xfailed']} | "
            f"xpassed {o['xpassed']}",
            f"# Setup errors: {accounting_v3['setup_errors']} | "
            f"teardown errors: {accounting_v3['teardown_errors']} | "
            f"collection errors: {accounting_v3['collection_errors']} | "
            f"collection skips: {accounting_v3['collection_skips']}",
            f"# Invariants all true: "
            f"{accounting_v3.get('invariants_all_true')} | "
            f"terminal cross-check agree: {cross_check.get('all_agree')}",
        ]
    _atomic_write(EVIDENCE_TXT, "\n".join(evidence_txt) + "\n")

    print(f"collected={a['collected']} executed={a['executed']} "
          f"passed={a['passed']} failed={a['failed']} "
          f"skipped={a['skipped']} xfailed={a['xfailed']} "
          f"xpassed={a['xpassed']} errors={a['errors']} "
          f"deselected={a['deselected']}")
    print(f"accounting_consistent={bool(a['accounting_consistent'])} "
          f"exit_code={completed.returncode}")
    # Name the failing tests in the runner log: the CI log captures only
    # this script's stdout, not pytest's interactive output, so without
    # this a red run gives no actionable failure name.
    if accounting_v3 and accounting_v3.get("failed_nodeids"):
        print("failed tests:")
        for nodeid in accounting_v3["failed_nodeids"]:
            print(f"  FAILED {nodeid}")
        # UM-DR-43C §2.6: pytest's output was captured into a PIPE and
        # never printed — the CI log named failing tests but never showed
        # WHY they failed (the option_b runner-only failure stayed
        # undiagnosed across runs #21/#22/#25 for exactly this reason).
        # Re-print the tail of the captured output; the FAILURES block
        # and short summary live at the end.
        print("---- pytest output tail (FAILURES section) ----")
        for line in output.splitlines()[-400:]:
            print(line)
        print("---- end pytest output tail ----")
    print(f"evidence: {EVIDENCE_JSON}")

    # Fail-closed: a non-zero pytest exit or an accounting the evidence
    # gate cannot verify is never a green evidence state (§3.6 contract).
    if completed.returncode != 0:
        return completed.returncode
    gate_ok, gate_reason = evidence_gate_ok(a, accounting_v3, cross_check)
    if not gate_ok:
        print(f"FAIL: {gate_reason}", file=sys.stderr)
        return 1
    if gate_reason:
        print(f"accounting note: {gate_reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail closed unless complete, CURRENT-run, provenance-bound test evidence exists.

UM-DR-36.1 §4 — the previous checker only verified that a text file
existed and contained a few markers, which meant an evidence file left
behind by an earlier workflow (or a local run months old) passed as
proof of a current test run. This checker validates that the evidence

  1. exists as a machine-readable record with the expected schema,
     produced by scripts/run_tests_with_evidence.py;
  2. records a COMPLETE accounting (collected, executed, passed,
     failed, skipped, xfailed, xpassed, errors, deselected) whose math
     verifies: executed == passed+failed+errors+skipped+xfailed+xpassed
     and collected == executed+deselected;
  3. belongs to the CURRENT source revision — the recorded commit must
     equal this checkout's HEAD (a stale evidence file from another
     commit fails);
  4. belongs to the CURRENT workflow execution when running under
     GitHub Actions — the recorded run id and attempt must match the
     GITHUB_RUN_ID / GITHUB_RUN_ATTEMPT environment values;
  5. records a successful run (exit code 0) — evidence of a failed or
     skipped test run never validates green;
  6. records sane timestamps (completion not before start).

A missing evidence file fails. An old evidence file fails. Evidence
from the right commit but a different workflow run fails in CI. There
is no path where a run that did not execute (or failed) validates.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_JSON = ROOT / "docs" / "FULL_SUITE_EVIDENCE.json"
EVIDENCE_TXT = ROOT / "docs" / "FULL_SUITE_EVIDENCE.txt"
EXPECTED_SCHEMA = "full-suite-evidence/v2"
EXPECTED_RUNNER = "run_tests_with_evidence.py"
REQUIRED_COUNTS = ("collected", "executed", "passed", "failed", "skipped",
                   "xfailed", "xpassed", "errors", "deselected")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _git_head() -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                       capture_output=True, text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def evaluate(record: dict, *, head: str, env: dict[str, str]) -> list[str]:
    """Return the list of failures (empty list == evidence validates)."""
    failures: list[str] = []

    if record.get("schema") != EXPECTED_SCHEMA:
        failures.append(f"schema is {record.get('schema')!r}, "
                        f"expected {EXPECTED_SCHEMA!r}")
    if record.get("runner") != EXPECTED_RUNNER:
        failures.append(f"runner is {record.get('runner')!r}, expected "
                        f"{EXPECTED_RUNNER!r} (hand-written evidence is not "
                        "accepted)")

    commit = str(record.get("source_commit", ""))
    if not _HEX40.match(commit):
        failures.append(f"source_commit is not a 40-hex sha: {commit!r}")
    elif head and commit != head:
        failures.append(
            f"evidence belongs to commit {commit}, but this checkout is "
            f"{head} — STALE evidence from a different source revision")

    run_env_id = env.get("GITHUB_RUN_ID")
    recorded = record.get("github")
    if run_env_id:
        if not isinstance(recorded, dict):
            failures.append("running under GitHub Actions but the evidence "
                            "records no workflow identity")
        else:
            if str(recorded.get("run_id")) != run_env_id:
                failures.append(
                    f"evidence workflow run {recorded.get('run_id')!r} != "
                    f"current run {run_env_id!r}")
            attempt = env.get("GITHUB_RUN_ATTEMPT")
            if attempt and str(recorded.get("run_attempt")) != attempt:
                failures.append(
                    f"evidence workflow attempt "
                    f"{recorded.get('run_attempt')!r} != current attempt "
                    f"{attempt!r}")

    accounting = record.get("accounting")
    if not isinstance(accounting, dict):
        failures.append("accounting block missing")
        return failures
    missing = [k for k in REQUIRED_COUNTS
               if not isinstance(accounting.get(k), int)]
    if missing:
        failures.append(f"accounting missing integer counts: {missing}")
    else:
        a = accounting
        total = (a["passed"] + a["failed"] + a["errors"] + a["skipped"]
                 + a["xfailed"] + a["xpassed"])
        if a["executed"] != total:
            failures.append(
                f"executed {a['executed']} != passed+failed+errors+skipped"
                f"+xfailed+xpassed {total}")
        if a["collected"] != a["executed"] + a["deselected"]:
            failures.append(
                f"collected {a['collected']} != executed+deselected "
                f"{a['executed'] + a['deselected']}")
        if not accounting.get("accounting_consistent"):
            failures.append("runner could not verify the accounting against "
                            "the pytest session summary")
    if not accounting.get("summary_found"):
        failures.append("no pytest session summary line was captured — the "
                        "test run did not produce a final summary")

    exit_code = record.get("exit_code")
    if exit_code != 0:
        failures.append(f"recorded test exit code is {exit_code!r}, not 0 — "
                        "evidence of a failed run never validates")

    started = str(record.get("started_at_utc", ""))
    completed = str(record.get("completed_at_utc", ""))
    if not started or not completed:
        failures.append("start/completion timestamps missing")
    elif completed < started:
        failures.append("completion timestamp precedes start timestamp")

    return failures


def main() -> int:
    if not EVIDENCE_JSON.is_file():
        print(f"FAIL: missing machine-readable evidence {EVIDENCE_JSON}")
        print("The evidence is generated by "
              "scripts/run_tests_with_evidence.py; a run that did not "
              "execute produces no acceptable evidence.")
        return 1
    try:
        record = json.loads(EVIDENCE_JSON.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"FAIL: evidence JSON unparseable: {exc}")
        return 1
    if not EVIDENCE_TXT.is_file():
        print(f"FAIL: human-readable transcript missing ({EVIDENCE_TXT})")
        return 1

    failures = evaluate(record, head=_git_head(), env=dict(os.environ))
    if failures:
        print(f"test_evidence: GATE FAILURE ({len(failures)})")
        for f in failures:
            print(f"  - {f}")
        return 1
    a = record["accounting"]
    print("test_evidence: PASS — current-run evidence verified "
          f"(commit {record['source_commit'][:12]}, "
          f"collected {a['collected']}, executed {a['executed']}, "
          f"passed {a['passed']}, failed {a['failed']}, "
          f"skipped {a['skipped']}, xfailed {a['xfailed']}, "
          f"xpassed {a['xpassed']}, errors {a['errors']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

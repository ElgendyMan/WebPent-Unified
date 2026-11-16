"""UM-DR-36.1 §4 — stale-evidence elimination tests.

Pins the new evidence contract end to end:

* the runner's accounting parser reads pytest's own final session
  summary (never progress lines) and verifies the math;
* the checker rejects, fail-closed: missing evidence, evidence from a
  different source commit (stale), evidence from a different workflow
  run/attempt, hand-written evidence, wrong schema, unverified
  accounting, collected-as-executed confusion, and evidence of a
  failed run;
* the checker accepts exactly one thing: complete, current-revision,
  current-run, mathematically-consistent evidence of a green run.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from check_test_evidence import evaluate  # noqa: E402
from run_tests_with_evidence import parse_accounting  # noqa: E402

HEAD = "a" * 40
OTHER = "b" * 40

OK_OUTPUT = """\
============================= test session starts ==============================
collected 9056 items
tests/test_a.py::test_one PASSED [  0%]
======================== 9040 passed, 12 skipped, 3 xfailed, 1 xpassed in 60.2s ========================
"""

FAIL_OUTPUT = """\
collected 100 items
=========================== short test summary info ============================
FAILED tests/test_a.py::test_one - assert False
ERROR tests/test_b.py
========================= 2 failed, 1 error, 95 passed, 2 skipped in 12.0s =========================
"""


def _record(**overrides) -> dict:
    record = {
        "schema": "full-suite-evidence/v2",
        "runner": "run_tests_with_evidence.py",
        "source_commit": HEAD,
        "github": None,
        "started_at_utc": "2026-11-14T09:00:00+00:00",
        "completed_at_utc": "2026-11-14T09:05:00+00:00",
        "accounting": {"collected": 100, "executed": 100, "passed": 98,
                       "failed": 0, "skipped": 2, "xfailed": 0, "xpassed": 0,
                       "errors": 0, "deselected": 0,
                       "accounting_consistent": 1, "summary_found": 1},
        "exit_code": 0,
    }
    record.update(overrides)
    return record


# ------------------------------------------------------------------ parser


def test_parser_reads_final_summary_not_progress_lines() -> None:
    a = parse_accounting(OK_OUTPUT)
    assert a["passed"] == 9040 and a["skipped"] == 12
    assert a["xfailed"] == 3 and a["xpassed"] == 1
    assert a["failed"] == 0 and a["errors"] == 0
    assert a["executed"] == 9056
    assert a["collected"] == 9056
    assert a["accounting_consistent"] == 1


def test_parser_counts_errors_and_failures_separately() -> None:
    a = parse_accounting(FAIL_OUTPUT)
    assert a["failed"] == 2 and a["errors"] == 1 and a["passed"] == 95
    assert a["executed"] == 100 and a["accounting_consistent"] == 1


def test_parser_accepts_collect_only_style_count_line() -> None:
    a = parse_accounting("9100 tests collected\n")
    assert a["collected"] == 9100


def test_parser_accepts_deselected_accounting() -> None:
    output = ("collected 9100 items\n"
              "====== 9050 passed, 48 skipped, 2 deselected in 60.0s ======")
    a = parse_accounting(output)
    assert a["deselected"] == 2 and a["executed"] == 9098
    assert a["accounting_consistent"] == 1


def test_parser_without_summary_fails_closed() -> None:
    a = parse_accounting("collected 10 items\n(no final summary line)\n")
    assert a["summary_found"] == 0
    assert a["accounting_consistent"] == 0


# ----------------------------------------------------------------- checker


def test_current_run_evidence_passes() -> None:
    assert evaluate(_record(), head=HEAD, env={}) == []


def test_missing_evidence_schema_fails() -> None:
    failures = evaluate(_record(schema="full-suite-evidence/v1"),
                        head=HEAD, env={})
    assert any("schema" in f for f in failures)


def test_hand_written_evidence_fails() -> None:
    failures = evaluate(_record(runner="human.txt"), head=HEAD, env={})
    assert any("hand-written" in f for f in failures)


def test_stale_commit_evidence_fails() -> None:
    failures = evaluate(_record(), head=OTHER, env={})
    assert any("STALE" in f for f in failures)


def test_missing_commit_fails() -> None:
    failures = evaluate(_record(source_commit="not-a-sha"), head=HEAD, env={})
    assert any("40-hex" in f for f in failures)


def test_ci_requires_matching_workflow_run() -> None:
    failures = evaluate(_record(), head=HEAD,
                        env={"GITHUB_RUN_ID": "12345",
                             "GITHUB_RUN_ATTEMPT": "1"})
    assert any("workflow identity" in f for f in failures)

    good = _record(github={"run_id": "12345", "run_attempt": "1"})
    assert evaluate(good, head=HEAD, env={"GITHUB_RUN_ID": "12345",
                                          "GITHUB_RUN_ATTEMPT": "1"}) == []

    wrong_run = _record(github={"run_id": "99999", "run_attempt": "1"})
    failures = evaluate(wrong_run, head=HEAD,
                        env={"GITHUB_RUN_ID": "12345",
                             "GITHUB_RUN_ATTEMPT": "1"})
    assert any("workflow run" in f for f in failures)

    wrong_attempt = _record(github={"run_id": "12345", "run_attempt": "2"})
    failures = evaluate(wrong_attempt, head=HEAD,
                        env={"GITHUB_RUN_ID": "12345",
                             "GITHUB_RUN_ATTEMPT": "1"})
    assert any("attempt" in f for f in failures)


def test_evidence_of_failed_run_never_validates() -> None:
    failures = evaluate(_record(exit_code=1), head=HEAD, env={})
    assert any("exit code" in f for f in failures)


def test_collected_as_executed_confusion_fails() -> None:
    # A record claiming 105 collected AND 105 executed while ALSO claiming
    # 5 deselected is internally impossible: collected must equal
    # executed + deselected (110). This is exactly the collected-as-
    # executed confusion (reporting the pre-deselection count as the
    # executed count) — the checker must catch it.
    accounting = {"collected": 105, "executed": 105, "passed": 103,
                  "failed": 0, "skipped": 2, "xfailed": 0, "xpassed": 0,
                  "errors": 0, "deselected": 5, "accounting_consistent": 1,
                  "summary_found": 1}
    failures = evaluate(_record(accounting=accounting), head=HEAD, env={})
    assert any("collected" in f and "executed+deselected" in f
               for f in failures)


def test_unverified_accounting_fails() -> None:
    accounting = dict(_record()["accounting"], accounting_consistent=0)
    failures = evaluate(_record(accounting=accounting), head=HEAD, env={})
    assert any("could not verify" in f for f in failures)


def test_missing_summary_capture_fails() -> None:
    accounting = dict(_record()["accounting"], summary_found=0)
    failures = evaluate(_record(accounting=accounting), head=HEAD, env={})
    assert any("session summary" in f for f in failures)


def test_missing_counts_fails() -> None:
    accounting = {k: v for k, v in _record()["accounting"].items()
                  if k != "xpassed"}
    failures = evaluate(_record(accounting=accounting), head=HEAD, env={})
    assert any("missing integer counts" in f for f in failures)


def test_reversed_timestamps_fail() -> None:
    failures = evaluate(_record(
        started_at_utc="2026-11-14T09:05:00+00:00",
        completed_at_utc="2026-11-14T09:00:00+00:00"), head=HEAD, env={})
    assert any("precedes" in f for f in failures)

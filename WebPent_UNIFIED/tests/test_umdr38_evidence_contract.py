"""UM-DR-38 §6.3 — evidence provenance regression tests.

The checker must reject, with an identifiable failure message:
  * evidence bound to a DIFFERENT commit (stale);
  * evidence recorded against a DIFFERENT lockfile (stale environment);
  * records with missing provenance fields (incomplete);
  * tampered accounting (invariant breaks);
  * coverage below the required floor;
  * evidence from a different GitHub run / attempt under CI;
  * the wrong schema or runner identity;
  * interrupted runs.

Only a complete, current, self-consistent record validates. These tests
pin the fail-closed semantics required by UM-DR-38 §6: no old successful
test file may pass as evidence for a new source revision.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, str(SCRIPTS / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _valid_record() -> dict:
    """A complete, self-consistent, current record — must validate."""
    return {
        "schema": "full-suite-evidence/v3",
        "runner": "run_tests_with_evidence.py",
        "source_commit": "b" * 40,
        "tree_clean": True,
        "github": None,
        "started_at_utc": "2026-11-16T00:00:00+00:00",
        "completed_at_utc": "2026-11-16T00:30:00+00:00",
        "python_version": "3.12.16",
        "uv_version": "uv 0.13.8",
        "lockfile_sha256": "c" * 64,
        "command": ["python", "-m", "pytest", "tests/"],
        "test_scope_digest": "d" * 64,
        "accounting": {
            "collected": 100, "executed": 100, "passed": 95, "failed": 0,
            "skipped": 2, "xfailed": 3, "xpassed": 0, "errors": 0,
            "deselected": 0, "accounting_consistent": 1, "summary_found": 1,
        },
        "accounting_v3": {
            "invariants_all_true": True, "interrupted": False,
            "not_started": 0, "collection_errors": 0, "collection_skips": 0,
            "collected_items": 100, "started_items": 100,
            "outcomes": {"passed": 95, "failed": 0, "skipped": 2,
                         "xfailed": 3, "xpassed": 0},
            "setup_errors": 0, "teardown_errors": 0,
        },
        "accounting_cross_check": {
            "plugin_available": True, "all_agree": True, "disagreements": {},
        },
        "coverage": {"floor_percent": 72,
                     "result": "72.50% (floor 72% — OK)",
                     "percent_covered": 72.5},
        "exit_code": 0,
    }


def _failures(record: dict, *, head: str = "b" * 40,
              env: dict | None = None,
              expected_lockfile_sha: str = "c" * 64) -> list[str]:
    checker = _load("check_test_evidence_umdr38",
                    "check_test_evidence.py")
    return checker.evaluate(record, head=head, env=env or {},
                            expected_lockfile_sha=expected_lockfile_sha)


def test_valid_complete_record_validates() -> None:
    assert _failures(_valid_record()) == []


def test_stale_commit_rejected() -> None:
    failures = _failures(_valid_record(), head="e" * 40)
    assert any("STALE" in f for f in failures)


def test_missing_provenance_fields_rejected() -> None:
    record = _valid_record()
    del record["lockfile_sha256"]
    del record["python_version"]
    failures = _failures(record)
    assert any("lockfile_sha256 missing" in f for f in failures)
    assert any("provenance field 'python_version' missing" in f
               for f in failures)


def test_lockfile_mismatch_rejected() -> None:
    failures = _failures(_valid_record(), expected_lockfile_sha="f" * 64)
    assert any("stale evidence from a different dependency state"
               in f for f in failures)


def test_coverage_below_floor_rejected() -> None:
    record = _valid_record()
    record["coverage"] = {"floor_percent": 72,
                          "result": "60.00% (floor 72% — BELOW FLOOR)",
                          "percent_covered": 60.0}
    failures = _failures(record)
    assert any("does not satisfy the required floor" in f
               for f in failures)


def test_github_run_and_attempt_mismatch_rejected() -> None:
    record = _valid_record()
    record["github"] = {"run_id": "999", "run_attempt": "1"}
    failures = _failures(record, env={"GITHUB_RUN_ID": "12345",
                                      "GITHUB_RUN_ATTEMPT": "2"})
    assert any("evidence workflow run" in f for f in failures)
    assert any("evidence workflow attempt" in f for f in failures)


def test_github_run_must_be_recorded_under_ci() -> None:
    failures = _failures(_valid_record(), env={"GITHUB_RUN_ID": "123"})
    assert any("records no workflow identity" in f for f in failures)


def test_tampered_accounting_rejected() -> None:
    record = _valid_record()
    # tamper one outcome: the v3 invariant (started == outcomes +
    # setup_errors) breaks
    record["accounting_v3"]["outcomes"]["passed"] = 96
    failures = _failures(record)
    assert any("started_items != outcomes + setup_errors" in f
               for f in failures)


def test_interrupted_run_rejected() -> None:
    record = _valid_record()
    record["accounting_v3"]["interrupted"] = True
    failures = _failures(record)
    assert any("INTERRUPTED" in f for f in failures)


def test_wrong_schema_and_runner_rejected() -> None:
    record = _valid_record()
    record["schema"] = "full-suite-evidence/legacy"
    record["runner"] = "handwritten.py"
    failures = _failures(record)
    assert any("schema is" in f for f in failures)
    assert any("hand-written evidence" in f for f in failures)


def test_evidence_output_lives_outside_tracked_source() -> None:
    """§6.2 structural pin: the runner and checker both address the
    ignored .webpent-evidence/ directory — never tracked docs/ paths."""
    checker = _load("check_test_evidence_umdr38",
                    "check_test_evidence.py")
    runner = _load("run_tests_with_evidence_umdr38",
                   "run_tests_with_evidence.py")
    for module in (checker, runner):
        assert ".webpent-evidence" in str(module.EVIDENCE_JSON), (
            "evidence JSON must live under .webpent-evidence/")
        assert ".webpent-evidence" in str(module.EVIDENCE_TXT)
        assert "/docs/" not in str(module.EVIDENCE_JSON)
    assert ".webpent-evidence" in str(runner.COVERAGE_JSON)
    assert hasattr(runner, "_atomic_write")

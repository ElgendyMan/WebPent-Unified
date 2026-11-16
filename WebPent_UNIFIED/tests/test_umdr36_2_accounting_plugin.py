"""UM-DR-36.2 §3.4 — hook-level test-accounting (evidence schema v3).

The UM-DR-36.1 evidence parsed pytest's terminal summary, which collapses
collection-phase reports into item counts — the recorded anomaly
"collected 9141 vs executed 9142" was exactly that conflation. The
plugin (scripts/pytest_accounting_plugin.py) counts every report by
phase; these tests pin the exact model on a live pytest run containing
every category, the checker's v3 contract, legacy v2 compatibility, and
the documented decomposition of the historical anomaly.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

SUITE = {
    "test_subject.py": """
import pytest

def test_passes():
    assert 1 + 1 == 2

def test_fails():
    assert 1 + 1 == 3

@pytest.mark.skip(reason="pinned skip")
def test_skipped():
    pass

@pytest.mark.xfail(reason="pinned xfail")
def test_xfailed():
    raise AssertionError("expected to fail")

@pytest.fixture
def exploding():
    raise RuntimeError("setup error")

def test_setup_error(exploding):
    pass
""",
    "test_collection_error.py": "import module_that_does_not_exist\n",
    "test_collection_skip.py": "import pytest\npytest.skip('module skip', allow_module_level=True)\n",
}


@pytest.fixture()
def suite_dir(tmp_path: Path) -> Path:
    for name, body in SUITE.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    return tmp_path


def _run_pytest(suite: Path, *extra: str) -> dict:
    import os

    out = suite / "accounting.json"
    env = dict(os.environ)
    env["UMDR_ACCOUNTING_OUT"] = str(out)
    env["PYTHONPATH"] = str(SCRIPTS) + os.pathsep + env.get("PYTHONPATH", "")
    subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "pytest_accounting_plugin",
         "-q", "--tb=no", "-p", "no:cacheprovider",
         # the fixture suite contains a deliberate collection ERROR;
         # without this flag pytest aborts the whole session on it
         # (exit 2, "Interrupted: N errors during collection").
         "--continue-on-collection-errors", *extra, str(suite)],
        cwd=suite, env=env, capture_output=True, text=True, check=False,
    )
    return json.loads(out.read_text(encoding="utf-8"))


def test_plugin_counts_every_category_exactly(suite_dir: Path) -> None:
    data = _run_pytest(suite_dir)
    assert data["collected_items"] == 5, data
    assert data["started_items"] == 5
    assert data["not_started"] == 0
    assert data["outcomes"] == {
        "passed": 1, "failed": 1, "skipped": 1, "xfailed": 1, "xpassed": 0,
    }, data["outcomes"]
    assert data["setup_errors"] == 1
    assert data["teardown_errors"] == 0
    assert data["collection_errors"] == 1
    assert data["collection_skips"] == 1
    assert data["errors_total"] == 2  # 1 setup + 0 teardown + 1 collection
    assert data["invariants_all_true"] is True
    assert data["interrupted"] is False


def test_plugin_counts_deselected(suite_dir: Path) -> None:
    data = _run_pytest(suite_dir, "-k", "passes or fails")
    assert data["deselected"] == 3, data
    assert data["collected_items"] == 5
    assert data["started_items"] == 2
    assert data["outcomes"]["passed"] == 1
    assert data["outcomes"]["failed"] == 1
    assert data["invariants_all_true"] is True


# ---------------------------------------------------------------------------
# Checker v3 contract
# ---------------------------------------------------------------------------

HEAD = subprocess.run(
    ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True,
    check=False,
).stdout.strip()


def _v3_record(**overrides) -> dict:
    record = {
        "schema": "full-suite-evidence/v3",
        "runner": "run_tests_with_evidence.py",
        "source_commit": HEAD,
        "tree_clean": True,
        "github": None,
        "started_at_utc": "2026-11-15T00:00:00+00:00",
        "completed_at_utc": "2026-11-15T00:30:00+00:00",
        "python_version": "3.12.16",
        "uv_version": "uv 0.13.8",
        "lockfile_sha256": "a" * 64,
        "command": ["python", "-m", "pytest"],
        "test_scope_digest": "b" * 64,
        "accounting": {
            "passed": 9, "failed": 0, "skipped": 1, "xfailed": 0,
            "xpassed": 0, "deselected": 0, "errors": 0,
            "collected": 10, "executed": 10, "accounting_consistent": 1,
            "summary_found": 1,
        },
        "accounting_v3": {
            "collected_items": 10, "started_items": 10, "not_started": 0,
            "outcomes": {"passed": 9, "failed": 0, "skipped": 1,
                         "xfailed": 0, "xpassed": 0},
            "outcomes_total": 10, "setup_errors": 0, "teardown_errors": 0,
            "collection_errors": 0, "collection_skips": 0,
            "errors_total": 0, "interrupted": False, "exitstatus": 0,
            "invariants": {
                "collected_eq_started_plus_not_started": True,
                "started_eq_outcomes_plus_setup_errors": True,
                "errors_total_decomposes": True,
                "not_started_zero_unless_interrupted": True,
            },
            "invariants_all_true": True,
        },
        "accounting_cross_check": {
            "plugin_available": True, "all_agree": True,
            "plugin_invariants_all_true": True, "disagreements": {},
        },
        "coverage": {"floor_percent": None, "result": "not_configured",
                     "percent_covered": None},
        "exit_code": 0,
    }
    record.update(overrides)
    return record


def _evaluate(record: dict) -> list[str]:
    sys.path.insert(0, str(SCRIPTS))
    try:
        import check_test_evidence
        return check_test_evidence.evaluate(
            record, head=HEAD, env={})
    finally:
        sys.path.remove(str(SCRIPTS))


def test_v3_checker_accepts_wellformed_evidence() -> None:
    assert _evaluate(_v3_record()) == []


def test_v3_checker_rejects_missing_v3_block() -> None:
    record = _v3_record()
    record["accounting_v3"] = None
    failures = _evaluate(record)
    assert any("accounting_v3" in f for f in failures)


def test_v3_checker_rejects_violated_invariants() -> None:
    record = _v3_record()
    record["accounting_v3"]["invariants_all_true"] = False
    record["accounting_v3"]["not_started"] = 2
    record["accounting_cross_check"]["plugin_invariants_all_true"] = False
    failures = _evaluate(record)
    assert any("invariants" in f for f in failures)
    assert any("never started" in f for f in failures)


def test_v3_checker_rejects_cross_check_disagreement() -> None:
    record = _v3_record()
    record["accounting_cross_check"]["all_agree"] = False
    record["accounting_cross_check"]["disagreements"] = {"passed": False}
    failures = _evaluate(record)
    assert any("disagrees with the terminal summary" in f for f in failures)


def test_v2_legacy_record_still_validates() -> None:
    record = _v3_record()
    record["schema"] = "full-suite-evidence/v2"
    record.pop("accounting_v3")
    record.pop("accounting_cross_check")
    assert _evaluate(record) == []


# ---------------------------------------------------------------------------
# The documented decomposition of the historical UM-DR-36.1 anomaly
# ---------------------------------------------------------------------------

def test_umdr36_1_accounting_anomaly_decomposes_exactly() -> None:
    """The recorded 'collected 9141 vs executed 9142' anomaly, explained
    by the v3 model with the numbers from the b3997c9 evidence run
    (docs/FULL_SUITE_EVIDENCE.txt, UM-DR-36.1):

      9,141 collected items = 9,134 item outcomes
                              + 7 setup-errored items (started, never ran)
      9,142 terminal "executed" = 9,134 outcomes + 7 setup errors
                                  + 1 module-level COLLECTION SKIP
                                  (non-item report the summary counts)
      terminal skipped 12 = 11 item skips + 1 collection skip
      terminal errors 7 = 7 setup + 0 teardown + 0 collection errors
    """
    v3_decomposition = {
        "collected_items": 9141,
        "outcomes": {"passed": 9019, "failed": 101, "skipped": 11,
                     "xfailed": 3, "xpassed": 0},
        "setup_errors": 7, "teardown_errors": 0,
        "collection_errors": 0, "collection_skips": 1,
    }
    o = v3_decomposition["outcomes"]
    outcomes_total = sum(o.values())
    started = outcomes_total + v3_decomposition["setup_errors"]
    assert started == v3_decomposition["collected_items"] == 9141
    assert (outcomes_total + v3_decomposition["setup_errors"]
            + v3_decomposition["collection_skips"]) == 9142
    assert (o["skipped"] + v3_decomposition["collection_skips"]) == 12
    assert (v3_decomposition["setup_errors"]
            + v3_decomposition["teardown_errors"]
            + v3_decomposition["collection_errors"]) == 7
    # the legacy v2 invariant genuinely fails on these numbers — which is
    # why the anomaly was recorded, and why v3 exists
    assert v3_decomposition["collected_items"] != 9142 + 0


# ---------------------------------------------------------------------------
# §3.6 — the runner's evidence-gate contract (v2 equation vs v3 model)
# ---------------------------------------------------------------------------

def _load_gate_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_tests_with_evidence_gate",
        str(SCRIPTS / "run_tests_with_evidence.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gate(v2_consistent: int, **v3_overrides) -> tuple[bool, str]:
    module = _load_gate_module()
    v3 = {"invariants_all_true": True, "collection_errors": 0,
          "collection_skips": 0}
    v3.update(v3_overrides)
    return module.evidence_gate_ok(
        {"accounting_consistent": v2_consistent}, v3,
        {"all_agree": True, "disagreements": {}})


def test_gate_v2_disagreement_explained_by_collection_reports() -> None:
    ok, reason = _gate(0, collection_skips=1)
    assert ok, reason
    assert "explained by 1 collection-phase report" in reason


def test_gate_v2_disagreement_without_collection_reports_fails() -> None:
    ok, reason = _gate(0)
    assert not ok
    assert "unexplained accounting inconsistency" in reason


def test_gate_missing_or_violated_v3_fails() -> None:
    module = _load_gate_module()
    ok, reason = module.evidence_gate_ok({"accounting_consistent": 1},
                                         None, None)
    assert not ok and "missing" in reason
    ok, reason = _gate(1, invariants_all_true=False)
    assert not ok and "invariants" in reason
    ok, reason = module.evidence_gate_ok(
        {"accounting_consistent": 1},
        {"invariants_all_true": True, "collection_errors": 0,
         "collection_skips": 0},
        {"all_agree": False, "disagreements": {"passed": False}})
    assert not ok and "disagrees with the terminal summary" in reason


def test_gate_fully_consistent_passes_silently() -> None:
    ok, reason = _gate(1)
    assert ok and reason == ""


# ---------------------------------------------------------------------------
# §3.6 — the CHECKER's contract (evaluate): the same v2/v3 semantics as
# the runner's evidence gate, applied to the evidence FILE validation.
# ---------------------------------------------------------------------------

def _load_checker():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_test_evidence_mod",
        str(SCRIPTS / "check_test_evidence.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _evidence_record(collection_skips: int, *, v3_invariants: bool = True,
                     cross_agree: bool = True) -> dict:
    return {
        "schema": "full-suite-evidence/v3",
        "runner": "run_tests_with_evidence.py",
        "source_commit": "a" * 40,
        "exit_code": 0,
        # the terminal v2 equation DISAGREES: 100 collected vs 101
        # executed+deselected (the shape a collection-phase skip
        # produces), and the runner recorded it as not-consistent
        "accounting": {
            "collected": 100, "executed": 101, "passed": 95, "failed": 2,
            "skipped": 3, "xfailed": 1, "xpassed": 0, "errors": 0,
            "deselected": 0, "summary_found": True,
            "accounting_consistent": False,
        },
        "accounting_v3": {
            "invariants_all_true": v3_invariants, "interrupted": False,
            "not_started": 0, "collection_errors": 0,
            "collection_skips": collection_skips,
            "collected_items": 100, "started_items": 100,
            "outcomes": {"passed": 95, "failed": 2, "skipped": 3,
                         "xfailed": 1, "xpassed": 0},
            "setup_errors": 0, "teardown_errors": 0,
        },
        "accounting_cross_check": {
            "all_agree": cross_agree, "disagreements": {}},
        "started_at": "2026-11-16T00:00:00+00:00",
        "completed_at": "2026-11-16T00:30:00+00:00",
    }


def test_checker_accepts_v2_disagreement_explained_by_collection_skip() -> None:
    """§3.6 on the checker side: with green v3 invariants, an agreeing
    cross-check and a recorded collection-phase skip, the legacy v2
    terminal equation's disagreement does NOT fail the evidence."""
    checker = _load_checker()
    failures = checker.evaluate(
        _evidence_record(collection_skips=1),
        head="", env={})
    assert not any("executed+deselected" in f for f in failures), failures
    assert not any("runner could not verify" in f for f in failures)


def test_checker_fails_unexplained_v2_disagreement_or_degraded_v3() -> None:
    checker = _load_checker()
    # no collection-phase reports -> the disagreement is UNEXPLAINED
    failures = checker.evaluate(
        _evidence_record(collection_skips=0), head="", env={})
    assert any("executed+deselected" in f for f in failures)
    assert any("runner could not verify" in f for f in failures)
    # collection skip present BUT v3 invariants violated -> still fails
    failures = checker.evaluate(
        _evidence_record(collection_skips=1, v3_invariants=False),
        head="", env={})
    assert any("executed+deselected" in f for f in failures)
    # collection skip present BUT the cross-check disagrees -> fails
    failures = checker.evaluate(
        _evidence_record(collection_skips=1, cross_agree=False),
        head="", env={})
    assert any("executed+deselected" in f for f in failures)

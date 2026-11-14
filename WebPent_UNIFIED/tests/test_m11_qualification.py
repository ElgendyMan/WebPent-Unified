"""M11 (Part 4 §13, UM-DR-22): benchmarking & research qualification.

Acceptance: "results support the declared qualification level; no
aggregate score without per-family detail and sample size".

1. **Per-family metrics** — TP/FP/FN/TN → precision/recall/F1 plus the
   operational rates (inconclusive, scope-rejection,
   human-intervention, crashes, reproducibility, time-to-first,
   cost-per-confirmed, requests-per-finding), each row with its sample
   size.
2. **No aggregate without per-family** — structural: the report model
   refuses empty family tables and zero-sample rows; the aggregate is
   computed FROM the rows.
3. **The label ladder** — unit_tested → lab_qualified →
   production_qualified, fail-closed with named evidence; LLM-involved
   components additionally require the Charter §4.1 verdict.
4. **The weekly runner** — the wired ق5 canary: deception benchmark +
   Charter baseline replay + the operator-configured dojo
   self-benchmark (honest note when absent) + the label rollup, dated
   reports on disk.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from webpent.qualification import (
    BenchmarkReportV2,
    FamilyMetrics,
    QualificationLabel,
    compute_family_metrics,
    evaluate_qualification_label,
    run_weekly_benchmarks,
)

FAMILY_OBSERVATIONS = [
    {"ground_truth": True, "predicted": True, "time_to_first_ms": 120.0,
     "cost_usd": 0.01, "requests": 8, "reproducible": True},
    {"ground_truth": True, "predicted": True, "time_to_first_ms": 300.0,
     "cost_usd": 0.02, "requests": 12, "reproducible": True},
    {"ground_truth": True, "predicted": False, "reproducible": False},
    {"ground_truth": False, "predicted": True, "inconclusive": True},
    {"ground_truth": False, "predicted": False, "scope_rejected": True},
    {"ground_truth": False, "predicted": False, "human_intervention": True},
    {"ground_truth": False, "predicted": False, "crashed": True},
]


# ---------------------------------------------------------------------------
# 1. Per-family metrics
# ---------------------------------------------------------------------------


def test_family_metrics_computation() -> None:
    metrics = compute_family_metrics("xss", FAMILY_OBSERVATIONS)
    assert metrics.family == "xss"
    assert metrics.sample_size == 7
    assert metrics.true_positives == 2
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.true_negatives == 3
    assert metrics.precision == round(2 / 3, 4)
    assert metrics.recall == round(2 / 3, 4)
    assert metrics.confirmed == 2
    assert metrics.inconclusive_rate == round(1 / 7, 4)
    assert metrics.scope_rejection_rate == round(1 / 7, 4)
    assert metrics.human_intervention_rate == round(1 / 7, 4)
    assert metrics.crash_count == 1
    assert metrics.reproducibility == round(2 / 3, 4)
    assert metrics.time_to_first_ms == 120.0
    assert metrics.cost_per_confirmed_usd == round(0.03 / 2, 6)
    assert metrics.requests_per_finding == round(20 / 2, 2)


def test_empty_family_is_all_zeros() -> None:
    metrics = compute_family_metrics("sqli", [])
    assert metrics.sample_size == 0
    assert metrics.precision == 0.0 and metrics.recall == 0.0


# ---------------------------------------------------------------------------
# 2. No aggregate without per-family detail + sample sizes
# ---------------------------------------------------------------------------


def _row(family: str, sample: int = 10, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "family": family,
        "sample_size": sample,
        "true_positives": 5,
        "false_positives": 1,
        "false_negatives": 2,
        "true_negatives": 2,
        "reproducibility": 1.0,
    }
    payload.update(overrides)
    return payload


def test_report_requires_family_rows() -> None:
    with pytest.raises(ValidationError, match="at least 1 item"):
        BenchmarkReportV2(
            report_id="rep-1",
            dataset_name="corpus",
            dataset_version="1",
            ground_truth_ref="manifest.json",
            executed_at="2026-11-06T00:00:00Z",
            family_metrics=[],
        )


def test_report_refuses_zero_sample_rows() -> None:
    with pytest.raises(ValidationError, match="sample_size=0"):
        BenchmarkReportV2(
            report_id="rep-1",
            dataset_name="corpus",
            dataset_version="1",
            ground_truth_ref="manifest.json",
            executed_at="2026-11-06T00:00:00Z",
            family_metrics=[FamilyMetrics(family="xss", sample_size=0)],
        )


def test_aggregate_is_derived_from_family_rows() -> None:
    report = BenchmarkReportV2(
        report_id="rep-2",
        dataset_name="corpus",
        dataset_version="1",
        dataset_commit="abc123",
        dataset_seed="42",
        ground_truth_ref="manifest.json",
        executed_at="2026-11-06T00:00:00Z",
        family_metrics=[
            FamilyMetrics(**_row("xss")),
            FamilyMetrics(**_row("sqli", sample=20, true_positives=10, false_positives=4,
                                 false_negatives=4, true_negatives=2)),
        ],
    )
    aggregate = report.compute_aggregate()
    assert aggregate["sample_size"] == 30
    assert aggregate["families_reported"] == 2
    assert aggregate["derived_from_family_rows"] is True
    assert aggregate["precision"] == round(15 / 20, 4)
    assert aggregate["recall"] == round(15 / 21, 4)


# ---------------------------------------------------------------------------
# 3. The label ladder
# ---------------------------------------------------------------------------


def test_label_ladder_is_fail_closed_with_named_evidence() -> None:
    # Nothing.
    verdict = evaluate_qualification_label("comp", {})
    assert verdict.label == QualificationLabel.UNQUALIFIED
    assert "unit_tests_green_run" in verdict.missing

    # Unit tests only.
    verdict = evaluate_qualification_label(
        "comp", {"tests_passing": 12, "tests_total": 12}
    )
    assert verdict.label == QualificationLabel.UNIT_TESTED
    assert "benchmark_report" in verdict.missing

    # + benchmark with per-family sizes + reproducibility + dataset.
    verdict = evaluate_qualification_label(
        "comp",
        {
            "tests_passing": 12,
            "tests_total": 12,
            "benchmark_report": {
                "dataset_name": "corpus",
                "dataset_version": "1",
                "family_metrics": [{"family": "xss", "sample_size": 30, "reproducibility": 0.9}],
            },
        },
    )
    assert verdict.label == QualificationLabel.LAB_QUALIFIED
    assert "blind_set_zero_false_positives" in verdict.missing

    # + blind set + deception pass (no LLM involved).
    verdict = evaluate_qualification_label(
        "comp",
        {
            "tests_passing": 12,
            "tests_total": 12,
            "benchmark_report": {
                "dataset_name": "corpus",
                "dataset_version": "1",
                "family_metrics": [{"family": "xss", "sample_size": 30, "reproducibility": 0.9}],
            },
            "blind_set": {"fixtures": 8, "false_positives": 0},
            "deception_report": {"fixtures_total": 24, "false_positives": 0},
        },
    )
    assert verdict.label == QualificationLabel.PRODUCTION_QUALIFIED

    # LLM-involved requires the charter verdict.
    verdict = evaluate_qualification_label(
        "llm-comp",
        {
            "tests_passing": 12,
            "tests_total": 12,
            "benchmark_report": {
                "dataset_name": "corpus",
                "dataset_version": "1",
                "family_metrics": [{"family": "xss", "sample_size": 30, "reproducibility": 0.9}],
            },
            "blind_set": {"fixtures": 8, "false_positives": 0},
            "deception_report": {"fixtures_total": 24, "false_positives": 0},
            "llm_involved": True,
        },
    )
    assert verdict.label == QualificationLabel.LAB_QUALIFIED
    assert "charter_gate_qualified_verdict" in verdict.missing


def test_failing_tests_block_the_ladder() -> None:
    verdict = evaluate_qualification_label(
        "comp", {"tests_passing": 10, "tests_total": 12}
    )
    assert verdict.label == QualificationLabel.UNQUALIFIED


# ---------------------------------------------------------------------------
# 4. The weekly runner (the wired ق5 canary)
# ---------------------------------------------------------------------------


def test_weekly_runner_internal_set_and_rollup(tmp_path) -> None:
    report = run_weekly_benchmarks(
        reports_root=tmp_path,
        now=lambda: __import__("datetime").datetime(
            2026, 11, 6, 12, 0, 0, tzinfo=__import__("datetime").timezone.utc
        ),
    )
    # Deception benchmark ran: 24 fixtures, 0 FP.
    assert report["deception_benchmark"]["fixtures_total"] == 24
    assert report["deception_benchmark"]["false_positives"] == 0
    # Charter baseline replay executed honestly (refused by construction).
    replay = report["charter_baseline_replay"]
    assert replay["qualified"] is False
    assert replay["sample_size"] == 120
    # The ق5 self-benchmark records the honest note when unconfigured.
    assert report["dojo_self_benchmark"]["status"] == "self_benchmark_not_configured"
    # The label rollup: the deception verifier has unit tests, a passing
    # deception benchmark AND a zero-FP blind set — the ladder earns it
    # production_qualified (no LLM involved, no charter requirement).
    labels = report["qualification_labels"]
    assert labels["deception_verifier"]["label"] == "production_qualified"
    assert not labels["deception_verifier"]["missing"]
    # The report is on disk, dated, deterministic path.
    assert report["report_path"].endswith("weekly_20261106T120000Z.json")
    on_disk = json.loads(open(report["report_path"]).read())
    assert on_disk["runner"] == "webpent-qualification-weekly-v1"


def test_weekly_runner_self_benchmark_factory_wired(tmp_path) -> None:
    called: list[str] = []

    def factory() -> dict[str, Any]:
        called.append("run")
        return {"scenarios": 5, "passed": 5, "families": ["xss", "sqli"]}

    report = run_weekly_benchmarks(reports_root=tmp_path, self_benchmark_factory=factory)
    assert called == ["run"]
    assert report["dojo_self_benchmark"]["passed"] == 5


def test_weekly_runner_records_factory_failures_honestly(tmp_path) -> None:
    def broken() -> dict[str, Any]:
        raise RuntimeError("agent factory down")

    report = run_weekly_benchmarks(reports_root=tmp_path, self_benchmark_factory=broken)
    assert "RuntimeError" in report["dojo_self_benchmark"]["error"]

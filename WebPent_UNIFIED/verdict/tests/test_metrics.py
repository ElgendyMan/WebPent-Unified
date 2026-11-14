"""U-VERDICT-6 — Metrics and Verdict Calculator tests (8 tests)."""

from __future__ import annotations

from verdict_tool.metrics import VerdictCalculator, VerdictMetrics
from verdict_tool.tracking import VerdictState


def _metrics(**overrides) -> VerdictMetrics:
    base = {
        "total_findings": 10, "confirmed_findings": 7, "false_positives": 2,
        "inconclusive": 1, "fp_rate": 0.2, "submitted": 5, "accepted": 0,
        "rejected": 0, "duplicates": 0, "under_review": 0,
        "acceptance_rate": 0.0, "time_to_first_finding_hours": 2.0,
        "time_to_first_accepted_days": None,
        "predicted_findings_range": None, "predicted_acceptance_range": None,
        "predictions_accurate": {},
    }
    base.update(overrides)
    return VerdictMetrics(**base)


def test_compute_empty_state_is_zeros() -> None:
    metrics = VerdictCalculator().compute(VerdictState(created_at="t"))
    assert metrics.total_findings == 0
    assert metrics.acceptance_rate == 0.0
    assert metrics.fp_rate == 0.0
    assert metrics.time_to_first_finding_hours is None


def test_final_verdict_go() -> None:
    assert VerdictCalculator.final_verdict(_metrics(accepted=3)) == \
        ("GO", "3+ accepted findings — tool is validated")
    assert VerdictCalculator.final_verdict(_metrics(accepted=7))[0] == "GO"


def test_final_verdict_go_cautious() -> None:
    assert VerdictCalculator.final_verdict(_metrics(accepted=2))[0] == \
        "GO_CAUTIOUS"


def test_final_verdict_improve_waiting_for_data() -> None:
    outcome, reasoning = VerdictCalculator.final_verdict(
        _metrics(accepted=1, under_review=2))
    assert outcome == "IMPROVE"
    assert "wait for more data" in reasoning


def test_final_verdict_improve_core_quality() -> None:
    outcome, reasoning = VerdictCalculator.final_verdict(_metrics(accepted=1))
    assert outcome == "IMPROVE"
    assert "core quality" in reasoning


def test_final_verdict_improve_duplicates() -> None:
    outcome, reasoning = VerdictCalculator.final_verdict(
        _metrics(accepted=0, duplicates=3))
    assert outcome == "IMPROVE"
    assert "duplicates" in reasoning


def test_final_verdict_no_go() -> None:
    outcome, reasoning = VerdictCalculator.final_verdict(_metrics())
    assert outcome == "NO-GO"
    assert "redesign" in reasoning


def test_compute_predictions_and_timing() -> None:
    state = VerdictState(
        created_at="2026-10-01T00:00:00+00:00",
        predicted_findings_range=[1, 3],
        predicted_acceptance_range=[0.5, 1.0],
        runs=[{"target": "target_a",
               "started_at": "2026-10-01T00:00:00+00:00",
               "stopped_at": None, "launch_path": "", "stop_path": ""}],
        findings=[{
            "finding_id": "f-1", "target": "target_a", "family": "sqli",
            "original_severity": "high", "original_evidence_score": 0.9,
            "classification": "confirmed", "registered_at":
            "2026-10-01T02:00:00+00:00",
        }, {
            "finding_id": "f-2", "target": "target_a", "family": "xss",
            "original_severity": "high", "original_evidence_score": 0.9,
            "classification": "confirmed", "registered_at":
            "2026-10-01T03:00:00+00:00",
        }, {
            "finding_id": "f-3", "target": "target_a", "family": "idor",
            "original_severity": "critical", "original_evidence_score": 0.9,
            "classification": "confirmed", "registered_at":
            "2026-10-01T04:00:00+00:00",
        }],
        submissions=[{"finding_id": "f-1", "platform_id": "p-1",
                      "platform": "hackerone",
                      "submitted_at": "2026-10-05T00:00:00+00:00",
                      "screenshot_path": "s.png",
                      "report_path": "r.md"},
                     {"finding_id": "f-2", "platform_id": "p-2",
                      "platform": "hackerone",
                      "submitted_at": "2026-10-05T00:00:00+00:00",
                      "screenshot_path": "s2.png",
                      "report_path": "r2.md"},
                     {"finding_id": "f-3", "platform_id": "p-3",
                      "platform": "hackerone",
                      "submitted_at": "2026-10-05T00:00:00+00:00",
                      "screenshot_path": "s3.png",
                      "report_path": "r3.md"}],
        watch=[{"finding_id": "f-1", "status": "accepted",
                "updated_at": "2026-10-09T00:00:00+00:00"},
               {"finding_id": "f-2", "status": "accepted",
                "updated_at": "2026-10-09T00:00:00+00:00"},
               {"finding_id": "f-3", "status": "accepted",
                "updated_at": "2026-10-09T00:00:00+00:00"}],
    )
    calculator = VerdictCalculator()
    metrics = calculator.compute(state)
    assert metrics.time_to_first_finding_hours == 2.0
    assert metrics.time_to_first_accepted_days == 4.0
    assert metrics.acceptance_rate == 1.0
    assert metrics.predictions_accurate == {"findings": True,
                                            "acceptance": True}
    outcome, _ = calculator.final_verdict(metrics)
    assert outcome == "GO"
    report = calculator.generate_report(metrics, state)
    assert "# Verdict Metrics Report" in report
    assert report == calculator.generate_report(metrics, state)

"""Wave 3 — U-CAMPAIGN-7 NarrativeGenerator + U-CAMPAIGN-8 ReportGenerator.

The storyteller renders what the machine actually recorded: no LLM in
any field, no invented facts, every sentence traceable to the thesis,
the phases or the recorded phase results. The report describes, it
never grades.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from webpent.campaign.executor.phase_runner import (
    HypothesisResult,
    PhaseResult,
    PhaseStatus,
)
from webpent.campaign.schemas import (
    CampaignBrief,
    CampaignBudget,
    Decision,
    Family,
    Phase,
    PhaseBudget,
    TargetThesis,
    ThesisEvidence,
)

_FAMILIES = [(Family.SQLI, 0.7), (Family.XSS, 0.5)]
_NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def _thesis() -> TargetThesis:
    return TargetThesis(
        thesis_id="th-story",
        target_id="https://target.example",
        statement="legacy surface worth a disciplined probe",
        confidence=0.66,
        likely_vuln_families=_FAMILIES,
        unlikely_vuln_families=[],
        crown_jewels=["admin panel"],
        likely_entry_points=["/api/v1"],
        evidence=[ThesisEvidence(
            evidence_id="ev-1", source="oracle", source_ref="/api/v1",
            claim="legacy stack visible", weight=0.8)],
        reasoning="oracle evidence only",
        created_at=_NOW,
    )


def _phase(order: int, goal: str) -> Phase:
    return Phase(
        phase_id=f"phase-{order}", order=order, goal=goal,
        thesis_alignment="serves the thesis directly",
        hypotheses=[],
        budget=PhaseBudget(max_requests=100, max_time_minutes=30,
                           max_llm_calls=10),
        exit_criteria=[], success_indicators=[], failure_indicators=[],
    )


def _brief() -> CampaignBrief:
    return CampaignBrief(
        campaign_id="camp-story", created_at=_NOW, thesis=_thesis(),
        phases=[_phase(1, "map the sqli surface"),
                _phase(2, "probe reflected xss")],
        total_budget=CampaignBudget(max_requests=400,
                                    max_time_minutes=60,
                                    max_llm_calls=40),
        decision=Decision.PENDING,
    )


def _phase_result(phase_id: str, status: PhaseStatus,
                  requests: int, findings: int) -> PhaseResult:
    return PhaseResult(
        phase_id=phase_id, target_id="https://target.example",
        status=status,
        hypothesis_results=[HypothesisResult(
            hypothesis_id=f"{phase_id}-h1", success=findings > 0,
            findings=[SimpleNamespace()] * findings,
            requests_used=requests, time_seconds=12.0,
            llm_calls_used=2, failure_reason=None if findings else "closed")],
        findings=[SimpleNamespace()] * findings,
        requests_used=requests, time_seconds=12.0, llm_calls_used=2,
        exited_due_to="budget" if status is PhaseStatus.EXHAUSTED else "met",
    )


# -- U-CAMPAIGN-7: NarrativeGenerator -----------------------------------


def test_narrative_renders_from_thesis_and_phases():
    from webpent.campaign.storyteller.narrative_generator import (
        NarrativeGenerator,
    )
    narrative = NarrativeGenerator().generate_campaign_narrative(
        _thesis(), [_phase(1, "map the sqli surface")], audience="operator")
    assert "https://target.example" in narrative.opening
    assert narrative.sections
    assert any("map the sqli surface" in s.text for s in narrative.sections)


def test_narrative_is_deterministic():
    from webpent.campaign.storyteller.narrative_generator import (
        NarrativeGenerator,
    )
    first = NarrativeGenerator().generate_campaign_narrative(
        _thesis(), [_phase(1, "map")], audience="operator")
    second = NarrativeGenerator().generate_campaign_narrative(
        _thesis(), [_phase(1, "map")], audience="operator")
    assert first == second


def test_narrative_audiences_differ():
    from webpent.campaign.storyteller.narrative_generator import (
        NarrativeGenerator,
    )
    operator = NarrativeGenerator().generate_campaign_narrative(
        _thesis(), [_phase(1, "map")], audience="operator")
    executive = NarrativeGenerator().generate_campaign_narrative(
        _thesis(), [_phase(1, "map")], audience="executive")
    assert operator.audience == "operator"
    assert executive.audience == "executive"
    assert operator != executive


def test_narrative_unknown_audience_rejected():
    from webpent.campaign.storyteller.narrative_generator import (
        NarrativeGenerator,
    )
    with pytest.raises(ValueError):
        NarrativeGenerator().generate_campaign_narrative(
            _thesis(), [], audience="poet")


def test_narrative_handles_zero_phases():
    from webpent.campaign.storyteller.narrative_generator import (
        NarrativeGenerator,
    )
    narrative = NarrativeGenerator().generate_campaign_narrative(
        _thesis(), [], audience="operator")
    assert narrative.sections == []
    assert "no phases" in narrative.closing.lower()


def test_narrative_declares_template_ids():
    from webpent.campaign.storyteller.narrative_generator import (
        NarrativeGenerator,
    )
    narrative = NarrativeGenerator().generate_campaign_narrative(
        _thesis(), [_phase(1, "map")], audience="operator")
    assert narrative.sections
    assert all(s.template_id for s in narrative.sections)


def test_narrative_has_no_llm_surface():
    import inspect

    from webpent.campaign.storyteller import narrative_generator
    source = inspect.getsource(narrative_generator)
    assert "openai" not in source.lower() and "anthropic" not in source.lower()
    gen = narrative_generator.NarrativeGenerator()
    assert not hasattr(gen, "client") and not hasattr(gen, "model")


def test_narrative_closing_names_the_operator():
    from webpent.campaign.storyteller.narrative_generator import (
        NarrativeGenerator,
    )
    narrative = NarrativeGenerator().generate_campaign_narrative(
        _thesis(), [_phase(1, "map")], audience="operator")
    assert "operator" in narrative.closing.lower()


# -- U-CAMPAIGN-8: ReportGenerator ---------------------------------------


def test_report_sums_recorded_budget():
    from webpent.campaign.storyteller.report_generator import (
        ReportGenerator,
    )
    results = [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 2),
               _phase_result("phase-2", PhaseStatus.EXHAUSTED, 40, 0)]
    report = ReportGenerator().generate_execution_report(
        _brief(), results)
    assert report.budget_requests_used == 100
    assert report.budget_llm_calls_used == 4


def test_report_outcome_mirrors_recorded_status_only():
    from webpent.campaign.storyteller.report_generator import (
        ReportGenerator,
    )
    results = [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 2),
               _phase_result("phase-2", PhaseStatus.EXHAUSTED, 40, 0)]
    report = ReportGenerator().generate_execution_report(_brief(), results)
    assert report.outcome["success"] == 1
    assert report.outcome["exhausted"] == 1


def test_report_counts_findings_from_results():
    from webpent.campaign.storyteller.report_generator import (
        ReportGenerator,
    )
    results = [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 3)]
    report = ReportGenerator().generate_execution_report(_brief(), results)
    assert report.findings_total == 3


def test_report_deterministic():
    from webpent.campaign.storyteller.report_generator import (
        ReportGenerator,
    )
    results = [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 1)]
    gen = ReportGenerator()
    assert gen.generate_execution_report(_brief(), results) == \
        gen.generate_execution_report(_brief(), results)


def test_report_empty_results_render():
    from webpent.campaign.storyteller.report_generator import (
        ReportGenerator,
    )
    report = ReportGenerator().generate_execution_report(_brief(), [])
    assert report.findings_total == 0
    assert report.outcome == {}


def test_report_never_grades():
    import inspect

    from webpent.campaign.storyteller import report_generator
    from webpent.campaign.storyteller.report_generator import (
        ReportGenerator,
    )
    source = inspect.getsource(report_generator)
    assert "def grade" not in source
    report = ReportGenerator().generate_execution_report(
        _brief(), [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 1)])
    assert not hasattr(report, "score") and not hasattr(report, "grade")

"""Wave 4 — U-CAMPAIGN-10 RetrospectiveEngine.

The retrospective compares what was planned with what was recorded —
never what was hoped. Every observation cites a recorded fact (a
phase's planned budget, its used budget, its recorded status); it
describes deltas, it never grades them.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

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
)

_FAMILIES = [(Family.SQLI, 0.7)]
_NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def _thesis() -> TargetThesis:
    return TargetThesis(
        thesis_id="th-retro", target_id="https://target.example",
        statement="recorded thesis", confidence=0.6,
        likely_vuln_families=_FAMILIES, unlikely_vuln_families=[],
        crown_jewels=[], likely_entry_points=[], evidence=[],
        reasoning="recorded", created_at=_NOW,
    )


def _phase(order: int, goal: str, max_requests: int = 100) -> Phase:
    return Phase(
        phase_id=f"phase-{order}", order=order, goal=goal,
        thesis_alignment="serves the thesis", hypotheses=[],
        budget=PhaseBudget(max_requests=max_requests,
                           max_time_minutes=30, max_llm_calls=10),
        exit_criteria=[], success_indicators=[], failure_indicators=[],
    )


def _brief() -> CampaignBrief:
    return CampaignBrief(
        campaign_id="camp-retro", created_at=_NOW, thesis=_thesis(),
        phases=[_phase(1, "map"), _phase(2, "probe")],
        total_budget=CampaignBudget(400, 60, 40),
        decision=Decision.APPROVED,
    )


def _phase_result(phase_id: str, status: PhaseStatus,
                  requests: int, findings: int) -> PhaseResult:
    return PhaseResult(
        phase_id=phase_id, target_id="https://target.example",
        status=status,
        hypothesis_results=[HypothesisResult(
            hypothesis_id=f"{phase_id}-h1", success=findings > 0,
            findings=[SimpleNamespace()] * findings,
            requests_used=requests, time_seconds=12.0, llm_calls_used=2,
            failure_reason=None if findings else "closed")],
        findings=[SimpleNamespace()] * findings,
        requests_used=requests, time_seconds=12.0, llm_calls_used=2,
        exited_due_to="met",
    )


def _report(findings_total: int = 3,
            budget_requests_used: int = 150) -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id="camp-retro", outcome={"success": 1},
        findings_total=findings_total,
        budget_requests_used=budget_requests_used)


def _engine():
    from webpent.campaign.historian.retrospective import RetrospectiveEngine
    return RetrospectiveEngine()


def test_review_records_campaign_id():
    retro = _engine().review(
        _brief(), _report(),
        [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 3)])
    assert retro.campaign_id == "camp-retro"


def test_per_phase_covers_every_planned_phase():
    results = [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 3)]
    retro = _engine().review(_brief(), _report(), results)
    assert [e.phase_id for e in retro.per_phase] == \
        ["phase-1", "phase-2"]


def test_planned_vs_used_budget_recorded():
    results = [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 3)]
    retro = _engine().review(_brief(), _report(), results)
    first = retro.per_phase[0]
    assert first.planned_requests == 100
    assert first.used_requests == 60


def test_status_mirrors_recorded_status_only():
    results = [
        _phase_result("phase-1", PhaseStatus.SUCCESS, 60, 3),
        _phase_result("phase-2", PhaseStatus.PENDING, 0, 0),
    ]
    retro = _engine().review(_brief(), _report(), results)
    assert retro.per_phase[0].status is PhaseStatus.SUCCESS
    assert retro.per_phase[1].status is PhaseStatus.PENDING


def test_unrun_phase_recorded_without_invention():
    results = [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 3)]
    retro = _engine().review(_brief(), _report(), results)
    second = retro.per_phase[1]
    assert second.used_requests == 0
    assert second.status is PhaseStatus.PENDING


def test_over_budget_phase_yields_citing_observation():
    results = [_phase_result("phase-1", PhaseStatus.SUCCESS, 150, 3)]
    retro = _engine().review(_brief(), _report(), results)
    assert retro.observations
    assert any("phase-1" in obs and "150" in obs and "100" in obs
               for obs in retro.observations)


def test_review_is_deterministic():
    results = [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 3)]
    first = _engine().review(_brief(), _report(), results)
    second = _engine().review(_brief(), _report(), results)
    assert first == second


def test_retrospective_never_grades():
    retro = _engine().review(
        _brief(), _report(),
        [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 3)])
    assert not hasattr(retro, "score") and not hasattr(retro, "grade")

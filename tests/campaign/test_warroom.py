"""Wave 5 — U-CAMPAIGN-12..15 (War Room).

CampaignDashboard (U-12): a deterministic text snapshot of a brief.
CampaignCLI (U-13): the operator's typed commands against the store —
list / status / approve / reject, nothing else, no shell, no network.
CampaignIntegration (U-14): the post-campaign flow (report → memory →
retrospective) as one composition of campaign-package components only.
TruthValidator (U-15): checks a report's claims against the recorded
phase results — inflated, deflated or fabricated numbers are flagged;
consistent reports pass silently.
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
)

_FAMILIES = [(Family.SQLI, 0.7)]
_NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def _thesis() -> TargetThesis:
    return TargetThesis(
        thesis_id="th-war", target_id="https://target.example",
        statement="recorded thesis", confidence=0.6,
        likely_vuln_families=_FAMILIES, unlikely_vuln_families=[],
        crown_jewels=[], likely_entry_points=[], evidence=[],
        reasoning="recorded", created_at=_NOW,
    )


def _brief() -> CampaignBrief:
    return CampaignBrief(
        campaign_id="camp-war", created_at=_NOW, thesis=_thesis(),
        phases=[Phase(order=1, phase_id="phase-1", goal="map",
                      thesis_alignment="serves the thesis",
                      hypotheses=[],
                      budget=PhaseBudget(100, 30, 10),
                      exit_criteria=[], success_indicators=[],
                      failure_indicators=[])],
        total_budget=CampaignBudget(400, 60, 40),
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
            requests_used=requests, time_seconds=12.0, llm_calls_used=2,
            failure_reason=None if findings else "closed")],
        findings=[SimpleNamespace()] * findings,
        requests_used=requests, time_seconds=12.0, llm_calls_used=2,
        exited_due_to="met",
    )


def _results() -> list[PhaseResult]:
    return [_phase_result("phase-1", PhaseStatus.SUCCESS, 60, 3)]


def _report(findings_total: int = 3, outcome: dict | None = None,
            budget_requests_used: int = 60) -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id="camp-war",
        outcome={"success": 1} if outcome is None else outcome,
        findings_total=findings_total,
        budget_requests_used=budget_requests_used)


# -- U-CAMPAIGN-12: CampaignDashboard ------------------------------------


def _dashboard():
    from webpent.campaign.warroom.dashboard import CampaignDashboard
    return CampaignDashboard()


def test_dashboard_includes_campaign_id():
    text = _dashboard().render(_brief())
    assert "camp-war" in text


def test_dashboard_includes_phase_count():
    text = _dashboard().render(_brief())
    assert "1" in text and "phase" in text.lower()


def test_dashboard_includes_decision():
    text = _dashboard().render(_brief())
    assert "pending" in text.lower()


def test_dashboard_is_deterministic():
    assert _dashboard().render(_brief()) == _dashboard().render(_brief())


def test_dashboard_with_report_shows_budget_used():
    text = _dashboard().render(_brief(), _report())
    assert "60" in text


# -- U-CAMPAIGN-13: CampaignCLI ------------------------------------------


def _store(tmp_path):
    from webpent.campaign.storage.campaign_store import CampaignStore
    store = CampaignStore(root_dir=tmp_path / "briefs")
    store.save_brief(_brief())
    return store


def _cli(store):
    from webpent.campaign.warroom.cli import CampaignCLI
    return CampaignCLI(store=store)


def test_cli_lists_registered_briefs(tmp_path):
    result = _cli(_store(tmp_path)).execute("list")
    assert result["ok"] is True
    assert "camp-war" in result["output"]


def test_cli_approve_records_operator_ruling(tmp_path):
    store = _store(tmp_path)
    result = _cli(store).execute("approve camp-war")
    assert result["ok"] is True
    assert store.get_brief("camp-war").decision is Decision.APPROVED


def test_cli_reject_records_operator_ruling(tmp_path):
    store = _store(tmp_path)
    result = _cli(store).execute("reject camp-war")
    assert result["ok"] is True
    assert store.get_brief("camp-war").decision is Decision.REJECTED


def test_cli_status_reports_brief_state(tmp_path):
    store = _store(tmp_path)
    result = _cli(store).execute("status camp-war")
    assert result["ok"] is True
    assert "camp-war" in result["output"]


def test_cli_unknown_command_is_typed_result_not_crash(tmp_path):
    result = _cli(_store(tmp_path)).execute("frobnicate everything")
    assert result["ok"] is False
    assert "command" in result["output"].lower()


def test_cli_ruling_on_unknown_campaign_is_typed_result(tmp_path):
    store = _store(tmp_path)
    result = _cli(store).execute("approve no-such-campaign")
    assert result["ok"] is False
    assert store.get_brief("no-such-campaign") is None


# -- U-CAMPAIGN-14: CampaignIntegration ----------------------------------


def _integration(tmp_path):
    from webpent.campaign.historian.campaign_memory import CampaignMemory
    from webpent.campaign.warroom.integration import CampaignIntegration
    memory = CampaignMemory(root_dir=tmp_path / "memory")
    return CampaignIntegration(memory=memory)


def test_flow_produces_report(tmp_path):
    flow = _integration(tmp_path).complete_campaign(_brief(), _results())
    assert flow.report.findings_total == 3


def test_flow_records_memory(tmp_path):
    flow = _integration(tmp_path).complete_campaign(_brief(), _results())
    assert flow.memory_id == "mem-camp-war"


def test_flow_produces_retrospective(tmp_path):
    flow = _integration(tmp_path).complete_campaign(_brief(), _results())
    assert flow.retrospective.campaign_id == "camp-war"


def test_flow_report_matches_direct_report(tmp_path):
    from webpent.campaign.storyteller.report_generator import ReportGenerator
    flow = _integration(tmp_path).complete_campaign(_brief(), _results())
    direct = ReportGenerator().generate_execution_report(
        _brief(), _results())
    assert flow.report == direct


def test_flow_with_zero_results_still_completes(tmp_path):
    flow = _integration(tmp_path).complete_campaign(_brief(), [])
    assert flow.report.findings_total == 0
    assert flow.memory_id == "mem-camp-war"


def test_flow_missing_brief_raises_typed_error(tmp_path):
    with pytest.raises(ValueError):
        _integration(tmp_path).complete_campaign(None, _results())


def test_flow_is_deterministic_across_runs(tmp_path):
    first = _integration(tmp_path).complete_campaign(_brief(), _results())
    from webpent.campaign.historian.campaign_memory import CampaignMemory
    from webpent.campaign.warroom.integration import CampaignIntegration
    fresh = CampaignIntegration(
        memory=CampaignMemory(root_dir=tmp_path / "memory2"))
    second = fresh.complete_campaign(_brief(), _results())
    assert first.report == second.report
    assert first.retrospective == second.retrospective


def test_integration_imports_campaign_components_only():
    import inspect

    from webpent.campaign.warroom import integration
    source = inspect.getsource(integration)
    assert "webpent.production" not in source
    assert "modern_spine" not in source


# -- U-CAMPAIGN-15: TruthValidator ---------------------------------------


def _validator():
    from webpent.campaign.warroom.truth_validator import TruthValidator
    return TruthValidator()


def test_consistent_report_has_no_issues():
    issues = _validator().validate(_report(), _results())
    assert issues == []


def test_inflated_findings_total_is_flagged():
    issues = _validator().validate(_report(findings_total=99), _results())
    assert issues
    assert any("findings" in issue.lower() for issue in issues)


def test_deflated_findings_total_is_flagged():
    issues = _validator().validate(_report(findings_total=1), _results())
    assert issues


def test_fabricated_outcome_status_is_flagged():
    issues = _validator().validate(
        _report(outcome={"success": 2, "exhausted": 5}), _results())
    assert issues
    assert any("outcome" in issue.lower() for issue in issues)


def test_zero_claims_over_zero_results_pass():
    issues = _validator().validate(
        _report(findings_total=0, outcome={}, budget_requests_used=0), [])
    assert issues == []


def test_budget_total_mismatch_is_flagged():
    issues = _validator().validate(
        _report(budget_requests_used=600), _results())
    assert issues
    assert any("budget" in issue.lower() for issue in issues)


def test_validation_is_deterministic():
    assert _validator().validate(_report(findings_total=7), _results()) == \
        _validator().validate(_report(findings_total=7), _results())


def test_validator_never_mutates_its_inputs():
    report = _report(findings_total=99)
    results = _results()
    report_before = vars(report).copy()
    _validator().validate(report, results)
    assert vars(report) == report_before
    assert len(results) == 1
    assert len(results[0].findings) == 3

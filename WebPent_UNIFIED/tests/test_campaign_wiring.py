"""Wave 3 — wiring tests: the campaign bridge inside the
ModernOrchator dispatch.

Direct construction of ModernOrchestrator, registered deliberately
in scripts/check_orchestrator_construction_authority.py TEST_ALLOWLIST
(Wave 3 review, see docs/reviews/round7_campaign_wave3_seal_update.md).
Same escape pattern as the verdict-bridge wiring tests: loopback
target, and the AVI class's run_campaign is replaced so the
orchestrator's wiring is what is under test, not the network.
"""
from __future__ import annotations

import dataclasses

import pytest

from webpent.campaign.schemas import Decision
from webpent.production.campaign_bridge import _resolve_store
from webpent.production.modern_spine import ModernOrchestrator

_TARGET = "http://127.0.0.1:9/cw3"


def _rich_avi_result() -> dict:
    """A result-shaped dict with enough signals for a thesis, plus
    the fields the orchestrator's post-campaign plumbing reads."""
    return {
        "target_url": _TARGET,
        "tech_stack": {"backend": "python", "framework": "django"},
        "subdomains": ["api.target.example", "admin.target.example"],
        "historical_endpoints": ["/api/v1/orders", "/admin/users"],
        "leaked_signals": [{"kind": "header",
                            "value": "Server: gunicorn"}],
        "crown_jewel_hints": [{"kind": "auth",
                               "value": "session cookie"}],
        "decisions": [],
        "decisions_executed": 0,
        "promoted_count": 0,
        "rejected_count": 0,
        "trace_records": [],
        "trace": {"full_coverage": True},
        "security_report": {"promoted_findings": [],
                            "rejected_findings": []},
    }


@pytest.fixture
def orchestrator(monkeypatch, tmp_path):
    monkeypatch.setenv("WEBPENT_CAMPAIGN_STORE",
                       str(tmp_path / "briefs"))
    from webpent.production import autonomous_validation_v1
    monkeypatch.setattr(
        autonomous_validation_v1.AutonomousValidationIntelligence,
        "run_campaign",
        lambda self, **kwargs: _rich_avi_result())
    from webpent.live_hunter.profile import AuthorizedLabProfile
    from webpent.live_hunter.tool_scope import ScopeLaw
    profile = AuthorizedLabProfile(
        authorized_targets=("127.0.0.1", "localhost"),
        engagement_id="eng_campaign_w3",
        operator_approval_at="2026-09-15T00:00:00Z",
        knowledge_ready=True,
    )
    return ModernOrchestrator(
        engagement_id="eng_campaign_w3",
        scope_law=ScopeLaw(profile=profile,
                           engagement_id="eng_campaign_w3"),
    )


def test_dispatch_carries_campaign_bridge_block(orchestrator):
    result = orchestrator.run_autonomous_validation_campaign(
        target_url=_TARGET, hypotheses=[])
    block = result["campaign_bridge"]
    assert block["brief"]["registered"] is True
    assert block["brief"]["decision"] == "PENDING"
    assert block["plan"]["attached"] is False


def test_brief_persisted_for_operator(tmp_path, orchestrator):
    orchestrator.run_autonomous_validation_campaign(
        target_url=_TARGET, hypotheses=[])
    store = _resolve_store(str(tmp_path / "briefs"))
    briefs = store.list_briefs()
    assert briefs
    assert briefs[0].thesis.target_id == _TARGET


def test_approved_plan_rides_next_dispatch_trace(tmp_path,
                                                 orchestrator):
    orchestrator.run_autonomous_validation_campaign(
        target_url=_TARGET, hypotheses=[])
    store = _resolve_store(str(tmp_path / "briefs"))
    brief = store.list_briefs()[0]
    # the OPERATOR approves (the machine never does)
    store.save_brief(dataclasses.replace(brief,
                                         decision=Decision.APPROVED))
    result = orchestrator.run_autonomous_validation_campaign(
        target_url=_TARGET, hypotheses=[])
    stages = [event.stage for event in orchestrator.trace.events
              if event.stage == "campaign_advisory_plan"]
    assert stages
    assert result["campaign_bridge"]["plan"]["attached"] is True
    assert result["campaign_bridge"]["plan"]["plan"]["phases"]


def test_bridge_failures_never_break_dispatch(orchestrator,
                                              monkeypatch):
    monkeypatch.delenv("WEBPENT_CAMPAIGN_STORE", raising=False)
    result = orchestrator.run_autonomous_validation_campaign(
        target_url=_TARGET, hypotheses=[])
    block = result["campaign_bridge"]
    # typed blocker, dispatch completed exactly as before
    assert block["brief"]["registered"] is False
    assert block["brief"]["blocker"]
    assert result["decisions_executed"] == 0
    assert result["verdict_bridge"]["gate"]["gate"] == "exempt_loopback"

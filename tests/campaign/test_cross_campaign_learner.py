"""Wave 4 — U-CAMPAIGN-11 CrossCampaignLearner.

Aggregates what the memory actually holds across campaigns: which
families the recorded work concentrated on, how many targets were
seen. It reads the memory and never writes to it, and every number it
reports traces back to recorded records.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from webpent.campaign.schemas import (
    CampaignBrief,
    CampaignBudget,
    Decision,
    Family,
    Phase,
    PhaseBudget,
    TargetThesis,
)

_NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def _thesis(target: str, families: list) -> TargetThesis:
    return TargetThesis(
        thesis_id=f"th-{abs(hash(target)) % 10_000}",
        target_id=target,
        statement="recorded thesis", confidence=0.6,
        likely_vuln_families=families, unlikely_vuln_families=[],
        crown_jewels=[], likely_entry_points=[], evidence=[],
        reasoning="recorded", created_at=_NOW,
    )


def _brief(target: str, campaign_id: str, families: list) -> CampaignBrief:
    return CampaignBrief(
        campaign_id=campaign_id, created_at=_NOW,
        thesis=_thesis(target, families),
        phases=[Phase(order=1, phase_id="phase-1", goal="map",
                      thesis_alignment="serves the thesis",
                      hypotheses=[],
                      budget=PhaseBudget(10, 5, 2),
                      exit_criteria=[], success_indicators=[],
                      failure_indicators=[])],
        total_budget=CampaignBudget(100, 30, 10),
        decision=Decision.APPROVED,
    )


def _report(campaign_id: str, findings_total: int) -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id=campaign_id, outcome={"success": 1},
        findings_total=findings_total, budget_requests_used=60)


def _memory_with(tmp_path):
    from webpent.campaign.historian.campaign_memory import CampaignMemory
    memory = CampaignMemory(root_dir=tmp_path / "memory")
    memory.record(
        _brief("https://a.example", "camp-a",
               [(Family.SQLI, 0.7), (Family.XSS, 0.5)]),
        _report("camp-a", 3))
    memory.record(
        _brief("https://b.example", "camp-b", [(Family.SQLI, 0.6)]),
        _report("camp-b", 1))
    return memory


def _learner():
    from webpent.campaign.historian.cross_campaign_learner import (
        CrossCampaignLearner,
    )
    return CrossCampaignLearner()


def test_learn_counts_campaigns_seen(tmp_path):
    memory = _memory_with(tmp_path)
    lessons = _learner().learn(memory)
    assert lessons.campaigns_seen == 2


def test_findings_attributed_to_top_recorded_family(tmp_path):
    memory = _memory_with(tmp_path)
    lessons = _learner().learn(memory)
    assert lessons.findings_by_family[Family.SQLI] == 4
    assert Family.XSS not in lessons.findings_by_family


def test_top_family_is_highest_recorded_count(tmp_path):
    memory = _memory_with(tmp_path)
    lessons = _learner().learn(memory)
    assert lessons.top_family() is Family.SQLI


def test_empty_memory_yields_empty_lessons(tmp_path):
    from webpent.campaign.historian.campaign_memory import CampaignMemory
    memory = CampaignMemory(root_dir=tmp_path / "empty")
    lessons = _learner().learn(memory)
    assert lessons.campaigns_seen == 0
    assert lessons.findings_by_family == {}
    assert lessons.top_family() is None


def test_learn_is_read_only_over_memory(tmp_path):
    memory = _memory_with(tmp_path)
    before = len(memory.list_all())
    _learner().learn(memory)
    assert len(memory.list_all()) == before


def test_learn_is_deterministic(tmp_path):
    memory = _memory_with(tmp_path)
    assert _learner().learn(memory) == _learner().learn(memory)

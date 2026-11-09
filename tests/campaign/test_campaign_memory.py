"""Wave 3 — U-CAMPAIGN-9 CampaignMemory.

The historian's memory: completed campaigns are recorded as JSON
records in the memory's own directory and recalled by target, by
family, or whole. Recall is read-only and deterministic; an empty
memory is an empty answer, never an error.
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

_FAMILIES = [(Family.SQLI, 0.7), (Family.XSS, 0.5)]
_NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def _thesis(target: str) -> TargetThesis:
    return TargetThesis(
        thesis_id=f"th-{abs(hash(target)) % 10_000}",
        target_id=target,
        statement="recorded thesis",
        confidence=0.6,
        likely_vuln_families=_FAMILIES,
        unlikely_vuln_families=[],
        crown_jewels=[],
        likely_entry_points=[],
        evidence=[],
        reasoning="recorded",
        created_at=_NOW,
    )


def _brief(target: str, campaign_id: str = "camp-m1") -> CampaignBrief:
    return CampaignBrief(
        campaign_id=campaign_id, created_at=_NOW, thesis=_thesis(target),
        phases=[Phase(order=1, phase_id="phase-1", goal="map",
                      thesis_alignment="serves the thesis",
                      hypotheses=[],
                      budget=PhaseBudget(10, 5, 2),
                      exit_criteria=[], success_indicators=[],
                      failure_indicators=[])],
        total_budget=CampaignBudget(100, 30, 10),
        decision=Decision.APPROVED,
    )


def _report(campaign_id: str = "camp-m1") -> SimpleNamespace:
    return SimpleNamespace(
        campaign_id=campaign_id,
        outcome={"success": 1},
        findings_total=2,
        budget_requests_used=60,
    )


def _memory(tmp_path):
    from webpent.campaign.historian.campaign_memory import CampaignMemory
    return CampaignMemory(root_dir=tmp_path / "memory")


def test_record_persists_json_round_trip(tmp_path):
    memory = _memory(tmp_path)
    memory_id = memory.record(_brief("https://a.example"), _report())
    recalled = memory.get(memory_id)
    assert recalled.thesis.target_id == "https://a.example"
    assert recalled.report.findings_total == 2


def test_recall_by_target(tmp_path):
    memory = _memory(tmp_path)
    memory.record(_brief("https://a.example", "camp-a"), _report("camp-a"))
    memory.record(_brief("https://b.example", "camp-b"), _report("camp-b"))
    hits = memory.recall_by_target("https://a.example")
    assert len(hits) == 1
    assert hits[0].campaign_id == "camp-a"


def test_recall_by_family(tmp_path):
    memory = _memory(tmp_path)
    memory.record(_brief("https://a.example", "camp-a"), _report("camp-a"))
    hits = memory.recall_by_family(Family.SQLI)
    assert [h.campaign_id for h in hits] == ["camp-a"]


def test_recall_unknown_target_is_empty_not_error(tmp_path):
    memory = _memory(tmp_path)
    assert memory.recall_by_target("https://nothing.example") == []


def test_get_unknown_id_is_none_not_error(tmp_path):
    memory = _memory(tmp_path)
    assert memory.get("no-such-memory") is None


def test_list_all_deterministic_order(tmp_path):
    memory = _memory(tmp_path)
    memory.record(_brief("https://a.example", "camp-a"), _report("camp-a"))
    memory.record(_brief("https://b.example", "camp-b"), _report("camp-b"))
    ids = [c.campaign_id for c in memory.list_all()]
    assert ids == sorted(ids)


def test_rerecording_same_campaign_updates_not_duplicates(tmp_path):
    memory = _memory(tmp_path)
    memory.record(_brief("https://a.example", "camp-a"), _report("camp-a"))
    updated = SimpleNamespace(
        campaign_id="camp-a",
        outcome={"success": 2},
        findings_total=5,
        budget_requests_used=90)
    memory.record(_brief("https://a.example", "camp-a"), updated)
    assert len(memory.list_all()) == 1
    assert memory.get("mem-camp-a").report.findings_total == 5


def test_recall_is_read_only_and_survives_reload(tmp_path):
    memory = _memory(tmp_path)
    memory_id = memory.record(_brief("https://a.example"), _report())
    reopened = _memory(tmp_path).get(memory_id)
    assert reopened.campaign_id == "camp-m1"

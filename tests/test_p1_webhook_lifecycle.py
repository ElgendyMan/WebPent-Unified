from __future__ import annotations

import asyncio

from webpent.integrations import webhook
from webpent.service.cost_alerts import AlertDispatcher
from webpent.service.facade import MultiCampaignService
from webpent.service.models import CampaignSpec
from webpent.service.store import ServiceStore


def _spec(name: str) -> CampaignSpec:
    return CampaignSpec(campaign_id=name, target_url="http://target.test", budget_limit=10, max_actions=5)


def test_promoted_lifecycle_uses_signed_webhook_path(monkeypatch, tmp_path):
    calls = []

    async def fake_push(finding, url):
        calls.append((finding, url))
        return True

    monkeypatch.setattr(webhook, "push_to_webhook", fake_push)
    dispatcher = AlertDispatcher(ServiceStore(tmp_path / "s.sqlite"), webhook_url="https://hooks.example.test/webpent")
    from webpent.service.models import FindingEvent
    assert dispatcher.finding(FindingEvent(
        campaign_id="camp", finding_id="find-1", status="promoted", severity="high",
        title="XSS reflected", evidence_ref="proof:1", payload={
            "finding_id": "find-1", "vulnerability_type": "XSS", "route": "/search",
            "cvss_score": "8.2",
        },
    )) is True
    assert len(calls) == 1
    finding, url = calls[0]
    assert url.startswith("https://")
    assert finding.campaign_id == "camp"
    assert finding.route == "/search"
    assert finding.confidence_level == "Tool-Confirmed"


def test_refuted_is_disabled_by_default_and_completion_is_idempotent(monkeypatch, tmp_path):
    calls = []

    async def fake_push(finding, url):
        calls.append(finding.title)
        return True

    monkeypatch.setattr(webhook, "push_to_webhook", fake_push)
    dispatcher = AlertDispatcher(ServiceStore(tmp_path / "s.sqlite"), webhook_url="https://hooks.example.test/webpent")
    from webpent.service.models import FindingEvent
    assert dispatcher.finding(FindingEvent(
        campaign_id="camp", finding_id="find-1", status="refuted", title="Not real", payload={}
    )) is False
    assert dispatcher.campaign_complete("camp", findings=1, cost=0.5, duration_seconds=2.0) is True
    assert dispatcher.campaign_complete("camp", findings=1, cost=0.5, duration_seconds=2.0) is False
    assert calls == ["Campaign camp completed"]


def test_facade_completion_emits_campaign_event_to_injected_sender(tmp_path):
    delivered = []
    service = MultiCampaignService(root=tmp_path, sender=lambda payload: delivered.append(payload) or True)
    service.plan(_spec("camp"))
    service.start("camp")
    result = service.complete("camp")
    assert result["state"] == "COMPLETED"
    assert any(item.get("event") == "campaign.completed" for item in delivered)

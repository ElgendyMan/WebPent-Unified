from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.service.facade import MultiCampaignService
from webpent.service.health import HealthMonitor
from webpent.service.models import CampaignSpec
from webpent.service.store import ServiceStore


def _spec(campaign_id: str, *, metadata=None, budget: float = 2.0, max_actions: int = 1) -> CampaignSpec:
    return CampaignSpec(
        campaign_id=campaign_id,
        target_url="http://127.0.0.1:8000",
        owner_id="tester",
        budget_limit=budget,
        max_actions=max_actions,
        metadata=metadata or {},
    )


def _reservation_kwargs(key: str, cost: float = 1.0) -> dict[str, object]:
    return {
        "idempotency_key": key,
        "task_id": key,
        "target_origin": "http://127.0.0.1:8000",
        "method": "GET",
        "action_family": "http_read",
        "identity_ref": "anonymous",
        "tenant_context": "tester",
        "vulnerability_class": "safe_probe",
        "validator_id": "test",
        "estimated_cost": cost,
    }


def test_campaign_id_is_safe_slug_and_nested_metadata_secrets_are_dropped(tmp_path) -> None:
    with pytest.raises(ValueError, match="safe_slug"):
        _spec("../escape")
    with pytest.raises(ValueError, match="safe_slug"):
        _spec("/absolute")
    spec = _spec("safe-1", metadata={"nested": {"api_key": "do-not-store", "label": "ok"}, "items": [{"password": "x"}]})
    assert "api_key" not in str(spec.metadata)
    assert "do-not-store" not in str(spec.metadata)
    assert "password" not in str(spec.metadata)
    service = MultiCampaignService(root=tmp_path)
    service.plan(spec)
    assert "do-not-store" not in str(service.manager.store.get_campaign("safe-1"))


def test_manager_reservation_uses_campaign_budget_and_action_limits(tmp_path) -> None:
    service = MultiCampaignService(root=tmp_path)
    service.plan(_spec("bounded", budget=2.0, max_actions=1))
    service.start("bounded")
    first = service.manager.reserve_action("bounded", **_reservation_kwargs("one", 1.5))
    assert first.allowed is True
    over_budget = service.manager.reserve_action("bounded", **_reservation_kwargs("two", 0.6))
    assert over_budget.allowed is False
    assert over_budget.reason == "budget:max_actions_exhausted"


def test_health_scheduled_tick_persists_hourly_and_daily_jobs(tmp_path) -> None:
    store = ServiceStore(tmp_path / "service.sqlite")
    monitor = HealthMonitor(store, alerts=__import__("webpent.service.cost_alerts", fromlist=["AlertDispatcher"]).AlertDispatcher(store), project_root=tmp_path)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    result = monitor.scheduled_tick(now=now, gate_runner=lambda gate: (0, "OK"))
    assert set(result["ran"]) == {"hourly_gates", "daily_manifest"}
    assert store.get_health_schedule("hourly_gates") is not None
    assert store.get_health_schedule("daily_manifest") is not None
    later = now.replace(second=(now.second + 1) % 60)
    second = monitor.scheduled_tick(now=later, gate_runner=lambda gate: (0, "OK"))
    assert second["ran"] == []

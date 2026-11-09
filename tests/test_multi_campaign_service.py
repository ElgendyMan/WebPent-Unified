from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.service.cost_alerts import AlertDispatcher
from webpent.service.facade import MultiCampaignService
from webpent.service.health import GATES, HealthMonitor
from webpent.service.models import CampaignLifecycle, CampaignSpec
from webpent.service.store import ServiceStore


def _spec(name: str, budget: float = 10.0) -> CampaignSpec:
    return CampaignSpec(
        campaign_id=name,
        target_url=f"http://{name}.test",
        owner_id=f"owner-{name}",
        budget_limit=budget,
        max_actions=10,
        retry_limit=2,
    )


def _reserve(service: MultiCampaignService, campaign_id: str, cost: float, key: str):
    return service.manager.ledger(campaign_id).reserve(
        idempotency_key=key,
        engagement_id=campaign_id,
        task_id=key,
        target_origin=f"http://{campaign_id}.test",
        method="GET",
        action_family="http_read",
        identity_ref="anonymous",
        tenant_context=campaign_id,
        vulnerability_class="safe_probe",
        validator_id="test",
        estimated_cost=cost,
        max_actions=10,
        max_budget=100.0,
    )


def test_two_campaigns_have_separate_ledgers_budgets_vaults_and_audits(tmp_path):
    service = MultiCampaignService(root=tmp_path)
    first = service.plan(_spec("alpha", budget=10.0))
    second = service.plan(_spec("beta", budget=10.0))
    assert first["vault_namespace"] != second["vault_namespace"]
    assert first["audit_namespace"] != second["audit_namespace"]

    service.start("alpha")
    service.start("beta")
    assert _reserve(service, "alpha", 8.5, "a1").allowed
    assert _reserve(service, "beta", 1.0, "b1").allowed
    assert service.snapshot("alpha")["used_budget"] == pytest.approx(8.5)
    assert service.snapshot("beta")["used_budget"] == pytest.approx(1.0)


def test_halt_is_per_campaign_and_budget_alert_is_idempotent(tmp_path):
    delivered: list[dict] = []
    service = MultiCampaignService(root=tmp_path, sender=lambda payload: delivered.append(payload) or True)
    service.plan(_spec("alpha", budget=10.0))
    service.plan(_spec("beta", budget=10.0))
    service.start("alpha")
    service.start("beta")
    halted = service.halt("alpha", "alice")
    assert halted["state"] == CampaignLifecycle.OPERATOR_HALTED
    assert service.snapshot("beta")["state"] == CampaignLifecycle.RUNNING
    assert not _reserve(service, "alpha", 1.0, "blocked").allowed
    assert _reserve(service, "beta", 8.1, "allowed").allowed
    service.costs.snapshot("beta")
    service.costs.snapshot("beta")
    budget_alerts = [p for p in delivered if p.get("event") == "webpent_budget_alert"]
    assert len(budget_alerts) == 1


def test_finding_lifecycle_emits_one_idempotent_redacted_event(tmp_path):
    delivered: list[dict] = []
    service = MultiCampaignService(root=tmp_path, sender=lambda payload: delivered.append(payload) or True)
    service.plan(_spec("alpha"))
    service.costs.record_finding(
        "alpha",
        {"finding_id": "f1", "title": "Safe finding", "severity": "high",
         "evidence_ref": "proof:f1", "Authorization": "should-never-ship"},
        status="promoted",
        cost=2.0,
    )
    service.costs.record_finding(
        "alpha",
        {"finding_id": "f1", "title": "Safe finding", "severity": "high", "evidence_ref": "proof:f1"},
        status="promoted",
        cost=2.0,
    )
    events = [p for p in delivered if p.get("event") == "webpent_finding_lifecycle"]
    assert len(events) == 1
    assert "should-never-ship" not in str(events[0])
    stored = service.store.list_findings("alpha")
    assert "should-never-ship" not in str(stored)


def test_scheduler_window_and_bounded_retry(tmp_path):
    service = MultiCampaignService(root=tmp_path)
    service.plan(_spec("alpha"))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    job = service.scheduler.schedule(
        "alpha", due_at=now.isoformat(),
        window_start=now.isoformat(), window_end=now.replace(year=now.year + 1).isoformat(), retry_limit=1,
    )
    calls = []

    def runner(campaign_id: str):
        calls.append(campaign_id)
        if len(calls) == 1:
            raise RuntimeError("transient")

    first = service.scheduler.tick(now=now.isoformat(), runner=runner)
    assert first[0]["status"] == "retry_scheduled"
    assert service.store.list_jobs("alpha")[0]["attempts"] == 1
    retry_job = service.store.list_jobs("alpha")[0]
    second = service.scheduler.tick(now=retry_job["due_at"], runner=runner)
    assert second[0]["status"] == "completed"
    assert service.snapshot("alpha")["state"] == CampaignLifecycle.COMPLETED


def test_health_monitor_detects_simulated_gate_failure(tmp_path):
    delivered: list[dict] = []
    store = ServiceStore(tmp_path / "service.sqlite")
    alerts = AlertDispatcher(store, sender=lambda payload: delivered.append(payload) or True)
    monitor = HealthMonitor(store, alerts, project_root=tmp_path)

    def fake_runner(gate: str):
        return (1, "simulated failure") if gate == GATES[2] else (0, "OK")

    results = monitor.run(gate_runner=fake_runner)
    assert len(results) == len(GATES)
    assert sum(not item.ok for item in results) == 1
    assert any(p.get("event") == "webpent_health_alert" for p in delivered)
    assert len(store.list_health_runs()) == len(GATES)

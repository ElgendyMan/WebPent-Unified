"""Composable facade for the multi-campaign product service."""
from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from webpent.config.settings import get_settings
from webpent.memory.improvement_tracker import ImprovementTracker
from webpent.memory.learning_lifecycle import persist_campaign_learning
from webpent.memory.lessons import LessonsManager
from webpent.service.cost_alerts import AlertDispatcher, CostTrackingService
from webpent.service.health import HealthMonitor
from webpent.service.manager import CampaignManager
from webpent.service.models import CampaignSpec
from webpent.service.scheduler import CampaignScheduler
from webpent.service.store import ServiceStore


class MultiCampaignService:
    def __init__(self, *, root: str | Path = "/tmp/webpent-service",
                 sender: Callable[[dict[str, Any]], bool] | None = None,
                 project_root: str | Path | None = None) -> None:
        root = Path(root)
        # Track 12 item 2: governor tickets live for the campaign's RUNNING
        # lifetime (acquired at start, released at complete/halt) — not just
        # the synchronous dispatch window.
        self._governor_tickets: dict[str, Any] = {}
        self._governor_lock = threading.Lock()
        # Track 12 item 3 wiring (v0.25.0): campaign-lifetime worker claims
        # (cross-worker mutual exclusion via a shared coordination dir).
        # Optional and default-off: ``None`` keeps the exact pre-0.25.0
        # behavior. Resource guard only — never replaces scope/authorization.
        from webpent.production.campaign_worker_claims import (
            make_campaign_claims_from_settings,
        )

        self._worker_claims = make_campaign_claims_from_settings()
        self._worker_claim_units: dict[str, dict[str, Any]] = {}
        self._claims_lock = threading.Lock()
        self.store = ServiceStore(root / "service.sqlite")
        self.lessons = LessonsManager(database_url=str(root / "lessons.sqlite3"))
        self.learning = ImprovementTracker(database_path=root / "learning_metrics.sqlite3")
        self.manager = CampaignManager(self.store, root=root)
        settings = get_settings()
        self.alerts = AlertDispatcher(
            self.store,
            sender=sender,
            webhook_url=settings.webhook_url if settings.webhook_enabled else "",
            on_promoted=settings.webhook_on_promoted,
            on_refuted=settings.webhook_on_refuted,
            on_campaign_complete=settings.webhook_on_campaign_complete,
        )
        self.costs = CostTrackingService(self.store, self.alerts, self.manager)
        self.scheduler = CampaignScheduler(self.store, self.manager)
        self.health = HealthMonitor(
            self.store, self.alerts, project_root=project_root or Path.cwd()
        )

    def plan(self, spec: CampaignSpec) -> dict[str, Any]:
        return self.manager.plan_campaign(spec).as_dict()

    def start(self, campaign_id: str) -> dict[str, Any]:
        # Track 12 item 2 (2026-10-28): shared concurrency admission before
        # dispatch. The ticket is held until complete()/halt() releases it,
        # so a RUNNING campaign occupies its slot for its whole lifetime.
        # Fail-closed for RESOURCE safety (a denied start returns a clear
        # rejection; the campaign state is unchanged and can be started
        # later). Scope/authorization always ran earlier and is never
        # replaced by this guard.
        from webpent.production.concurrency_governor import get_concurrency_governor

        governor = get_concurrency_governor()
        with self._governor_lock:
            if campaign_id not in self._governor_tickets:
                snapshot = self.store.get_campaign(campaign_id)
                target_url = str((snapshot or {}).get("target_url", "") or "")
                ticket = governor.try_acquire(campaign_id, target_url)
                if ticket is None:
                    gov = governor.snapshot().as_dict()
                    raise RuntimeError(
                        f"campaign {campaign_id} not admitted: concurrency "
                        f"limits (max_concurrent_campaigns={governor.max_global}, "
                        f"max_concurrent_per_target={governor.max_per_target}) — "
                        f"stop another campaign first. Governor: {gov}"
                    )
                self._governor_tickets[campaign_id] = ticket
        # Track 12 item 3 (v0.25.0): cross-worker claim admission after the
        # governor's in-process/cross-process cap. Fail-closed for BUSY and
        # SCOPE_CONFLICT (another live worker holds the unit, or it is held
        # under a different scope — never taken over); ledger outages fail
        # open inside the adapter (resource guard, not a security boundary).
        if self._worker_claims is not None:
            snapshot = self.store.get_campaign(campaign_id)
            client_id = str((snapshot or {}).get("metadata", {}).get("client_id", "") or "")
            target_url = str((snapshot or {}).get("target_url", "") or "")
            decision = self._worker_claims.claim(
                campaign_id, client_id=client_id, target_url=target_url
            )
            if not decision.get("held", False):
                self._release_governor_ticket(campaign_id)
                raise RuntimeError(
                    f"campaign {campaign_id} not admitted: worker coordination "
                    f"{decision.get('outcome')} — "
                    f"{decision.get('note') or 'unit held by another worker'} "
                    f"(holder={decision.get('holder_worker_id')})"
                )
            if not decision.get("fail_open"):
                claim_unit = {
                    "client_id": client_id,
                    "target_url": target_url,
                }
                with self._claims_lock:
                    self._worker_claim_units[campaign_id] = claim_unit
        try:
            return self.manager.start_campaign(campaign_id).as_dict()
        except Exception:
            self._release_worker_claim(campaign_id)
            self._release_governor_ticket(campaign_id)
            raise

    def _release_worker_claim(self, campaign_id: str) -> None:
        """Release the campaign's coordination claim (never raises)."""
        if self._worker_claims is None:
            return
        with self._claims_lock:
            unit = self._worker_claim_units.pop(campaign_id, None)
        if unit is None:
            return
        self._worker_claims.release(
            campaign_id,
            client_id=str(unit.get("client_id", "")),
            target_url=str(unit.get("target_url", "")),
        )

    def _release_governor_ticket(self, campaign_id: str) -> None:
        from webpent.production.concurrency_governor import get_concurrency_governor

        with self._governor_lock:
            ticket = self._governor_tickets.pop(campaign_id, None)
        if ticket is not None:
            get_concurrency_governor().release(ticket)

    def halt(self, campaign_id: str, requested_by: str = "operator") -> dict[str, Any]:
        result = self.manager.request_halt(campaign_id, requested_by).as_dict()
        self._release_worker_claim(campaign_id)
        self._release_governor_ticket(campaign_id)
        return result

    def resume(self, campaign_id: str) -> dict[str, Any]:
        return self.manager.resume_campaign(campaign_id).as_dict()

    def complete(self, campaign_id: str, *, result: dict[str, Any] | None = None,
                 client_id: str | None = None, target_type: str = "generic_web",
                 cost_total: float = 0.0, time_total: float | None = None,
                 time_to_first_finding: float | None = None) -> dict[str, Any]:
        # Track 12 item 2: a completed campaign frees its concurrency slot.
        # Track 12 item 3 (v0.25.0): and its cross-worker coordination claim.
        self._release_worker_claim(campaign_id)
        self._release_governor_ticket(campaign_id)
        snapshot = self.manager.complete_campaign(campaign_id)
        cost = self.costs.snapshot(campaign_id)
        duration_seconds = float(time_total) if time_total is not None else 0.0
        if time_total is None:
            try:
                from datetime import datetime

                created = datetime.fromisoformat(
                    str(self.store.get_campaign(campaign_id)["created_at"])
                )
                updated = float(str(snapshot.updated_at))
                duration_seconds = max(0.0, updated - created.timestamp())
            except (TypeError, ValueError, KeyError, OSError):
                duration_seconds = 0.0
        self.alerts.campaign_complete(
            campaign_id,
            findings=cost.findings,
            cost=cost.actual_cost,
            duration_seconds=duration_seconds,
            target_url=snapshot.target_url,
        )
        response = snapshot.as_dict()
        if result is not None:
            campaign = self.store.get_campaign(campaign_id)
            scoped_client = str(
                client_id or campaign.get("metadata", {}).get("client_id") or ""
            ).strip()
            if scoped_client:
                response["learning"] = persist_campaign_learning(
                    result, campaign_id=campaign_id, client_id=scoped_client,
                    target_type=target_type, lessons_manager=self.lessons,
                    tracker=self.learning, cost_total=cost_total,
                    time_total=time_total, time_to_first_finding=time_to_first_finding,
                )
        return response

    def snapshot(self, campaign_id: str) -> dict[str, Any]:
        return self.manager.snapshot(campaign_id).as_dict()

    def reserve_action(self, campaign_id: str, **kwargs: Any) -> dict[str, Any]:
        result = self.manager.reserve_action(campaign_id, **kwargs)
        return {
            "allowed": result.allowed,
            "reason": result.reason,
            "used_actions": result.used_actions,
            "used_budget": result.used_budget,
            "rejection_metadata": result.rejection_metadata,
        }

    def dashboard(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.store.get_campaign(campaign_id)
        client_id = str(campaign.get("metadata", {}).get("client_id") or "").strip() or None
        target_type = str(campaign.get("metadata", {}).get("target_type") or "generic_web")
        return {
            "campaign": self.snapshot(campaign_id),
            "cost": self.costs.snapshot(campaign_id).as_dict(),
            "findings": self.store.list_findings(campaign_id),
            "alerts": self.store.list_alerts(campaign_id),
            "jobs": self.store.list_jobs(campaign_id),
            "learning": self.learning_dashboard(client_id=client_id, target_type=target_type),
        }

    def learning_dashboard(
        self, *, client_id: str | None = None, target_type: str | None = None
    ) -> dict[str, Any]:
        summary = self.lessons.structured_lesson_summary(client_id=client_id)
        trends = self.learning.trends(client_id=client_id, target_type=target_type)
        knowledge = {
            "available": False,
            "entries_by_family": {},
            "reason": "not_materialized_in_service_store",
        }
        return {"lessons": summary, "knowledge_base": knowledge, "trends": trends}

    def record_learning_metrics(self, *, campaign_id: str, client_id: str, target_type: str,
                                result: dict[str, Any], cost_total: float = 0.0,
                                time_total: float | None = None,
                                time_to_first_finding: float | None = None) -> dict[str, Any]:
        return self.learning.record_campaign(
            campaign_id=campaign_id, client_id=client_id, target_type=target_type,
            result=result, cost_total=cost_total, time_total=time_total,
            time_to_first_finding=time_to_first_finding,
        ).as_dict()

    def generate_completion_reports(
        self, campaign_id: str, output_dir: str | Path | None = None
    ) -> list[str]:
        """Generate reports from already-promoted sealed findings only."""
        from webpent.reporter.bounty_report import generate_bounty_reports

        findings = [item["payload"] for item in self.store.list_findings(campaign_id)
                    if item["status"] == "promoted"]
        reports = generate_bounty_reports(findings, campaign_id=campaign_id)
        if output_dir is None:
            return [report.to_json() for report in reports]
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        paths: list[str] = []
        for index, report in enumerate(reports, start=1):
            json_path = destination / f"{campaign_id}-{index}.json"
            md_path = destination / f"{campaign_id}-{index}.md"
            json_path.write_text(
                json.dumps(report.to_json(), indent=2, default=str) + "\n",
                encoding="utf-8",
            )
            md_path.write_text(report.to_markdown(), encoding="utf-8")
            paths.extend([str(json_path), str(md_path)])
        return paths

    def tick_scheduler(self, *, now: str | None = None,
                       runner: Callable[[str], Any] | None = None,
                       report_dir: str | Path | None = None) -> list[dict[str, Any]]:
        return self.scheduler.tick(
            now=now,
            runner=runner,
            on_complete=lambda campaign_id: self.generate_completion_reports(
                campaign_id, report_dir
            ),
        )


__all__ = ["MultiCampaignService"]

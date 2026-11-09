"""Application-level multi-campaign lifecycle manager."""
from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from webpent.service.models import CampaignLifecycle, CampaignSnapshot, CampaignSpec
from webpent.service.store import ServiceStore
from webpent.shared.action_ledger import LedgerReservation, SQLiteActionLedger


class CampaignManager:
    """Coordinates campaigns; trust-chain authorization remains elsewhere."""

    def __init__(self, store: ServiceStore | None = None, *, root: str | Path = "/tmp/webpent-service") -> None:
        self.root = Path(root)
        self.store = store or ServiceStore(self.root / "service.sqlite")
        self.ledger_root = self.root / "ledgers"
        self.ledger_root.mkdir(parents=True, exist_ok=True)

    def plan_campaign(self, spec: CampaignSpec) -> CampaignSnapshot:
        row = self.store.create_campaign(spec, run_id=uuid.uuid4().hex,
                                         created_at=str(time.time()))
        return self.snapshot(spec.campaign_id)

    def start_campaign(self, campaign_id: str) -> CampaignSnapshot:
        row = self.store.get_campaign(campaign_id)
        state = row["state"]
        if state == CampaignLifecycle.COMPLETED:
            raise ValueError("campaign_already_completed")
        if state == CampaignLifecycle.OPERATOR_HALTED:
            raise ValueError("campaign_operator_halted")
        if state not in {CampaignLifecycle.PLANNED, CampaignLifecycle.RUNNING}:
            raise ValueError(f"campaign_invalid_start_state:{state}")
        self.store.update_campaign(campaign_id, state=CampaignLifecycle.RUNNING, updated_at=str(time.time()), last_error="")
        return self.snapshot(campaign_id)

    def request_halt(self, campaign_id: str, requested_by: str = "operator") -> CampaignSnapshot:
        row = self.store.get_campaign(campaign_id)
        if row["state"] == CampaignLifecycle.COMPLETED:
            raise ValueError("campaign_already_completed")
        ledger = self.ledger(campaign_id)
        if not ledger.request_halt(row["campaign_id"], requested_by):
            raise RuntimeError("campaign_halt_persist_failed")
        self.store.update_campaign(campaign_id, state=CampaignLifecycle.OPERATOR_HALTED, updated_at=str(time.time()))
        return self.snapshot(campaign_id)

    def resume_campaign(self, campaign_id: str) -> CampaignSnapshot:
        row = self.store.get_campaign(campaign_id)
        if row["state"] != CampaignLifecycle.OPERATOR_HALTED:
            raise ValueError("campaign_not_operator_halted")
        if not self.ledger(campaign_id).clear_halt(row["campaign_id"]):
            raise RuntimeError("campaign_resume_persist_failed")
        self.store.update_campaign(campaign_id, state=CampaignLifecycle.RUNNING, updated_at=str(time.time()))
        return self.snapshot(campaign_id)

    def complete_campaign(self, campaign_id: str) -> CampaignSnapshot:
        row = self.store.get_campaign(campaign_id)
        if row["state"] == CampaignLifecycle.OPERATOR_HALTED:
            raise ValueError("campaign_operator_halted")
        self.store.update_campaign(campaign_id, state=CampaignLifecycle.COMPLETED, updated_at=str(time.time()), last_error="")
        return self.snapshot(campaign_id)

    def transient_failure(self, campaign_id: str, error: str) -> CampaignSnapshot:
        row = self.store.get_campaign(campaign_id)
        retries = int(row["retry_count"]) + 1
        if retries > int(row["retry_limit"]):
            # Keep the four-state public lifecycle; a retry-exhausted campaign
            # remains planned with a durable error and can be operator-replanned.
            retries = int(row["retry_limit"])
        self.store.update_campaign(campaign_id, retry_count=retries, last_error=str(error)[:300], updated_at=str(time.time()), state=CampaignLifecycle.PLANNED)
        return self.snapshot(campaign_id)

    def ledger(self, campaign_id: str) -> SQLiteActionLedger:
        row = self.store.get_campaign(campaign_id)
        return SQLiteActionLedger(self.ledger_root / f"{row['campaign_id']}.sqlite")

    def reserve_action(
        self, campaign_id: str, *, idempotency_key: str, task_id: str, target_origin: str,
        method: str, action_family: str, identity_ref: str, tenant_context: str,
        vulnerability_class: str, validator_id: str, estimated_cost: float,
        action_signature: str = "", loop_threshold: int = 3,
    ) -> LedgerReservation:
        """Reserve with limits loaded atomically from the campaign specification."""
        row = self.store.get_campaign(campaign_id)
        if row["state"] != CampaignLifecycle.RUNNING:
            return LedgerReservation(False, f"campaign:not_running:{row['state']}")
        return self.ledger(campaign_id).reserve(
            idempotency_key=idempotency_key, engagement_id=row["campaign_id"], task_id=task_id,
            target_origin=target_origin, method=method, action_family=action_family,
            identity_ref=identity_ref, tenant_context=tenant_context,
            vulnerability_class=vulnerability_class, validator_id=validator_id,
            estimated_cost=float(estimated_cost), max_actions=int(row["max_actions"]),
            max_budget=float(row["budget_limit"]), action_signature=action_signature,
            loop_threshold=loop_threshold,
        )

    def snapshot(self, campaign_id: str) -> CampaignSnapshot:
        row = self.store.get_campaign(campaign_id)
        usage = self.store.get_usage(campaign_id)
        ledger = self.ledger(campaign_id).snapshot(campaign_id)
        metrics = {key: value for key, value in usage.items() if key != "campaign_id"}
        return CampaignSnapshot(
            campaign_id=row["campaign_id"], run_id=row["run_id"], state=row["state"],
            target_url=row["target_url"], owner_id=row["owner_id"],
            budget_limit=float(row["budget_limit"]), used_budget=float(ledger.get("used_budget", 0.0)),
            used_actions=int(ledger.get("used_actions", 0)),
            vault_namespace=row["vault_namespace"], audit_namespace=row["audit_namespace"],
            retry_count=int(row["retry_count"]), retry_limit=int(row["retry_limit"]),
            last_error=row.get("last_error", ""), metrics=metrics,
            last_rejection=ledger.get("last_rejection"), updated_at=row["updated_at"],
        )

    def list_snapshots(self) -> list[CampaignSnapshot]:
        return [self.snapshot(row["campaign_id"]) for row in self.store.list_campaigns()]


__all__ = ["CampaignManager"]
